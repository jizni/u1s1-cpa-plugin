// executor.go implements the executor capability: it forwards translated
// chat-completions payloads to the u1s1 gateway with a fresh DPoP proof, the
// cached attestation token, and the client fingerprint headers.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// maxStreamCollectBytes caps how much the synchronous collectStream path may
// buffer. pumpStream (the normal async path) streams chunk by chunk and needs
// no cap; the fallback path holds the whole response in memory.
const maxStreamCollectBytes = 64 * 1024 * 1024

type rpcExecutorRequest struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type streamResponse struct {
	Headers http.Header                     `json:"headers,omitempty"`
	Chunks  []pluginapi.ExecutorStreamChunk `json:"chunks,omitempty"`
}

func chatEndpoint(sa storedAuth) string { return sa.baseURL() + "/chat/completions" }

func streamHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	return h
}

// prepareBody normalizes the outbound payload: force the upstream model id and
// the desired stream flag, and translate a host thinking suffix into the
// reasoning fields this model's request_format expects. The host already
// translated the body into the chat-completions protocol.
func prepareBody(payload, original []byte, model string, stream bool) []byte {
	body := payload
	if len(body) == 0 {
		body = original
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	// The host strips the auth prefix but leaves any thinking suffix on the model
	// id; sending "deepseek-v4-flash(high)" upstream is a 400.
	baseModel, rawSuffix, hasSuffix := parseModelSuffix(model)
	if strings.TrimSpace(baseModel) != "" {
		obj["model"] = baseModel
	}
	var intent thinkingIntent
	hasIntent := false
	if hasSuffix {
		intent, hasIntent = parseThinkingSuffix(rawSuffix)
	}
	applyThinking(obj, baseModel, intent, hasIntent)
	obj["stream"] = stream
	if stream {
		// Ask for usage in the final SSE chunk, matching the official client.
		if _, ok := obj["stream_options"]; !ok {
			obj["stream_options"] = map[string]any{"include_usage": true}
		}
	} else {
		delete(obj, "stream_options")
	}
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return rewritten
}

// resolveModel prefers the requested model id; CPA may route an alias here, but
// the plugin registers upstream ids verbatim so no alias table is needed.
func resolveModel(req pluginapi.ExecutorRequest) string {
	if strings.TrimSpace(req.Model) != "" {
		return req.Model
	}
	return ""
}

func handleExecExecute(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	url := chatEndpoint(sa)
	body := prepareBody(req.Payload, req.OriginalRequest, resolveModel(req.ExecutorRequest), false)
	headers, err := signedHeaders(sa, "POST", url, attestationFor(req.AuthID, sa, req.HostCallbackID))
	if err != nil {
		return nil, err
	}
	resp, err := doRequest("POST", url, headers, body, req.HostCallbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return errorEnvelopeWithStatus("http_error", redactSecrets(gatewayMessage(resp.Body, resp.StatusCode)), resp.StatusCode), nil
	}
	return okEnvelope(pluginapi.ExecutorResponse{
		Payload: resp.Body,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
}

func handleExecStream(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	url := chatEndpoint(sa)
	body := prepareBody(req.Payload, req.OriginalRequest, resolveModel(req.ExecutorRequest), true)
	headers, err := signedHeaders(sa, "POST", url, attestationFor(req.AuthID, sa, req.HostCallbackID))
	if err != nil {
		return nil, err
	}
	headers["accept"] = "text/event-stream"
	sseFramed := clientNeedsSSEFrame(req.Metadata)

	// No async stream id: drain the upstream synchronously and return the chunks.
	if req.StreamID == "" {
		chunks, status, errCollect := collectStream(url, headers, body, sseFramed, req.HostCallbackID)
		if errCollect != nil {
			if status >= 400 {
				return errorEnvelopeWithStatus("http_error", redactSecrets(errCollect.Error()), status), nil
			}
			return nil, errCollect
		}
		return okEnvelope(streamResponse{Headers: streamHeaders(), Chunks: chunks})
	}

	// Async: return immediately and pump chunks to the host stream bridge.
	go pumpStream(url, headers, body, sseFramed, req.StreamID, req.HostCallbackID)
	return okEnvelope(streamResponse{Headers: streamHeaders()})
}

// collectStream reads the whole upstream SSE response into a chunk slice.
func collectStream(url string, headers map[string]string, body []byte, sseFramed bool, callbackID string) ([]pluginapi.ExecutorStreamChunk, int, error) {
	stream, status, _, err := doStream("POST", url, headers, body, callbackID)
	if err != nil {
		// Propagate the status the bridge surfaced (e.g. the gateway rejected the
		// request and returned no stream body): callers key their http_error
		// envelope off it, so hardcoding 0 would mask the real upstream failure.
		return nil, status, fmt.Errorf("http_error: %w", err)
	}
	defer stream.Close()
	reader := newStreamReader(stream)
	if status >= 400 {
		payload := readAllLimited(reader, maxErrorBytes)
		return nil, status, fmt.Errorf("%s", gatewayMessage(payload, status))
	}
	var chunks []pluginapi.ExecutorStreamChunk
	collected := 0
	err = scanSSE(reader, func(payload []byte) error {
		collected += len(payload)
		if collected > maxStreamCollectBytes {
			return fmt.Errorf("upstream stream too large (> %d bytes)", maxStreamCollectBytes)
		}
		chunks = append(chunks, pluginapi.ExecutorStreamChunk{Payload: framePayload(payload, sseFramed)})
		return nil
	})
	if err != nil {
		return chunks, status, err
	}
	if len(chunks) == 0 {
		return nil, status, fmt.Errorf("empty upstream stream")
	}
	return chunks, status, nil
}

// pumpStream forwards the upstream SSE to the host stream bridge chunk by chunk
// so the client sees true streaming. The host stream is always closed exactly once.
func pumpStream(url string, headers map[string]string, body []byte, sseFramed bool, streamID, callbackID string) {
	defer streamClose(streamID)
	defer reportStreamPanic(streamID)
	pumpStreamChunks(url, headers, body, sseFramed, callbackID,
		func(payload []byte) error { return streamEmit(streamID, payload) },
		func(message string) { streamEmitError(streamID, message) })
}

// reportStreamPanic converts a panic inside the pump goroutine into a stream
// error. Deferred, so it must be called as `defer reportStreamPanic(id)`.
//
// A goroutine panic has no cgo frame to unwind into at all: without this the
// process dies. Reporting it also matters on its own — a silent return would let
// the host append [DONE] and present a truncated answer as a complete one.
func reportStreamPanic(streamID string) {
	reportStreamPanicTo(streamID, func(message string) { streamEmitError(streamID, message) })
}

// reportStreamPanicTo is reportStreamPanic with an injectable sink for tests.
func reportStreamPanicTo(streamID string, emitError func(string)) {
	if recovered := recover(); recovered != nil {
		emitError(fmt.Sprintf("u1s1 plugin panic while streaming: %v", recovered))
	}
}

// pumpStreamChunks drains the upstream SSE into emit, reporting terminal
// failures through emitError. A failing emit means the client hung up and the
// host already closed the stream: stay silent. Any other failure must still be
// reported even when chunks went out — returning quietly would let the host
// append [DONE] and present a truncated answer as a complete one.
func pumpStreamChunks(url string, headers map[string]string, body []byte, sseFramed bool, callbackID string, emit func([]byte) error, emitError func(string)) {
	stream, status, _, err := doStream("POST", url, headers, body, callbackID)
	if err != nil {
		emitError(fmt.Sprintf("http_error: %v", err))
		return
	}
	defer stream.Close()
	reader := newStreamReader(stream)
	if status >= 400 {
		payload := readAllLimited(reader, maxErrorBytes)
		emitError(gatewayMessage(payload, status))
		return
	}
	emitted := 0
	emitBroken := false
	errScan := scanSSE(reader, func(payload []byte) error {
		if err := emit(framePayload(payload, sseFramed)); err != nil {
			// Client disconnected and the host closed the stream: stop reading.
			emitBroken = true
			return err
		}
		emitted++
		return nil
	})
	if errScan != nil {
		if !emitBroken {
			emitError(fmt.Sprintf("upstream stream read error: %v", errScan))
		}
		return
	}
	if emitted == 0 {
		emitError("empty upstream stream")
	}
}

// scanSSE splits an SSE body into data events and hands each valid JSON payload
// to emit. The trailing [DONE] sentinel is dropped: the host writes its own.
func scanSSE(reader *streamReader, emit func([]byte) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		content := stripDataPrefix(scanner.Text())
		if content == "" {
			continue
		}
		if content == "[DONE]" {
			break
		}
		if !json.Valid([]byte(content)) {
			continue
		}
		if err := emit([]byte(content)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// framePayload adds "data: " framing when the client entry path is not the
// native chat-completions passthrough (cross-format translators expect frames).
func framePayload(payload []byte, sseFramed bool) []byte {
	if !sseFramed {
		return payload
	}
	out := make([]byte, 0, len(payload)+6)
	out = append(out, "data: "...)
	out = append(out, payload...)
	return out
}

func stripDataPrefix(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "data:") {
		s = strings.TrimSpace(strings.TrimPrefix(s, "data:"))
	}
	return s
}

// clientNeedsSSEFrame reports whether chunk payloads must carry their own SSE
// framing. CPA's chat-completions passthrough adds the prefix itself; every
// cross-format response translator consumes already-framed "data: " lines.
func clientNeedsSSEFrame(metadata map[string]any) bool {
	path, _ := metadata["request_path"].(string)
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "/v1/chat/completions", "/v1/completions":
		return false
	default:
		return true
	}
}

func readAllLimited(reader *streamReader, limit int) []byte {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 8192)
	for len(buf) < limit {
		n, err := reader.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}

// handleCountTokens answers token-count probes. The u1s1 gateway has no count
// endpoint, so the number is computed locally.
//
// A flat zero (the previous behaviour) is worse than an estimate: the host
// records the value in usage logs and clients use it for context-window
// budgeting, so zero reads as "this conversation is empty" and suppresses the
// warnings that keep a request under the model limit. countTokensEstimate is
// deliberately conservative (it rounds up) for the same reason.
func handleCountTokens(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &req)
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	total := countTokensEstimate(body)
	payload, _ := json.Marshal(map[string]any{
		"total_tokens": total,
		// Mirror the chat-completions usage shape so cross-format translators and
		// usage parsers find the field they expect.
		"usage": map[string]any{
			"prompt_tokens":     total,
			"completion_tokens": 0,
			"total_tokens":      total,
		},
	})
	return okEnvelope(pluginapi.ExecutorResponse{
		Payload: payload,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
}

// countTokensEstimate approximates the prompt token count of a chat-completions
// body without pulling in a tokenizer dependency.
//
// CJK text is roughly one token per rune; Latin text is roughly one token per
// four bytes. Both are rounded up, and a small per-message overhead mirrors the
// role/separator tokens every chat format adds. This is an estimate by
// construction: it exists so callers get the right order of magnitude, not an
// exact figure the gateway would bill against.
func countTokensEstimate(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	var parsed struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools  json.RawMessage `json:"tools"`
		System json.RawMessage `json:"system"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Unparseable body: fall back to the whole payload so the answer still
		// scales with request size instead of collapsing to zero.
		return estimateTextTokens(string(body))
	}
	total := 0
	for _, message := range parsed.Messages {
		// Per-message role and delimiter overhead, as in the OpenAI cookbook.
		total += 4
		total += estimateTextTokens(extractTextContent(message.Content))
	}
	total += estimateTextTokens(extractTextContent(parsed.System))
	total += estimateTextTokens(extractTextContent(parsed.Tools))
	return total
}

// extractTextContent flattens the several shapes chat content can take (plain
// string, content-part array, tool schema object) into the text that matters for
// a size estimate.
func extractTextContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var sb strings.Builder
		for _, part := range parts {
			sb.WriteString(part.Text)
			sb.WriteByte(' ')
		}
		if sb.Len() > 0 {
			return sb.String()
		}
	}
	// Objects (tool schemas, image parts): the serialized form is the best
	// available proxy for its token weight.
	return string(raw)
}

func estimateTextTokens(text string) int {
	if text == "" {
		return 0
	}
	wide := 0
	narrowBytes := 0
	for _, r := range text {
		if r > 0x2E80 {
			// CJK, kana, and full-width forms: about one token per rune.
			wide++
			continue
		}
		narrowBytes += len(string(r))
	}
	// Round the Latin portion up so the estimate never undercounts.
	return wide + (narrowBytes+3)/4
}
