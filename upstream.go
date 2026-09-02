// upstream.go owns all outbound u1s1 traffic. Requests go through the CPA host
// HTTP bridge (host.http.do / host.http.do_stream) so proxy-url, transport
// policy, and request logging stay under host control; a direct client is used
// only when the bridge is unavailable (unit tests / older hosts).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

const (
	// Response caps mirror the official CLI limits (8MB body / 64KB error).
	maxResponseBytes = 8 * 1024 * 1024
	maxErrorBytes    = 64 * 1024
)

var (
	httpClientOnce sync.Once
	sharedClient   *http.Client
)

func sharedHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		sharedClient = &http.Client{
			Timeout: 300 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 5,
			},
		}
	})
	return sharedClient
}

func hostBridgeAvailable() bool { return hostAPI != nil }

// ---------------------------------------------------------------------------
// buffered requests
// ---------------------------------------------------------------------------

type hostHTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type hostHTTPInner struct {
	Method  string              `json:"method,omitempty"`
	URL     string              `json:"url,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    []byte              `json:"body,omitempty"`
}

type hostHTTPRequestWire struct {
	HostCallbackID string         `json:"host_callback_id,omitempty"`
	Request        *hostHTTPInner `json:"request,omitempty"`
}

type hostHTTPBufferedResponseWire struct {
	StatusCodeSnake  int                 `json:"status_code"`
	StatusCodePascal int                 `json:"StatusCode"`
	Headers          map[string][]string `json:"headers,omitempty"`
	Body             []byte              `json:"body,omitempty"`
}

// doRequest performs one buffered upstream call.
func doRequest(method, url string, headers map[string]string, body []byte, callbackID string) (*hostHTTPResponse, error) {
	if !hostBridgeAvailable() {
		return doRequestDirect(method, url, headers, body)
	}
	wire := hostHTTPRequestWire{
		HostCallbackID: strings.TrimSpace(callbackID),
		Request: &hostHTTPInner{
			Method:  method,
			URL:     url,
			Headers: toHeaderMap(headers),
			Body:    body,
		},
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	raw, err := hostCall(pluginabi.MethodHostHTTPDo, payload)
	if err != nil {
		return nil, fmt.Errorf("host.http.do: %w", err)
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostHTTPDo)
	if err != nil {
		return nil, err
	}
	var decoded hostHTTPBufferedResponseWire
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("decode host.http.do response: %w", err)
	}
	status := decoded.StatusCodeSnake
	if status == 0 {
		status = decoded.StatusCodePascal
	}
	return &hostHTTPResponse{StatusCode: status, Headers: http.Header(decoded.Headers), Body: decoded.Body}, nil
}

func doRequestDirect(method, url string, headers map[string]string, body []byte) (*hostHTTPResponse, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := sharedHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	return &hostHTTPResponse{StatusCode: resp.StatusCode, Headers: resp.Header.Clone(), Body: raw}, nil
}

func toHeaderMap(headers map[string]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		out[k] = []string{v}
	}
	return out
}

// ---------------------------------------------------------------------------
// streaming requests
// ---------------------------------------------------------------------------

type hostHTTPStreamResponseWire struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	StreamID   string              `json:"stream_id,omitempty"`
}

type hostHTTPStreamReadWire struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

// upstreamStream is a handle over an in-flight upstream response body, either
// bridged through the host or read directly.
type upstreamStream struct {
	streamID  string
	direct    io.ReadCloser
	directErr error
}

func doStream(method, url string, headers map[string]string, body []byte, callbackID string) (*upstreamStream, int, http.Header, error) {
	if !hostBridgeAvailable() {
		return doStreamDirect(method, url, headers, body)
	}
	wire := hostHTTPRequestWire{
		HostCallbackID: strings.TrimSpace(callbackID),
		Request: &hostHTTPInner{
			Method:  method,
			URL:     url,
			Headers: toHeaderMap(headers),
			Body:    body,
		},
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return nil, 0, nil, err
	}
	raw, err := hostCall(pluginabi.MethodHostHTTPDoStream, payload)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("host.http.do_stream: %w", err)
	}
	return decodeStreamBridgeResponse(raw)
}

// decodeStreamBridgeResponse interprets the host's do_stream reply. Extracted
// from doStream so unit tests can exercise the no-stream error branch without
// a live cgo bridge.
func decodeStreamBridgeResponse(raw []byte) (*upstreamStream, int, http.Header, error) {
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostHTTPDoStream)
	if err != nil {
		return nil, 0, nil, err
	}
	var decoded hostHTTPStreamResponseWire
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, 0, nil, fmt.Errorf("decode host.http.do_stream response: %w", err)
	}
	if decoded.StreamID == "" {
		if decoded.StatusCode >= 400 {
			// The gateway rejected the request and the host handed back no stream
			// to read the error body from. Name the upstream status instead of a
			// generic bridge failure, and keep it in the returned status so the
			// caller can report a real http_error envelope.
			return nil, decoded.StatusCode, http.Header(decoded.Headers),
				fmt.Errorf("upstream %d: no error body available", decoded.StatusCode)
		}
		return nil, decoded.StatusCode, http.Header(decoded.Headers), fmt.Errorf("host stream bridge unavailable")
	}
	return &upstreamStream{streamID: decoded.StreamID}, decoded.StatusCode, http.Header(decoded.Headers), nil
}

func doStreamDirect(method, url string, headers map[string]string, body []byte) (*upstreamStream, int, http.Header, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := sharedHTTPClient().Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	return &upstreamStream{direct: resp.Body}, resp.StatusCode, resp.Header.Clone(), nil
}

// Read returns (payload, done, err) for the next chunk.
func (s *upstreamStream) Read() ([]byte, bool, error) {
	if s == nil {
		return nil, true, fmt.Errorf("stream closed")
	}
	if s.direct != nil {
		if s.directErr != nil {
			err := s.directErr
			s.directErr = nil
			return nil, true, err
		}
		buf := make([]byte, 32*1024)
		n, err := s.direct.Read(buf)
		if n > 0 {
			if err == io.EOF {
				return buf[:n], true, nil
			}
			if err != nil {
				s.directErr = err
			}
			return buf[:n], false, nil
		}
		if err == io.EOF {
			return nil, true, nil
		}
		if err != nil {
			return nil, true, err
		}
		return nil, false, nil
	}
	if s.streamID == "" {
		return nil, true, fmt.Errorf("stream closed")
	}
	payload, _ := json.Marshal(map[string]any{"stream_id": s.streamID})
	raw, err := hostCall(pluginabi.MethodHostHTTPStreamRead, payload)
	if err != nil {
		return nil, true, err
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostHTTPStreamRead)
	if err != nil {
		return nil, true, err
	}
	var decoded hostHTTPStreamReadWire
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, true, fmt.Errorf("decode host.http.stream_read response: %w", err)
	}
	if decoded.Error != "" {
		return nil, true, fmt.Errorf("%s", decoded.Error)
	}
	return decoded.Payload, decoded.Done, nil
}

func (s *upstreamStream) Close() {
	if s == nil {
		return
	}
	if s.direct != nil {
		_ = s.direct.Close()
		s.direct = nil
		return
	}
	if s.streamID == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{"stream_id": s.streamID})
	_, _ = hostCall(pluginabi.MethodHostHTTPStreamClose, payload)
	s.streamID = ""
}

// streamReader adapts upstreamStream to io.Reader so bufio.Scanner can re-frame
// SSE lines from arbitrary 32KB bridge chunks.
type streamReader struct {
	s    *upstreamStream
	buf  []byte
	done bool
	err  error
}

func newStreamReader(s *upstreamStream) *streamReader { return &streamReader{s: s} }

func (r *streamReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	if r.done {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	chunk, done, err := r.s.Read()
	if err != nil {
		r.done = true
		r.err = err
		return 0, err
	}
	if len(chunk) > 0 {
		n := copy(p, chunk)
		if n < len(chunk) {
			r.buf = append(r.buf, chunk[n:]...)
		}
		if done {
			r.done = true
		}
		return n, nil
	}
	if done {
		r.done = true
		return 0, io.EOF
	}
	return r.Read(p)
}

// ---------------------------------------------------------------------------
// host stream bridge (executor -> client)
// ---------------------------------------------------------------------------

func streamEmit(streamID string, payload []byte) error {
	if streamID == "" {
		return fmt.Errorf("no stream id")
	}
	if !hostBridgeAvailable() {
		// Async streaming only exists when the host handed us a stream id, which
		// requires the bridge. Report it instead of dropping chunks silently.
		return fmt.Errorf("host stream bridge unavailable")
	}
	body, _ := json.Marshal(map[string]any{"stream_id": streamID, "payload": payload})
	_, err := hostCall(pluginabi.MethodHostStreamEmit, body)
	return err
}

func streamEmitError(streamID, message string) {
	if streamID == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{"stream_id": streamID, "error": redactSecrets(message)})
	_, _ = hostCall(pluginabi.MethodHostStreamEmit, body)
}

func streamClose(streamID string) {
	if streamID == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{"stream_id": streamID})
	_, _ = hostCall(pluginabi.MethodHostStreamClose, body)
}

func hostLog(level, message string) {
	if !hostBridgeAvailable() {
		return
	}
	body, _ := json.Marshal(map[string]any{"level": level, "message": redactSecrets(message)})
	_, _ = hostCall(pluginabi.MethodHostLog, body)
}

// redactSecrets strips device tokens, DPoP proofs, and API keys from any text
// that may reach logs or clients.
func redactSecrets(in string) string {
	out := in
	// Longest prefix first: u1s1d- must win over u1s1-.
	for _, prefix := range []string{"u1s1d-", "u1s1-"} {
		var sb strings.Builder
		rest := out
		for {
			idx := strings.Index(rest, prefix)
			if idx < 0 {
				sb.WriteString(rest)
				break
			}
			end := idx + len(prefix)
			for end < len(rest) && isTokenChar(rest[end]) {
				end++
			}
			sb.WriteString(rest[:idx])
			sb.WriteString(prefix)
			sb.WriteString("[redacted]")
			rest = rest[end:]
		}
		out = sb.String()
	}
	return out
}

func isTokenChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_'
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
