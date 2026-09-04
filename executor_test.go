// executor_test.go covers the streaming pump and token estimation: upstream
// failures mid-stream must be surfaced, client disconnects must stay silent, and
// count_tokens must report a usable estimate.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// ---------------------------------------------------------------------------
// stream pump error reporting
// ---------------------------------------------------------------------------

// Regression test for silent truncation: when the upstream connection dies
// mid-stream after chunks were already delivered, the client must see an error.
// Returning quietly lets the host append [DONE] and pass a truncated answer off
// as a complete one.
func TestPumpStreamReportsUpstreamFailureAfterChunks(t *testing.T) {
	srv := sseServer(t, []string{`{"i":1}`, `{"i":2}`}, true)

	var emitted []string
	var errs []string
	pumpStreamChunks(srv.URL, map[string]string{}, nil, false, "",
		func(payload []byte) error { emitted = append(emitted, string(payload)); return nil },
		func(message string) { errs = append(errs, message) })

	if len(emitted) == 0 {
		t.Fatal("expected the chunks received before the abort to be emitted")
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly one upstream read error", errs)
	}
	if !strings.Contains(errs[0], "upstream stream read error") {
		t.Fatalf("error = %q, want it to name the upstream read failure", errs[0])
	}
}

// A failing emit means the client hung up: the host already closed the stream,
// so the plugin must stay silent instead of emitting into a dead stream.
func TestPumpStreamStaysSilentWhenClientDisconnects(t *testing.T) {
	srv := sseServer(t, []string{`{"i":1}`, `{"i":2}`, `{"i":3}`}, false)

	var errs []string
	calls := 0
	pumpStreamChunks(srv.URL, map[string]string{}, nil, false, "",
		func(payload []byte) error {
			calls++
			return http.ErrBodyNotAllowed // stand-in for "host stream closed"
		},
		func(message string) { errs = append(errs, message) })

	if calls != 1 {
		t.Fatalf("emit calls = %d, want the scan to stop after the first failure", calls)
	}
	if len(errs) != 0 {
		t.Fatalf("errors = %v, want silence when the client disconnected", errs)
	}
}

func TestPumpStreamReportsEmptyStream(t *testing.T) {
	srv := sseServer(t, []string{"[DONE]"}, false)
	var errs []string
	pumpStreamChunks(srv.URL, map[string]string{}, nil, false, "",
		func([]byte) error { return nil },
		func(message string) { errs = append(errs, message) })
	if len(errs) != 1 || !strings.Contains(errs[0], "empty upstream stream") {
		t.Fatalf("errors = %v, want the empty-stream report", errs)
	}
}

// pumpStream's goroutine has no cgo frame to unwind into at all, so a panic
// there kills the process unless it is recovered and reported.
func TestStreamPanicIsReportedNotFatal(t *testing.T) {
	var emitted []string
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("panic escaped the guard: %v", recovered)
			}
		}()
		defer reportStreamPanicTo("stream-1", func(message string) { emitted = append(emitted, message) })
		panic("scan exploded")
	}()
	if len(emitted) != 1 || !strings.Contains(emitted[0], "panic while streaming") {
		t.Fatalf("emitted = %v, want the panic reported as a stream error", emitted)
	}
	// pumpStream must still close the stream after a panic, so the client is not
	// left waiting on an abandoned stream. Verified structurally: streamClose is
	// deferred before the panic guard, so it runs last.
	srv := sseServer(t, []string{`{"i":1}`}, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// No host bridge in tests: emit fails, the pump goes quiet and returns.
		pumpStream(srv.URL, map[string]string{}, nil, false, "stream-2", "")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pumpStream did not return")
	}
}

// ---------------------------------------------------------------------------
// response headers
// ---------------------------------------------------------------------------

// The official CLI hit this on its loopback signing proxy: replaying the
// upstream content-encoding onto an already-decoded body made the local SDK try
// to inflate plain JSON, turning every non-streaming error into
// "<status> terminated" (zlib "incorrect header check") and hiding the real
// message (dist/device-auth.js forwardedResponseHeaders, u1s1-cli 1.5.0).
//
// The plugin cannot reproduce it — host.http.do hands back a decoded body and
// the executor builds its own header set rather than replaying the upstream's.
// This test pins that property so a future "pass the upstream headers through"
// change cannot reintroduce the bug the CLI just fixed.
func TestExecutorDoesNotReplayUpstreamTransportHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Shapes a compressing gateway or edge cache sends. br rather than gzip so
		// Go's transport leaves the header on the response instead of decoding and
		// stripping it: the header really is present for the plugin to mishandle.
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	storage, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	payload, _ := json.Marshal(rpcExecutorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
		Model:       "deepseek-v4-flash",
		StorageJSON: storage,
		Payload:     []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}})
	raw, err := handleMethod(pluginabi.MethodExecutorExecute, payload)
	if err != nil {
		t.Fatalf("executor.execute error = %v", err)
	}
	var resp pluginapi.ExecutorResponse
	unwrapResult(t, raw, &resp)

	for _, name := range []string{"Content-Encoding", "Transfer-Encoding", "Content-Length", "Connection"} {
		if got := resp.Headers.Get(name); got != "" {
			t.Fatalf("response carries upstream %s = %q; the body is already decoded", name, got)
		}
	}
	if ct := resp.Headers.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(string(resp.Payload), `"content":"ok"`) {
		t.Fatalf("payload = %q, want the upstream body verbatim", resp.Payload)
	}

	// The streaming path builds its own SSE headers for the same reason.
	for _, name := range []string{"Content-Encoding", "Transfer-Encoding", "Content-Length"} {
		if got := streamHeaders().Get(name); got != "" {
			t.Fatalf("stream headers carry %s = %q", name, got)
		}
	}
}

// ---------------------------------------------------------------------------
// count_tokens estimation
// ---------------------------------------------------------------------------

// A flat zero reads as "empty conversation" in usage logs and disables client
// context-budget warnings.
func TestCountTokensEstimatesPrompt(t *testing.T) {
	body := []byte(`{"model":"deepseek-v4-flash","messages":[
		{"role":"system","content":"You are a helpful assistant."},
		{"role":"user","content":"请帮我审查这段代码的并发安全性"}]}`)
	payload, _ := json.Marshal(rpcExecutorRequest{ExecutorRequest: pluginapi.ExecutorRequest{Payload: body}})
	raw, err := handleMethod(pluginabi.MethodExecutorCountTokens, payload)
	if err != nil {
		t.Fatalf("executor.count_tokens error = %v", err)
	}
	var resp pluginapi.ExecutorResponse
	unwrapResult(t, raw, &resp)

	var out struct {
		TotalTokens int `json:"total_tokens"`
		Usage       struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatalf("unmarshal count payload: %v", err)
	}
	if out.TotalTokens <= 0 {
		t.Fatalf("total_tokens = %d, want a positive estimate", out.TotalTokens)
	}
	if out.Usage.PromptTokens != out.TotalTokens || out.Usage.TotalTokens != out.TotalTokens {
		t.Fatalf("usage block inconsistent: %+v", out)
	}
	// The estimate must scale with the prompt.
	longer := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("word ", 500) + `"}]}`)
	if countTokensEstimate(longer) <= out.TotalTokens {
		t.Fatal("a much longer prompt must estimate higher")
	}
	// CJK counts about one token per rune, Latin about one per four bytes.
	if got := countTokensEstimate([]byte(`{"messages":[{"role":"user","content":"你好世界"}]}`)); got < 8 {
		t.Fatalf("CJK estimate = %d, want at least the rune count plus overhead", got)
	}
	if countTokensEstimate(nil) != 0 {
		t.Fatal("an empty body must estimate zero")
	}
	// An unparseable body must still scale with size rather than report zero.
	if countTokensEstimate([]byte("not json at all, but long enough to matter")) <= 0 {
		t.Fatal("unparseable bodies must fall back to a size-based estimate")
	}
}
