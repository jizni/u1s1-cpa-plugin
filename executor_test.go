// executor_test.go covers the streaming pump and token estimation: upstream
// failures mid-stream must be surfaced, client disconnects must stay silent, and
// count_tokens must report a usable estimate.
package main

import (
	"encoding/json"
	"net/http"
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
