package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFakeBody returns an io.ReadCloser over a fixed string for stream tests.
func newFakeBody(body string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(body))
}

// useBaseURL points the plugin config at a test server for the duration of one
// test. Auth routes hang off the origin, so the /v1 suffix is required.
func useBaseURL(t *testing.T, origin string) {
	t.Helper()
	cfgMu.Lock()
	pluginCfg.BaseURL = strings.TrimSuffix(origin, "/") + "/v1"
	cfgMu.Unlock()
	t.Cleanup(func() {
		cfgMu.Lock()
		pluginCfg = defaultPluginConfig()
		cfgMu.Unlock()
	})
}

// storedAuthFor returns a credential pinned to a test server.
func storedAuthFor(t *testing.T, origin string) storedAuth {
	t.Helper()
	sa := testStoredAuth(t)
	sa.BaseURL = strings.TrimSuffix(origin, "/") + "/v1"
	return sa
}

// modelsHandler answers GET /v1/models with one model and an attestation token.
// expiresIn <= 0 omits client_attestation.expires_in.
func modelsHandler(token string, expiresIn int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"object": "list",
			"data":   []map[string]any{{"id": "deepseek-v4-flash", "object": "model"}},
		}
		if token != "" {
			att := map[string]any{"token": token}
			if expiresIn > 0 {
				att["expires_in"] = expiresIn
			}
			body["client_attestation"] = att
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

// sseServer streams the given events, then optionally aborts the connection
// mid-body so the client observes a genuine upstream read failure (no
// terminating zero-length chunk). Used to prove truncation is not silent.
func sseServer(t *testing.T, events []string, abort bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !abort {
			w.Header().Set("Content-Type", "text/event-stream")
			for _, e := range events {
				_, _ = io.WriteString(w, "data: "+e+"\n\n")
			}
			w.(http.Flusher).Flush()
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		writeAbortedChunks(conn, buf, events)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeAbortedChunks(conn net.Conn, buf *bufio.ReadWriter, events []string) {
	defer conn.Close()
	_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
	for _, e := range events {
		chunk := "data: " + e + "\n\n"
		_, _ = fmt.Fprintf(buf, "%x\r\n%s\r\n", len(chunk), chunk)
	}
	// No terminating "0\r\n\r\n": the client read fails with unexpected EOF.
	_ = buf.Flush()
}
