// diagnostics_test.go covers the request-id ring: every upstream failure must
// leave a record with the gateway's request id, the ring must stay bounded, and
// the management route must expose it without leaking credential material.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// The request id only ever appeared in the error text of the one response that
// failed. Support looks requests up by it, so it has to outlive that response.
func TestUpstreamErrorsRecordRequestID(t *testing.T) {
	resetDiagnosticsForTests()
	t.Cleanup(resetDiagnosticsForTests)

	body := []byte(`{"error":{"message":"今日免费额度已用完","type":"insufficient_quota","code":"quota_exceeded","request_id":"req_abc123"}}`)
	message := gatewayMessage(body, http.StatusTooManyRequests)
	if !strings.Contains(message, "req_abc123") {
		t.Fatalf("message = %q, want the request id in the tail", message)
	}

	records := recentUpstreamErrors()
	if len(records) != 1 {
		t.Fatalf("records = %d, want the failure recorded once", len(records))
	}
	got := records[0]
	if got.RequestID != "req_abc123" {
		t.Fatalf("request_id = %q", got.RequestID)
	}
	if got.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got.Status)
	}
	// quota_exceeded and type insufficient_quota are the same condition; the
	// record must name it the way errorTail does so the panel and the client text
	// agree.
	if got.Code != "insufficient_quota" {
		t.Fatalf("code = %q, want the normalised quota code", got.Code)
	}
	if !strings.Contains(got.Message, "今日免费额度已用完") {
		t.Fatalf("message = %q", got.Message)
	}
	if got.At == "" {
		t.Fatal("record carries no timestamp")
	}
}

// An unparseable error body still has a status worth remembering, and the ring
// must not grow without bound.
func TestUpstreamErrorRingIsBoundedAndNewestFirst(t *testing.T) {
	resetDiagnosticsForTests()
	t.Cleanup(resetDiagnosticsForTests)

	// Two more than the cap, each with a distinguishable id.
	for i := 0; i < maxDiagnosticRecords+2; i++ {
		body := []byte(`{"error":{"message":"boom","request_id":"req_` + string(rune('a'+i)) + `"}}`)
		gatewayMessage(body, http.StatusBadGateway)
	}
	// Plus one body that is not JSON at all.
	gatewayMessage([]byte("<html>502 Bad Gateway</html>"), http.StatusBadGateway)

	records := recentUpstreamErrors()
	if len(records) != maxDiagnosticRecords {
		t.Fatalf("records = %d, want the ring capped at %d", len(records), maxDiagnosticRecords)
	}
	// Newest first: the non-JSON body was recorded last and carries no id.
	if records[0].RequestID != "" || records[0].Status != http.StatusBadGateway {
		t.Fatalf("newest record = %+v, want the id-less 502 first", records[0])
	}
	// The two oldest ids must have been evicted.
	for _, r := range records {
		if r.RequestID == "req_a" || r.RequestID == "req_b" {
			t.Fatalf("record %q should have been evicted", r.RequestID)
		}
	}
}

// A device token appearing in an upstream message must be redacted before it is
// stored, not only before it is logged: this ring is served over HTTP.
func TestUpstreamErrorRecordsRedactSecrets(t *testing.T) {
	resetDiagnosticsForTests()
	t.Cleanup(resetDiagnosticsForTests)

	token := "u1s1d-" + strings.Repeat("f", 64)
	body := []byte(`{"error":{"message":"设备 ` + token + ` 已被吊销","request_id":"req_x"}}`)
	gatewayMessage(body, http.StatusUnauthorized)

	records := recentUpstreamErrors()
	if len(records) != 1 {
		t.Fatalf("records = %d", len(records))
	}
	if strings.Contains(records[0].Message, token) {
		t.Fatal("the stored message still contains the device token")
	}
	if !strings.Contains(records[0].Message, "[redacted]") {
		t.Fatalf("message = %q, want the token redacted", records[0].Message)
	}
}

func TestDiagnosticsRouteReturnsRecords(t *testing.T) {
	resetDiagnosticsForTests()
	t.Cleanup(resetDiagnosticsForTests)

	gatewayMessage([]byte(`{"error":{"message":"客户端完整性校验未通过","code":"client_integrity_review","request_id":"req_int"}}`), http.StatusForbidden)

	payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/management/plugins/u1s1/diagnostics",
	}})
	raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
	if err != nil {
		t.Fatalf("management.handle error = %v", err)
	}
	var resp pluginapi.ManagementResponse
	unwrapResult(t, raw, &resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var decoded struct {
		Errors        []diagnosticRecord `json:"errors"`
		MaxRecords    int                `json:"max_records"`
		ClientVersion string             `json:"client_version"`
		PluginVersion string             `json:"plugin_version"`
	}
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		t.Fatalf("decode diagnostics body: %v", err)
	}
	if len(decoded.Errors) != 1 || decoded.Errors[0].RequestID != "req_int" {
		t.Fatalf("errors = %+v", decoded.Errors)
	}
	if decoded.MaxRecords != maxDiagnosticRecords {
		t.Fatalf("max_records = %d", decoded.MaxRecords)
	}
	// The two versions a support report needs alongside the id: which client
	// fingerprint the plugin claims, and which plugin build produced it.
	if decoded.ClientVersion != defaultClientVersion {
		t.Fatalf("client_version = %q, want %q", decoded.ClientVersion, defaultClientVersion)
	}
	if decoded.PluginVersion != pluginVersion {
		t.Fatalf("plugin_version = %q, want %q", decoded.PluginVersion, pluginVersion)
	}
}

// The route is registered, otherwise the host never routes to it.
func TestDiagnosticsRouteIsRegistered(t *testing.T) {
	found := false
	for _, route := range managementRegistration().Routes {
		if route.Method == http.MethodGet && strings.HasSuffix(route.Path, "/diagnostics") {
			found = true
		}
	}
	if !found {
		t.Fatal("management.register does not declare the diagnostics route")
	}
}

// The panel must offer the ids to the operator; a route nobody can reach is a
// route nobody uses.
func TestPanelExposesDiagnostics(t *testing.T) {
	body := string(renderPanel())
	for _, needle := range []string{`id="diag"`, "/plugins/u1s1/diagnostics", "请求编号"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("panel does not surface diagnostics: missing %q", needle)
		}
	}
	// Upstream text reaches this table, so it must go through the escaper.
	if !strings.Contains(body, "esc(e.message") {
		t.Fatal("diagnostics rows must escape the gateway message")
	}
}
