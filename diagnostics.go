// diagnostics.go keeps the gateway request ids that came back with upstream
// errors, so a user reporting a problem has an id to quote.
//
// The official CLI grew the same thing in 1.5.0 (dist/request-trace.js): it
// remembers the request_id of the last failed model call and attaches it to the
// ticket `u1s1 feedback` opens. The plugin has no feedback command, but it has
// the same need — the id is minted by the gateway and is the only handle support
// can use to find the request in its logs. Until now it existed only inside the
// error text of whichever chat response happened to fail, i.e. in the client's
// scrollback rather than anywhere the operator can look afterwards.
//
// The ring is deliberately tiny and in-memory: this is a troubleshooting aid for
// the operator reading the panel, not an audit log. Nothing here is persisted,
// so a restart starts empty.
package main

import (
	"strings"
	"time"
)

// maxDiagnosticRecords bounds the ring. Ten is enough to cover the burst of
// failures a broken credential or an exhausted quota produces while a user is
// still looking at the panel, and small enough that the whole thing rides along
// in the usage response without thought.
const maxDiagnosticRecords = 10

// diagnosticRecord is one upstream failure, in the shape the panel renders.
// Every field here is already visible to the client in the error text; nothing
// credential-derived is recorded.
type diagnosticRecord struct {
	At        string `json:"at"`
	Status    int    `json:"status"`
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}

// recordUpstreamError appends one failure to the ring. It is called from
// gatewayMessage, which is the one function every non-2xx upstream response
// already goes through, so no call site has to be threaded with an extra
// argument to make this work.
func recordUpstreamError(ge gatewayError, status int) {
	code := ge.Error.Code
	if ge.Error.Type == "insufficient_quota" || code == "quota_exceeded" {
		// Same normalisation errorTail applies, so the panel and the client text
		// name the condition identically.
		code = "insufficient_quota"
	}
	record := diagnosticRecord{
		At:        time.Now().UTC().Format(time.RFC3339),
		Status:    status,
		RequestID: truncate(strings.TrimSpace(ge.Error.RequestID), 64),
		Code:      truncate(strings.TrimSpace(code), 64),
		Message:   truncate(redactSecrets(strings.TrimSpace(ge.Error.Message)), 200),
	}
	diagMu.Lock()
	defer diagMu.Unlock()
	diagRing = append(diagRing, record)
	if len(diagRing) > maxDiagnosticRecords {
		diagRing = diagRing[len(diagRing)-maxDiagnosticRecords:]
	}
}

// recentUpstreamErrors returns the ring newest-first. The slice is a copy: the
// caller marshals it into a response while other goroutines keep appending.
func recentUpstreamErrors() []diagnosticRecord {
	diagMu.Lock()
	defer diagMu.Unlock()
	out := make([]diagnosticRecord, 0, len(diagRing))
	for i := len(diagRing) - 1; i >= 0; i-- {
		out = append(out, diagRing[i])
	}
	return out
}

// resetDiagnosticsForTests clears the ring so tests that assert on its contents
// do not depend on which other tests ran first.
func resetDiagnosticsForTests() {
	diagMu.Lock()
	diagRing = nil
	diagMu.Unlock()
}
