// gateway_errors.go decodes upstream error bodies. gatewayMessage extracts
// { error: { message } } and appends the tail the official CLI shows
// (dist/error-humanize.js): HTTP status, error code, and the gateway request id.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type gatewayError struct {
	Error struct {
		Message   string `json:"message"`
		Type      string `json:"type"`
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// gatewayMessage extracts { error: { message } } and appends the tail the
// official CLI shows (dist/error-humanize.js): HTTP status, error code, and the
// gateway request id. The plain message alone is often all a client renders, so
// without the tail a user reporting a problem has no id to quote and the
// quota-exhausted case is indistinguishable from a transient failure.
func gatewayMessage(body []byte, status int) string {
	var ge gatewayError
	if err := json.Unmarshal(body, &ge); err == nil && ge.Error.Message != "" {
		return ge.Error.Message + errorTail(ge, status)
	}
	return fmt.Sprintf("upstream %d: %s", status, truncate(strings.TrimSpace(string(body)), 200))
}

// errorTail formats the " (HTTP 429 · insufficient_quota · 请求编号 …)" suffix.
// The code names follow the CLI so the same text keeps its meaning on both
// clients; insufficient_quota in particular marks "do not retry, the quota is
// gone" rather than a rate limit.
func errorTail(ge gatewayError, status int) string {
	code := ge.Error.Code
	if ge.Error.Type == "insufficient_quota" || code == "quota_exceeded" {
		code = "insufficient_quota"
	}
	tags := make([]string, 0, 3)
	if status > 0 {
		tags = append(tags, fmt.Sprintf("HTTP %d", status))
	}
	if strings.TrimSpace(code) != "" {
		tags = append(tags, code)
	}
	if id := strings.TrimSpace(ge.Error.RequestID); id != "" {
		tags = append(tags, "请求编号 "+truncate(id, 64))
	}
	if len(tags) == 0 {
		return ""
	}
	return " (" + strings.Join(tags, " · ") + ")"
}
