// gateway_device.go wraps the browser device login endpoints
// /auth/device/start and /auth/device/poll.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type deviceStartResponse struct {
	VerifyURL  string `json:"verify_url"`
	PollSecret string `json:"poll_secret"`
	Interval   int    `json:"interval"`
	ExpiresIn  int    `json:"expires_in"`
}

type devicePollResponse struct {
	Status      string `json:"status"`
	APIKey      string `json:"api_key"`
	DeviceToken string `json:"device_token"`
	DeviceID    int64  `json:"device_id"`
}

// startDeviceLogin posts a fresh public key to /auth/device/start and returns
// the browser verification URL plus the polling secret.
func startDeviceLogin(pair *deviceKeyPair, callbackID string) (*deviceStartResponse, error) {
	cfg := activeConfig()
	url := cfg.apiOrigin() + "/auth/device/start"
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "cli-proxy-api"
	}
	body, err := json.Marshal(map[string]any{
		"public_jwk":     pair.Public,
		"device_name":    fmt.Sprintf("%s (linux via CLIProxyAPI)", hostname),
		"client_version": cfg.ClientVersion,
	})
	if err != nil {
		return nil, err
	}
	resp, err := doRequest("POST", url, map[string]string{
		"content-type": "application/json",
		"user-agent":   cfg.UserAgent,
	}, body, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 device start: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded deviceStartResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, fmt.Errorf("u1s1 device start: decode: %w", err)
	}
	if decoded.VerifyURL == "" || decoded.PollSecret == "" {
		return nil, fmt.Errorf("u1s1 device start: gateway returned no verify_url/poll_secret")
	}
	if decoded.ExpiresIn <= 0 || decoded.ExpiresIn > 1800 {
		decoded.ExpiresIn = 900
	}
	if !strings.HasPrefix(decoded.VerifyURL, "http://") && !strings.HasPrefix(decoded.VerifyURL, "https://") {
		return nil, fmt.Errorf("u1s1 device start: unexpected verify_url scheme")
	}
	// Clamp the gateway's poll hint into [2,30]s while preserving a requested
	// slower cadence: a rate-limited 60s hint must not become a 2s hammer.
	decoded.Interval = min(max(decoded.Interval, 2), 30)
	return &decoded, nil
}

// pollDeviceLogin performs one poll against /auth/device/poll. The host drives
// the polling cadence via repeated auth.login.poll calls, so this is one shot.
// The HTTP status is surfaced so the caller can end the session on permanent
// client errors instead of spinning until the session expires.
func pollDeviceLogin(pollSecret, callbackID string) (*devicePollResponse, int, error) {
	cfg := activeConfig()
	url := cfg.apiOrigin() + "/auth/device/poll"
	body, err := json.Marshal(map[string]any{"poll_secret": pollSecret})
	if err != nil {
		return nil, 0, err
	}
	resp, err := doRequest("POST", url, map[string]string{
		"content-type": "application/json",
		"user-agent":   cfg.UserAgent,
	}, body, callbackID)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("u1s1 device poll: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded devicePollResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("u1s1 device poll: decode: %w", err)
	}
	return &decoded, resp.StatusCode, nil
}
