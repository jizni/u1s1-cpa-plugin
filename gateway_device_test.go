// gateway_device_test.go covers the /auth/device/start request builder: poll
// interval clamping and the origin-rooted route.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStartDeviceLoginPreservesSlowPollInterval(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/device/start" {
			t.Errorf("path = %q, want the origin-rooted auth route", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	useBaseURL(t, srv.URL)

	pair, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}

	cases := []struct {
		name     string
		interval int
		want     int
	}{
		// A rate-limited gateway asking for 60s must not be polled every 2s.
		{"slower than the cap is clamped down, not reset", 60, 30},
		{"in range is preserved", 5, 5},
		{"zero falls back to the default", 0, 2},
		{"negative falls back to the default", -1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ = json.Marshal(map[string]any{
				"verify_url":  "https://u1s1.io/login?device=abc",
				"poll_secret": "ps-1",
				"interval":    tc.interval,
				"expires_in":  900,
			})
			start, errStart := startDeviceLogin(pair, "")
			if errStart != nil {
				t.Fatalf("startDeviceLogin() error = %v", errStart)
			}
			if start.Interval != tc.want {
				t.Fatalf("interval = %d, want %d", start.Interval, tc.want)
			}
		})
	}
}
