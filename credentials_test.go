// credentials_test.go covers the storedAuth credential model: the round-trip
// must preserve every key the struct does not model, and modelled fields must
// still win over anything carried in Extra.
package main

import (
	"encoding/json"
	"testing"
)

// auth.refresh and model.for_auth decode the credential file into storedAuth and
// re-encode it. Fields the struct does not model (host- and user-owned settings)
// used to disappear on every refresh.
func TestStoredAuthPreservesUnknownKeys(t *testing.T) {
	sa := testStoredAuth(t)
	base, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var withExtras map[string]any
	if err := json.Unmarshal(base, &withExtras); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	extras := map[string]any{
		"priority":        float64(7),
		"note":            "primary account",
		"proxy_url":       "http://proxy.internal:8080",
		"weight":          float64(3),
		"excluded_models": []any{"glm-5.3-free"},
		"disabled":        false,
		"request_retry":   float64(2),
		"headers":         map[string]any{"x-trace": "on"},
	}
	for key, value := range extras {
		withExtras[key] = value
	}
	raw, _ := json.Marshal(withExtras)

	parsed, err := parseStored(raw)
	if err != nil {
		t.Fatalf("parseStored() error = %v", err)
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal round-trip: %v", err)
	}
	var final map[string]any
	if err := json.Unmarshal(out, &final); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}
	for key, want := range extras {
		got, ok := final[key]
		if !ok {
			t.Fatalf("round-trip dropped %q", key)
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("%q = %s, want %s", key, gotJSON, wantJSON)
		}
	}
	// Modelled fields must still win over anything carried in Extra.
	if final["deviceToken"] != sa.DeviceToken {
		t.Fatalf("deviceToken = %v", final["deviceToken"])
	}
}

// Credential files written by older CLI installs still carry the legacy China
// site API root. The plugin must migrate it to the configured base URL (matching
// u1s1-cli site.js migrateStoredBaseUrl) instead of sending signed requests to a
// host the CLI has left behind.
func TestBaseURLMigratesLegacyChinaSite(t *testing.T) {
	sa := testStoredAuth(t)
	sa.BaseURL = "https://api.u1s1.io/v1"
	if got := sa.baseURL(); got != defaultBaseURL {
		t.Fatalf("baseURL() = %q, want migrated %q", got, defaultBaseURL)
	}

	// Trailing-slash variants normalize before the legacy comparison.
	sa.BaseURL = "https://api.u1s1.io/v1/"
	if got := sa.baseURL(); got != defaultBaseURL {
		t.Fatalf("baseURL() with trailing slash = %q, want %q", got, defaultBaseURL)
	}
}

// The current China-site base and the international site are different
// accounts/endpoints; migration must leave them untouched.
func TestBaseURLKeepsNonLegacyHosts(t *testing.T) {
	cases := []string{
		defaultBaseURL,
		"https://api.u1s1.dev/v1",
		"https://gateway.example.com/v1",
	}
	for _, base := range cases {
		sa := testStoredAuth(t)
		sa.BaseURL = base
		if got := sa.baseURL(); got != base {
			t.Fatalf("baseURL(%q) = %q, want unchanged", base, got)
		}
	}
}

// An empty credential base falls back to the configured (new) default.
func TestBaseURLFallsBackToConfig(t *testing.T) {
	sa := testStoredAuth(t)
	sa.BaseURL = ""
	if got := sa.baseURL(); got != defaultBaseURL {
		t.Fatalf("baseURL() = %q, want %q", got, defaultBaseURL)
	}
}
