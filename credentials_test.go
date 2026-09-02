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
