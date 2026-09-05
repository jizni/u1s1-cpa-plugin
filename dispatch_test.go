// dispatch_test.go covers the method dispatch layer: panics must become
// envelopes (never cross the cgo boundary) and handler errors must be redacted.
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// dispatchMethod runs directly under a cgo entry point: a panic unwinding past
// it crosses the C ABI and takes the whole CPA process down.
func TestDispatchPanicBecomesEnvelope(t *testing.T) {
	secret := "u1s1d-" + strings.Repeat("e", 40)
	out, rc := guardDispatchPanic(pluginabi.MethodPluginRegister, func() ([]byte, int) {
		panic("boom with token " + secret)
	})
	if rc == 0 {
		t.Fatal("a panic must produce a non-zero return code")
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "plugin_panic" {
		t.Fatalf("envelope = %+v, want a plugin_panic error", env)
	}
	if !strings.Contains(env.Error.Message, pluginabi.MethodPluginRegister) {
		t.Fatalf("message = %q, want the failing method named", env.Error.Message)
	}
	// A panic value can carry credential material, so it is redacted too.
	if strings.Contains(string(out), secret) {
		t.Fatalf("plugin_panic leaked the token: %s", out)
	}
	// The non-panicking path must be untouched.
	if out, rc := guardDispatchPanic("x", func() ([]byte, int) { return []byte("ok"), 0 }); rc != 0 || string(out) != "ok" {
		t.Fatalf("passthrough = (%q,%d)", out, rc)
	}
}

// Handler errors can carry upstream text, so the plugin_error envelope has to be
// redacted like every other client- or log-facing path.
func TestDispatchMethodRedactsHandlerErrors(t *testing.T) {
	secret := "u1s1d-" + strings.Repeat("f", 40)
	storage, _ := json.Marshal(map[string]any{"deviceToken": secret})
	payload, _ := json.Marshal(rpcAuthRefreshRequest{AuthRefreshRequest: pluginapi.AuthRefreshRequest{
		AuthProvider: providerName,
		StorageJSON:  storage,
	}})
	out, rc := dispatchMethod(pluginabi.MethodAuthRefresh, payload)
	if rc == 0 {
		t.Fatal("expected a non-zero return code for an unusable credential")
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "plugin_error" {
		t.Fatalf("envelope = %+v, want a plugin_error", env)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("plugin_error leaked the device token: %s", out)
	}
}

