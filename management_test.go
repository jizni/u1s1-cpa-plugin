// management_test.go covers the management API: the quota snapshot cache lock
// discipline and the exact-match panel resource route.
package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// snapshotTime and cache hits must stay responsive while a collection runs; the
// cache lock is no longer held across the /v1/me round-trips.
func TestUsageCacheLockNotHeldDuringCollection(t *testing.T) {
	usageCacheMu.Lock()
	prev := usageCache
	usageCache = &usageSnapshot{
		fetchedAt: time.Now().Add(-2 * usageCacheTTL),
		accounts:  []accountUsage{{Name: "u1s1-seed.json"}},
	}
	usageCacheMu.Unlock()
	t.Cleanup(func() {
		usageCacheMu.Lock()
		usageCache = prev
		usageCacheMu.Unlock()
	})

	// Hold usageCollectMu to simulate an in-flight collection.
	usageCollectMu.Lock()
	defer usageCollectMu.Unlock()

	done := make(chan string, 1)
	go func() { done <- snapshotTime() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshotTime blocked while a collection was in flight")
	}
}

func TestPanelResourceRouteRequiresExactPath(t *testing.T) {
	call := func(method, path string) pluginapi.ManagementResponse {
		payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
			Method: method, Path: path,
		}})
		raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
		if err != nil {
			t.Fatalf("management.handle error = %v", err)
		}
		var resp pluginapi.ManagementResponse
		unwrapResult(t, raw, &resp)
		return resp
	}
	if resp := call("GET", "/v0/resource/plugins/u1s1/panel"); resp.StatusCode != http.StatusOK {
		t.Fatalf("panel status = %d, want 200", resp.StatusCode)
	}
	// A loose prefix match would serve the panel for all of these.
	for _, path := range []string{
		"/v0/resource/plugins/u1s1",
		"/v0/resource/plugins/u1s1/panel/extra",
		"/v0/resource/plugins/u1s1-other/panel",
	} {
		if resp := call("GET", path); resp.StatusCode == http.StatusOK {
			t.Fatalf("%q must not be served by the panel route", path)
		}
	}
}
