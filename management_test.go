// management_test.go covers the management API: the quota snapshot cache lock
// discipline, forced-refresh freshness, and the exact-match panel resource route.
package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// seedUsageSnapshot installs a snapshot for one test and restores the previous
// one afterwards.
func seedUsageSnapshot(t *testing.T, fetchedAt time.Time) {
	t.Helper()
	usageCacheMu.Lock()
	prev := usageCache
	usageCache = &usageSnapshot{
		fetchedAt: fetchedAt,
		accounts:  []accountUsage{{Name: "u1s1-seed.json"}},
	}
	usageCacheMu.Unlock()
	t.Cleanup(func() {
		usageCacheMu.Lock()
		usageCache = prev
		usageCacheMu.Unlock()
	})
}

// A forced refresh must not be satisfied by a snapshot that predates it. The
// panel's initial load fills the cache seconds before the user reaches the 刷新
// button, so a TTL-based hit here made POST /refresh a silent no-op: same
// numbers, same fetched_at, nothing for the page to show.
func TestForcedRefreshRejectsSnapshotOlderThanTheRequest(t *testing.T) {
	seedUsageSnapshot(t, time.Now())
	requestedAt := time.Now()

	if _, ok := freshUsageSnapshot(false, requestedAt); !ok {
		t.Fatal("a snapshot inside the TTL must satisfy a plain load")
	}
	if _, ok := freshUsageSnapshot(true, requestedAt); ok {
		t.Fatal("a snapshot collected before the request must not satisfy a forced refresh")
	}
}

// The other half of the contract: a collection that overlapped this call still
// counts, so concurrent forced refreshes collapse into one /v1/me pass.
func TestForcedRefreshReusesOverlappingCollection(t *testing.T) {
	requestedAt := time.Now()
	seedUsageSnapshot(t, requestedAt.Add(10*time.Millisecond))

	accounts, ok := freshUsageSnapshot(true, requestedAt)
	if !ok {
		t.Fatal("a snapshot collected after the request must satisfy a forced refresh")
	}
	if len(accounts) != 1 || accounts[0].Name != "u1s1-seed.json" {
		t.Fatalf("accounts = %+v, want the seeded snapshot", accounts)
	}
}

// An expired snapshot fails both checks: forced or not, it must be re-collected.
func TestStaleSnapshotSatisfiesNobody(t *testing.T) {
	seedUsageSnapshot(t, time.Now().Add(-2*usageCacheTTL))
	requestedAt := time.Now()

	if _, ok := freshUsageSnapshot(false, requestedAt); ok {
		t.Fatal("an expired snapshot must not satisfy a plain load")
	}
	if _, ok := freshUsageSnapshot(true, requestedAt); ok {
		t.Fatal("an expired snapshot must not satisfy a forced refresh")
	}
}

// The end-to-end shape of the bug: with a snapshot inside the TTL, a forced
// refresh must reach the collection path (and therefore contend for
// usageCollectMu) while a plain load still answers from cache immediately.
func TestForcedRefreshReachesCollectionPathDespiteFreshCache(t *testing.T) {
	seedUsageSnapshot(t, time.Now())

	usageCollectMu.Lock()
	unlockOnce := false
	unlock := func() {
		if !unlockOnce {
			unlockOnce = true
			usageCollectMu.Unlock()
		}
	}
	defer unlock()

	plain := make(chan struct{})
	go func() { _, _ = cachedUsage("", false); close(plain) }()
	select {
	case <-plain:
	case <-time.After(2 * time.Second):
		t.Fatal("a plain load must be served from the fresh snapshot without collecting")
	}

	forced := make(chan struct{})
	go func() { _, _ = cachedUsage("", true); close(forced) }()
	select {
	case <-forced:
		t.Fatal("a forced refresh returned without entering the collection path")
	case <-time.After(200 * time.Millisecond):
	}

	// Let it run: with no host bridge the collection fails and falls back to the
	// seeded snapshot, which is the documented behaviour, not a hang.
	unlock()
	select {
	case <-forced:
	case <-time.After(5 * time.Second):
		t.Fatal("forced refresh did not finish after the collection lock was released")
	}
}

// snapshotTime and cache hits must stay responsive while a collection runs; the
// cache lock is no longer held across the /v1/me round-trips.
func TestUsageCacheLockNotHeldDuringCollection(t *testing.T) {
	seedUsageSnapshot(t, time.Now().Add(-2*usageCacheTTL))

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
