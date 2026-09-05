// management_test.go covers the management API: the quota snapshot cache lock
// discipline, forced-refresh freshness, and the exact-match panel resource route.
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestIsTransientCancel pins which upstream failures deserve one retry: only
// the host tearing down the request context (context canceled) is momentary;
// a 502 or nil must not be retried.
func TestIsTransientCancel(t *testing.T) {
	if !isTransientCancel(errors.New(`host.http.do: host error host_call_failed: execute host http request: Get "https://api.u1s1.io/v1/me": context canceled`)) {
		t.Fatal("context canceled must count as transient")
	}
	if isTransientCancel(errors.New("u1s1 me: 502 Bad Gateway")) {
		t.Fatal("an upstream 502 is not a cancellation")
	}
	if isTransientCancel(nil) {
		t.Fatal("nil must not count as transient")
	}
}

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

// groupPackagesForPanel must collapse per-day login_checkin packages into one
// row (the dashboard's mergePkgs behaviour): same kind+scope+daily-ness merge,
// distinct expiry dates survive in expiry_dates, sums add up, and a member
// without an expiry flags has_never_expiring.
func TestGroupPackagesForPanelMergesLoginCheckin(t *testing.T) {
	rows := make([]packageUsage, 0, 8)
	total := int64(0)
	remaining := int64(0)
	for i := 1; i <= 8; i++ {
		p := packageUsage{
			ID:          int64(1000 + i),
			Kind:        "login_checkin",
			KindLabel:   "登录打卡",
			Scope:       "all",
			DailyTokens: 0,
			TotalTokens: 2_000_000,
			Remaining:   2_000_000 - int64(i*100),
			ExpiresAt:   time.Date(2026, 9, 25+i, 8, 0, 0, 0, time.UTC).Format("2006-01-02 15:04:05"),
		}
		total += p.TotalTokens
		remaining += p.Remaining
		rows = append(rows, p)
	}
	got := groupPackagesForPanel(rows)
	if len(got) != 1 {
		t.Fatalf("got %d groups, want 1", len(got))
	}
	g := got[0]
	if g.Count != 8 {
		t.Errorf("count = %d, want 8", g.Count)
	}
	if g.TotalTokens != total || g.Remaining != remaining {
		t.Errorf("sums = total %d/%d remaining %d/%d", g.TotalTokens, total, g.Remaining, remaining)
	}
	if len(g.ExpiryDates) != 8 {
		t.Fatalf("expiry_dates = %d entries, want 8", len(g.ExpiryDates))
	}
	if g.ExpiryDates[0] != "2026-09-26 08:00:00" || g.ExpiryDates[7] != "2026-10-03 08:00:00" {
		t.Errorf("expiry_dates not sorted: %v", g.ExpiryDates)
	}
	if g.HasNeverExpiring {
		t.Error("has_never_expiring = true, want false")
	}
}

// admin_grant notes are user-facing copy; different notes must not merge away.
func TestGroupPackagesForPanelKeepsAdminGrantNotes(t *testing.T) {
	rows := []packageUsage{
		{ID: 1, Kind: "admin_grant", Scope: "all", TotalTokens: 5_000_000, Remaining: 5_000_000, ExpiresAt: "2026-09-29 14:37:29", Note: "内测感谢"},
		{ID: 2, Kind: "admin_grant", Scope: "all", TotalTokens: 2_000_000, Remaining: 1_999_325, Note: "新用户赠送"},
		{ID: 3, Kind: "admin_grant", Scope: "all", TotalTokens: 3_000_000, Remaining: 3_000_000, ExpiresAt: "2026-10-01 00:00:00", Note: "内测感谢"},
	}
	got := groupPackagesForPanel(rows)
	if len(got) != 2 {
		t.Fatalf("got %d groups, want 2 (same note merges, different notes stay apart)", len(got))
	}
	if got[0].Count != 2 || got[0].TotalTokens != 8_000_000 {
		t.Errorf("merged admin_grant group = count %d total %d, want 2 / 8000000", got[0].Count, got[0].TotalTokens)
	}
	if len(got[0].ExpiryDates) != 2 {
		t.Errorf("merged group expiry_dates = %v, want both dates", got[0].ExpiryDates)
	}
	if got[1].Count != 1 {
		t.Errorf("distinct-note group count = %d, want 1", got[1].Count)
	}
}

// A never-expiring member mixed into an expiring group keeps both signals.
func TestGroupPackagesForPanelNeverExpiring(t *testing.T) {
	rows := []packageUsage{
		{ID: 1, Kind: "invite", Scope: "all", TotalTokens: 1_000_000, Remaining: 800_000, ExpiresAt: "2026-10-01 00:00:00"},
		{ID: 2, Kind: "invite", Scope: "all", TotalTokens: 1_000_000, Remaining: 900_000},
	}
	got := groupPackagesForPanel(rows)
	if len(got) != 1 {
		t.Fatalf("got %d groups, want 1", len(got))
	}
	if !got[0].HasNeverExpiring || len(got[0].ExpiryDates) != 1 {
		t.Errorf("group = never %v dates %v, want never=true with 1 date", got[0].HasNeverExpiring, got[0].ExpiryDates)
	}
	if got[0].Remaining != 1_700_000 {
		t.Errorf("remaining = %d, want 1700000", got[0].Remaining)
	}
}
