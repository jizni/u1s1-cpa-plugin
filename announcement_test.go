// announcement_test.go covers the gateway operator notice: capture from
// /v1/models, publication through the management usage route, and the
// TTL-bounded refresh the panel triggers.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// Announcements carry maintenance windows and policy notices. The official CLI
// polls for them mid-session precisely because an outage otherwise shows up only
// as failing requests; the panel is the equivalent surface for this plugin.
func TestModelsResponseCapturesAnnouncement(t *testing.T) {
	t.Cleanup(func() { storeAnnouncement(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"deepseek-v4-flash"}],
"announcement":{"text":"维护公告：今晚 02:00 起短暂重启","url":"https://u1s1.io/announcements"}}`))
	}))
	t.Cleanup(srv.Close)

	if _, err := fetchModels(storedAuthFor(t, srv.URL), "", ""); err != nil {
		t.Fatalf("fetchModels() error = %v", err)
	}
	got := currentAnnouncement()
	if got == nil || !strings.Contains(got.Text, "维护公告") {
		t.Fatalf("announcement = %+v", got)
	}
	if got.URL != "https://u1s1.io/announcements" {
		t.Fatalf("announcement URL = %q", got.URL)
	}

	// A cleared announcement must disappear rather than linger from an earlier
	// response, and the panel must never receive a non-http URL to link.
	storeAnnouncement(&gatewayAnnouncement{Text: "x", URL: "javascript:alert(1)"})
	if got := currentAnnouncement(); got == nil || got.URL != "" {
		t.Fatalf("announcement = %+v, want the non-http URL dropped", got)
	}
	storeAnnouncement(&gatewayAnnouncement{Text: "   "})
	if currentAnnouncement() != nil {
		t.Fatal("a blank announcement must clear the previous one")
	}
}

// The panel reads the announcement from the authenticated usage route, so the
// route has to publish it alongside the accounts.
func TestManagementUsageIncludesAnnouncement(t *testing.T) {
	t.Cleanup(func() { storeAnnouncement(nil) })
	storeAnnouncement(&gatewayAnnouncement{Text: "维护公告", URL: "https://u1s1.io/announcements"})

	usageCacheMu.Lock()
	prev := usageCache
	usageCache = &usageSnapshot{fetchedAt: time.Now(), accounts: []accountUsage{{Name: "u1s1-a.json"}}}
	usageCacheMu.Unlock()
	t.Cleanup(func() {
		usageCacheMu.Lock()
		usageCache = prev
		usageCacheMu.Unlock()
	})

	payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/management/plugins/u1s1/usage",
	}})
	raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
	if err != nil {
		t.Fatalf("management.handle error = %v", err)
	}
	var resp pluginapi.ManagementResponse
	unwrapResult(t, raw, &resp)
	var body struct {
		Announcement *gatewayAnnouncement `json:"announcement"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("unmarshal usage body: %v", err)
	}
	if body.Announcement == nil || body.Announcement.Text != "维护公告" {
		t.Fatalf("announcement = %+v", body.Announcement)
	}
}

// A notice can appear hours after the last chat request, so the panel refreshes
// a stale copy itself instead of relying on model traffic to carry it.
func TestAnnouncementRefreshRespectsTTL(t *testing.T) {
	t.Cleanup(func() { storeAnnouncement(nil) })

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[],"announcement":{"text":"新公告"}}`))
	}))
	t.Cleanup(srv.Close)
	sa := storedAuthFor(t, srv.URL)

	// A fresh cache must not cost a round-trip on every panel load.
	storeAnnouncement(&gatewayAnnouncement{Text: "缓存的公告"})
	refreshAnnouncementIfStale(sa, "", "")
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("models calls = %d, want none while the notice is fresh", got)
	}

	// Age the cache past the TTL: the next panel load picks up the new notice.
	announcementMu.Lock()
	announcementFetchedAt = time.Now().Add(-2 * announcementTTL)
	announcementMu.Unlock()
	refreshAnnouncementIfStale(sa, "", "")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("models calls = %d, want exactly one refresh", got)
	}
	if got := currentAnnouncement(); got == nil || got.Text != "新公告" {
		t.Fatalf("announcement = %+v, want the refreshed notice", got)
	}
}
