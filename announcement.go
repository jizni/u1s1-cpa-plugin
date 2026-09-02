// announcement.go holds the operator notice the gateway ships with every models
// response. The official CLI polls for it during a session because a maintenance
// window otherwise only surfaces as bare request failures; the panel is the
// equivalent surface here. The cache itself lives in state.go.
package main

import (
	"strings"
	"time"
)

// gatewayAnnouncement is the operator notice the gateway ships with every
// models response.
type gatewayAnnouncement struct {
	Text string `json:"text"`
	URL  string `json:"url,omitempty"`
}

const maxAnnouncementChars = 2000

// announcementTTL bounds how stale the panel's copy of the notice may get. It
// matches modelCacheTTL: both are refreshed by the same /v1/models call.
const announcementTTL = 5 * time.Minute

// storeAnnouncement records the notice from the latest models response,
// including its absence: a cleared announcement must disappear from the panel.
// The URL is validated here because the panel renders it as a link.
func storeAnnouncement(a *gatewayAnnouncement) {
	var next *gatewayAnnouncement
	if a != nil && strings.TrimSpace(a.Text) != "" {
		next = &gatewayAnnouncement{Text: truncate(strings.TrimSpace(a.Text), maxAnnouncementChars)}
		if url := strings.TrimSpace(a.URL); isHTTPURL(url) {
			next.URL = url
		}
	}
	announcementMu.Lock()
	announcementSeen = next
	announcementFetchedAt = time.Now()
	announcementMu.Unlock()
}

func currentAnnouncement() *gatewayAnnouncement {
	announcementMu.RLock()
	defer announcementMu.RUnlock()
	if announcementSeen == nil {
		return nil
	}
	copied := *announcementSeen
	return &copied
}

// refreshAnnouncementIfStale re-reads /v1/models when the cached notice is older
// than announcementTTL. Chat traffic refreshes it as a side effect, but a host
// that only serves a fixed model would otherwise keep a maintenance notice from
// hours ago; the panel is the only place this plugin can show one at all.
// Failures are ignored: a stale notice beats a failed panel load.
func refreshAnnouncementIfStale(sa storedAuth, attestation, callbackID string) {
	announcementMu.RLock()
	fresh := !announcementFetchedAt.IsZero() && time.Since(announcementFetchedAt) < announcementTTL
	announcementMu.RUnlock()
	if fresh {
		return
	}
	if _, err := fetchModels(sa, attestation, callbackID); err != nil {
		hostLog("debug", "u1s1: announcement refresh failed: "+redactSecrets(err.Error()))
	}
}

// isHTTPURL keeps javascript:/data: payloads out of the panel's link href.
func isHTTPURL(raw string) bool {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	if len(raw) > 2048 {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return false
		}
	}
	return true
}
