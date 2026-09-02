// attestation.go implements the client_attestation token lifecycle. The gateway
// hands the token out with /v1/models; it lives 7 days and every authenticated
// request must carry it. The cache refreshes a day early, backs off after a
// failure, and collapses concurrent refreshes for one credential into a single
// /models round-trip. The cache itself lives in state.go.
package main

import (
	"strings"
	"sync"
	"time"
)

// The gateway hands out a client_attestation token with /v1/models. It lives 7
// days; refresh a day early, and back off after a failure so a flaky gateway is
// not hammered per request.
const (
	attestationRefreshMargin = 24 * time.Hour
	attestationFailCooldown  = 30 * time.Second
	// Bounds how long a token with unknown lifetime may be reused. It must stay
	// above attestationRefreshMargin: with a missing expires_in the entry is
	// refreshed once a day (48h TTL minus 24h margin) instead of either never
	// (zero expiry reads as fresh) or on every request (reads as stale).
	attestationUnknownTTL = 48 * time.Hour
)

// attestationFreshUntil derives the cache expiry for a fetched token. A missing
// expires_in must not yield a zero expiry: attestationFor treats zero as stale
// and would then re-fetch on every single request.
func attestationFreshUntil(expiresIn int64) time.Time {
	if expiresIn > 0 {
		return time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	return time.Now().Add(attestationUnknownTTL)
}

type attestationEntry struct {
	token       string
	expiresAt   time.Time
	lastFailure time.Time
	// mu guards the fields above. It is never held across a gateway round-trip.
	mu sync.Mutex
	// fetching serializes the /models refresh itself, so concurrent chat requests
	// for one credential produce a single refresh instead of one per request,
	// while still letting readers see the current token without blocking.
	fetching sync.Mutex
}

// attestationCacheKey is the single definition of the cache key. Refresh paths
// must derive it the same way as attestationFor, otherwise an empty AuthID
// makes them update a different entry than the one chat requests read.
func attestationCacheKey(authID string, sa storedAuth) string {
	if strings.TrimSpace(authID) != "" {
		return authID
	}
	return sa.DeviceToken
}

// setAttestation records a freshly issued token plus its expiry. The expiry is
// always written (see attestationFreshUntil) so a restart never trusts a token
// for an unknown remaining lifetime just because the gateway omitted expires_in.
func (s *storedAuth) setAttestation(token string, expiresIn int64) {
	if strings.TrimSpace(token) == "" {
		return
	}
	s.Attestation = token
	s.AttestationExpiresAt = attestationFreshUntil(expiresIn).Unix()
}

// cacheAttestation aligns the in-memory entry with a token a refresh path just
// fetched out of band, so the next chat request reuses it instead of re-fetching.
func cacheAttestation(authID string, sa storedAuth) {
	if sa.Attestation == "" {
		return
	}
	v, _ := attestationCache.LoadOrStore(attestationCacheKey(authID, sa), &attestationEntry{})
	entry := v.(*attestationEntry)
	entry.mu.Lock()
	entry.token = sa.Attestation
	if sa.AttestationExpiresAt > 0 {
		entry.expiresAt = time.Unix(sa.AttestationExpiresAt, 0)
	}
	entry.lastFailure = time.Time{}
	entry.mu.Unlock()
}

func attestationFor(authID string, sa storedAuth, callbackID string) string {
	v, _ := attestationCache.LoadOrStore(attestationCacheKey(authID, sa), &attestationEntry{})
	entry := v.(*attestationEntry)

	// Phase 1: decide under the short lock whether a refresh is needed.
	entry.mu.Lock()
	// Seed from the credential file on first use after a restart. A seed with
	// an unknown expiry stays zero on purpose: the stale check below then
	// replaces the untrusted token with a fresh one instead of trusting it for
	// an unknown remaining lifetime.
	if entry.token == "" && sa.Attestation != "" {
		entry.token = sa.Attestation
		if sa.AttestationExpiresAt > 0 {
			entry.expiresAt = time.Unix(sa.AttestationExpiresAt, 0)
		}
	}
	current := entry.token
	stale := entry.token == "" || entry.expiresAt.IsZero() ||
		time.Now().After(entry.expiresAt.Add(-attestationRefreshMargin))
	coolingDown := !entry.lastFailure.IsZero() && time.Since(entry.lastFailure) < attestationFailCooldown
	entry.mu.Unlock()

	if !stale || coolingDown {
		return current
	}

	// Phase 2: refresh outside entry.mu so readers of the still-valid token are
	// not blocked behind a gateway round-trip. fetching collapses the concurrent
	// refreshes for this credential into one.
	entry.fetching.Lock()
	defer entry.fetching.Unlock()

	// Another goroutine may have refreshed while we waited for fetching.
	entry.mu.Lock()
	current = entry.token
	stillStale := entry.token == "" || entry.expiresAt.IsZero() ||
		time.Now().After(entry.expiresAt.Add(-attestationRefreshMargin))
	coolingDown = !entry.lastFailure.IsZero() && time.Since(entry.lastFailure) < attestationFailCooldown
	entry.mu.Unlock()
	if !stillStale || coolingDown {
		return current
	}

	token, expiresIn, err := fetchAttestation(sa, callbackID)

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if err != nil || token == "" {
		entry.lastFailure = time.Now()
		return entry.token
	}
	entry.token = token
	entry.lastFailure = time.Time{}
	entry.expiresAt = attestationFreshUntil(expiresIn)
	return entry.token
}

func fetchAttestation(sa storedAuth, callbackID string) (string, int64, error) {
	resp, err := fetchModels(sa, "", callbackID)
	if err != nil {
		return "", 0, err
	}
	if resp.ClientAttestation == nil {
		return "", 0, nil
	}
	return resp.ClientAttestation.Token, resp.ClientAttestation.ExpiresIn, nil
}
