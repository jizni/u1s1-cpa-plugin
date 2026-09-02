// attestation_test.go covers the client_attestation token cache: refresh
// collapsing, the zero-expiry bounds, and key consistency between refresh and
// lookup paths.
package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The refresh used to hold the entry mutex across the whole /models round-trip,
// so every concurrent request for one credential queued behind it. Readers must
// now proceed while exactly one refresh runs.
func TestAttestationRefreshCollapsesConcurrentCallers(t *testing.T) {
	var hits int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the round-trip open
		modelsHandler("att-concurrent", 7*24*3600)(w, r)
	}))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	authID := "auth-concurrent"
	t.Cleanup(func() { attestationCache.Delete(authID) })

	const callers = 8
	var wg sync.WaitGroup
	tokens := make([]string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tokens[idx] = attestationFor(authID, sa, "")
		}(i)
	}
	// Let the callers pile up, then let the single in-flight fetch finish.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("models hits = %d, want the concurrent refreshes collapsed into 1", n)
	}
	got := 0
	for _, token := range tokens {
		if token == "att-concurrent" {
			got++
		}
	}
	if got == 0 {
		t.Fatalf("no caller received the refreshed token: %v", tokens)
	}
}

// A seeded token with no recorded expiry must be replaced rather than trusted
// forever, and a gateway that omits expires_in must not turn every request into
// a /models round-trip.
func TestAttestationRefreshesWhenExpiryUnknown(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		modelsHandler("att-fresh", 0)(w, r) // no expires_in
	}))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	sa.Attestation = "att-seeded"
	sa.AttestationExpiresAt = 0 // unknown lifetime

	authID := "auth-unknown-expiry"
	t.Cleanup(func() { attestationCache.Delete(authID) })

	if got := attestationFor(authID, sa, ""); got != "att-fresh" {
		t.Fatalf("attestation = %q, want the seeded token with unknown expiry replaced", got)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("models hits = %d, want 1", n)
	}
	// Second call must be served from cache: a missing expires_in has to yield a
	// bounded expiry, not a zero one that reads as stale on every request.
	if got := attestationFor(authID, sa, ""); got != "att-fresh" {
		t.Fatalf("attestation = %q on the cached path", got)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("models hits = %d, want the second call served from cache", n)
	}
}

func TestAttestationFreshUntilBoundsUnknownLifetime(t *testing.T) {
	explicit := attestationFreshUntil(3600)
	if d := time.Until(explicit); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("explicit expires_in produced %v", d)
	}
	unknown := attestationFreshUntil(0)
	if unknown.IsZero() {
		t.Fatal("a missing expires_in must not yield a zero expiry")
	}
	// Must exceed the refresh margin, otherwise the entry is stale on arrival
	// and every request re-fetches.
	if d := time.Until(unknown); d <= attestationRefreshMargin {
		t.Fatalf("unknown lifetime %v must exceed the refresh margin %v", d, attestationRefreshMargin)
	}
}

func TestSetAttestationAlwaysRecordsExpiry(t *testing.T) {
	var sa storedAuth
	sa.setAttestation("tok", 0)
	if sa.Attestation != "tok" || sa.AttestationExpiresAt <= time.Now().Unix() {
		t.Fatalf("stored attestation = %q expiry = %d, want a future expiry", sa.Attestation, sa.AttestationExpiresAt)
	}
	// An empty token must never clear a good one.
	before := sa.AttestationExpiresAt
	sa.setAttestation("", 3600)
	if sa.Attestation != "tok" || sa.AttestationExpiresAt != before {
		t.Fatal("an empty token must be ignored")
	}
}

// The refresh path used to update attestationCache under req.AuthID only, while
// attestationFor falls back to the device token when AuthID is empty: the two
// keyed different entries and the refresh was silently dropped.
func TestCacheAttestationSharesKeyWithLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("attestationFor must not hit the gateway after cacheAttestation")
	}))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	sa.setAttestation("att-refreshed", 7*24*3600)
	t.Cleanup(func() { attestationCache.Delete(attestationCacheKey("", sa)) })

	cacheAttestation("", sa) // empty AuthID: keyed by device token
	if got := attestationFor("", sa, ""); got != "att-refreshed" {
		t.Fatalf("attestation = %q, want the cached token", got)
	}
}
