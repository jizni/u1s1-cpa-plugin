// auth_test.go covers the auth_provider capability: credential metadata
// publication (the host merge contract), auth.refresh, and the device login
// poll state machine.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// ---------------------------------------------------------------------------
// credential metadata must publish every key (host merge contract)
// ---------------------------------------------------------------------------

// The host merges the *existing* credential file into AuthData.Metadata before
// writing (management.saveTokenRecord -> MergeExistingAuthMetadata) and lets
// metadata win over StorageJSON. Any credential key the plugin omits from
// metadata is therefore refilled from the old file, so a freshly approved device
// token would be replaced by the revoked one.
func TestAuthDataPublishesEveryCredentialKeyInMetadata(t *testing.T) {
	sa := testStoredAuth(t)
	sa.Prefix = "u1s1"
	sa.setAttestation("att-new", 7*24*3600)

	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	// Every key in the persisted credential must also be in metadata, otherwise
	// the host backfills a stale value over it.
	var storage map[string]any
	if err := json.Unmarshal(data.StorageJSON, &storage); err != nil {
		t.Fatalf("unmarshal storage: %v", err)
	}
	for key := range storage {
		if _, published := data.Metadata[key]; !published {
			t.Fatalf("metadata omits credential key %q: the host would refill it from the previous file", key)
		}
	}
	// The security-critical ones, named explicitly so a regression is obvious.
	for _, key := range []string{"deviceToken", "devicePrivateJwk", "devicePublicJwk", "attestation", "attestationExpiresAt"} {
		if _, ok := data.Metadata[key]; !ok {
			t.Fatalf("metadata must carry %q", key)
		}
	}
	if data.Metadata["deviceToken"] != sa.DeviceToken {
		t.Fatalf("metadata deviceToken = %v", data.Metadata["deviceToken"])
	}
	if data.Metadata["attestation"] != "att-new" {
		t.Fatalf("metadata attestation = %v", data.Metadata["attestation"])
	}
}

// An empty attestation must be published as an explicit empty value, not left
// absent: absent keys are the ones the host backfills, and inheriting a token
// issued for a previous device registration produces 403s that look random.
func TestAuthDataPublishesEmptyAttestationExplicitly(t *testing.T) {
	sa := testStoredAuth(t)
	sa.Attestation = ""
	sa.AttestationExpiresAt = 0
	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	value, present := data.Metadata["attestation"]
	if !present {
		t.Fatal("attestation must be present (empty) so the host cannot backfill a stale token")
	}
	if value != "" {
		t.Fatalf("attestation = %v, want empty", value)
	}
	if data.Metadata["attestationExpiresAt"] != int64(0) {
		t.Fatalf("attestationExpiresAt = %v, want 0", data.Metadata["attestationExpiresAt"])
	}
}

// A refresh that renews the attestation must keep the user's fields.
func TestAuthRefreshPreservesUserFields(t *testing.T) {
	srv := httptest.NewServer(modelsHandler("att-refreshed", 7*24*3600))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	sa.Attestation = "att-stale"
	sa.AttestationExpiresAt = time.Now().Add(-time.Hour).Unix()
	storage, _ := json.Marshal(sa)
	var withExtras map[string]any
	_ = json.Unmarshal(storage, &withExtras)
	withExtras["priority"] = 9
	withExtras["note"] = "keep me"
	raw, _ := json.Marshal(withExtras)

	authID := "u1s1-user-fields"
	payload, _ := json.Marshal(rpcAuthRefreshRequest{AuthRefreshRequest: pluginapi.AuthRefreshRequest{
		AuthID:       authID,
		AuthProvider: providerName,
		StorageJSON:  raw,
	}})
	out, err := handleMethod(pluginabi.MethodAuthRefresh, payload)
	if err != nil {
		t.Fatalf("auth.refresh error = %v", err)
	}
	t.Cleanup(func() { attestationCache.Delete(authID) })

	var resp pluginapi.AuthRefreshResponse
	unwrapResult(t, out, &resp)
	var final map[string]any
	if err := json.Unmarshal(resp.Auth.StorageJSON, &final); err != nil {
		t.Fatalf("unmarshal refreshed storage: %v", err)
	}
	if final["attestation"] != "att-refreshed" {
		t.Fatalf("attestation = %v, want the renewed token", final["attestation"])
	}
	if final["priority"] != float64(9) || final["note"] != "keep me" {
		t.Fatalf("refresh dropped user fields: %v", final)
	}
	// Metadata must carry them too, or the host merge would resurrect old values.
	if resp.Auth.Metadata["priority"] != float64(9) {
		t.Fatalf("metadata priority = %v", resp.Auth.Metadata["priority"])
	}
}

// ---------------------------------------------------------------------------
// the host must actually schedule auth.refresh
// ---------------------------------------------------------------------------

// Without refresh_interval_seconds the host's shouldRefresh() falls through to
// ProviderRefreshLead("u1s1"), which is nil for third-party providers: the
// credential is never entered into the auto-refresh heap and auth.refresh is
// never called, no matter what NextRefreshAfter says.
func TestAuthDataRequestsRefreshInterval(t *testing.T) {
	data, err := authDataFor(testStoredAuth(t))
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if data.Metadata["refresh_interval_seconds"] != refreshIntervalSeconds {
		t.Fatalf("metadata refresh_interval_seconds = %v, want %d",
			data.Metadata["refresh_interval_seconds"], refreshIntervalSeconds)
	}
	if data.Attributes["refresh_interval_seconds"] != "43200" {
		t.Fatalf("attributes refresh_interval_seconds = %q", data.Attributes["refresh_interval_seconds"])
	}
	// The interval has to stay inside both the 7-day attestation life and the
	// 48h attestationUnknownTTL, minus the refresh margin.
	interval := time.Duration(refreshIntervalSeconds) * time.Second
	if interval >= attestationUnknownTTL-attestationRefreshMargin {
		t.Fatalf("refresh interval %v is too long for attestationUnknownTTL %v", interval, attestationUnknownTTL)
	}
}

// refresh and model.for_auth must not hand back a recomputed FileName: it would
// rename credentials imported under a different name (e.g. a copied
// ~/.u1s1/config.json). The host backfills an empty FileName from the record.
func TestRefreshLeavesFileNameToHost(t *testing.T) {
	srv := httptest.NewServer(modelsHandler("att-refresh", 7*24*3600))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	storage, _ := json.Marshal(sa)
	payload, _ := json.Marshal(rpcAuthRefreshRequest{AuthRefreshRequest: pluginapi.AuthRefreshRequest{
		AuthID:       "u1s1-imported-config",
		AuthProvider: providerName,
		StorageJSON:  storage,
	}})
	raw, err := handleMethod(pluginabi.MethodAuthRefresh, payload)
	if err != nil {
		t.Fatalf("auth.refresh error = %v", err)
	}
	t.Cleanup(func() { attestationCache.Delete("u1s1-imported-config") })

	var resp pluginapi.AuthRefreshResponse
	unwrapResult(t, raw, &resp)
	if resp.Auth.FileName != "" {
		t.Fatalf("file name = %q, want it left to the host", resp.Auth.FileName)
	}
	if resp.Auth.ID != "u1s1-imported-config" {
		t.Fatalf("id = %q, want the host auth id echoed", resp.Auth.ID)
	}
	refreshed, errParse := parseStored(resp.Auth.StorageJSON)
	if errParse != nil {
		t.Fatalf("parseStored() error = %v", errParse)
	}
	if refreshed.Attestation != "att-refresh" || refreshed.AttestationExpiresAt <= time.Now().Unix() {
		t.Fatalf("attestation = %q expiry = %d", refreshed.Attestation, refreshed.AttestationExpiresAt)
	}
}

// ---------------------------------------------------------------------------
// device login poll state machine
// ---------------------------------------------------------------------------

// A permanent 4xx from the poll route can never succeed, so the login session
// must end instead of reporting "pending" until it expires.
func TestAuthLoginPollEndsSessionOnPermanentError(t *testing.T) {
	status := http.StatusBadRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid poll secret"}}`))
	}))
	t.Cleanup(srv.Close)
	useBaseURL(t, srv.URL)

	seed := func(state string) {
		loginSessions.Store(state, &loginSession{
			Pair:       &deviceKeyPair{},
			PollSecret: "ps-1",
			ExpiresAt:  time.Now().Add(10 * time.Minute),
		})
	}
	poll := func(state string) pluginapi.AuthLoginPollResponse {
		payload, _ := json.Marshal(pluginapi.AuthLoginPollRequest{Provider: providerName, State: state})
		raw, err := handleMethod(pluginabi.MethodAuthLoginPoll, payload)
		if err != nil {
			t.Fatalf("auth.login.poll error = %v", err)
		}
		var resp pluginapi.AuthLoginPollResponse
		unwrapResult(t, raw, &resp)
		return resp
	}

	seed("u1s1-permanent")
	resp := poll("u1s1-permanent")
	if resp.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error on a permanent 4xx", resp.Status)
	}
	if _, alive := loginSessions.Load("u1s1-permanent"); alive {
		t.Fatal("a permanently failed session must be dropped")
	}

	// 429 and 5xx stay retryable.
	for _, retryable := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
		status = retryable
		state := "u1s1-retry"
		seed(state)
		if resp := poll(state); resp.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("status = %q for upstream %d, want pending", resp.Status, retryable)
		}
		if _, alive := loginSessions.Load(state); !alive {
			t.Fatalf("session must survive a retryable %d", retryable)
		}
		loginSessions.Delete(state)
	}
}

// The login flow must obtain the attestation token before calling /me: /models
// is the only route that works without it, and a bare-DPoP call to /me risks
// 403 client_integrity_review.
func TestAuthLoginPollFetchesAttestationBeforeMe(t *testing.T) {
	var mu sync.Mutex
	var order []string
	var meAttestation string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/auth/device/poll":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"device_token": "u1s1d-" + strings.Repeat("c", 64),
				"device_id":    7,
			})
		case "/v1/models":
			modelsHandler("att-login", 7*24*3600)(w, r)
		case "/v1/me":
			mu.Lock()
			meAttestation = r.Header.Get("x-u1s1-attestation")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	useBaseURL(t, srv.URL)

	pair, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}
	state := "u1s1-order"
	loginSessions.Store(state, &loginSession{Pair: pair, PollSecret: "ps-1", ExpiresAt: time.Now().Add(10 * time.Minute)})
	t.Cleanup(func() { loginSessions.Delete(state) })

	payload, _ := json.Marshal(pluginapi.AuthLoginPollRequest{Provider: providerName, State: state})
	raw, err := handleMethod(pluginabi.MethodAuthLoginPoll, payload)
	if err != nil {
		t.Fatalf("auth.login.poll error = %v", err)
	}
	var resp pluginapi.AuthLoginPollResponse
	unwrapResult(t, raw, &resp)
	if resp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status = %q (%s), want success", resp.Status, resp.Message)
	}

	mu.Lock()
	defer mu.Unlock()
	models, me := indexOf(order, "/v1/models"), indexOf(order, "/v1/me")
	if models < 0 || me < 0 {
		t.Fatalf("call order = %v, want both /v1/models and /v1/me", order)
	}
	if models > me {
		t.Fatalf("call order = %v, want /v1/models (attestation) before /v1/me", order)
	}
	if meAttestation != "att-login" {
		t.Fatalf("/me attestation header = %q, want the freshly issued token", meAttestation)
	}
	// The credential must carry the primed token and a bounded expiry.
	sa, errParse := parseStored(resp.Auth.StorageJSON)
	if errParse != nil {
		t.Fatalf("parseStored() error = %v", errParse)
	}
	if sa.Attestation != "att-login" || sa.AttestationExpiresAt <= time.Now().Unix() {
		t.Fatalf("stored attestation = %q expiry = %d", sa.Attestation, sa.AttestationExpiresAt)
	}
	if sa.Email != "user@example.com" {
		t.Fatalf("email = %q, want the /me lookup to land", sa.Email)
	}
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return -1
}
