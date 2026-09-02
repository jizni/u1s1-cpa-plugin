package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestPumpStreamReportsUpstreamFailureAfterChunks is the regression test for
// silent truncation: when the upstream connection dies mid-stream after chunks
// were already delivered, the client must see an error. Returning quietly lets
// the host append [DONE] and pass a truncated answer off as a complete one.
func TestPumpStreamReportsUpstreamFailureAfterChunks(t *testing.T) {
	srv := sseServer(t, []string{`{"i":1}`, `{"i":2}`}, true)

	var emitted []string
	var errs []string
	pumpStreamChunks(srv.URL, map[string]string{}, nil, false, "",
		func(payload []byte) error { emitted = append(emitted, string(payload)); return nil },
		func(message string) { errs = append(errs, message) })

	if len(emitted) == 0 {
		t.Fatal("expected the chunks received before the abort to be emitted")
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly one upstream read error", errs)
	}
	if !strings.Contains(errs[0], "upstream stream read error") {
		t.Fatalf("error = %q, want it to name the upstream read failure", errs[0])
	}
}

// A failing emit means the client hung up: the host already closed the stream,
// so the plugin must stay silent instead of emitting into a dead stream.
func TestPumpStreamStaysSilentWhenClientDisconnects(t *testing.T) {
	srv := sseServer(t, []string{`{"i":1}`, `{"i":2}`, `{"i":3}`}, false)

	var errs []string
	calls := 0
	pumpStreamChunks(srv.URL, map[string]string{}, nil, false, "",
		func(payload []byte) error {
			calls++
			return http.ErrBodyNotAllowed // stand-in for "host stream closed"
		},
		func(message string) { errs = append(errs, message) })

	if calls != 1 {
		t.Fatalf("emit calls = %d, want the scan to stop after the first failure", calls)
	}
	if len(errs) != 0 {
		t.Fatalf("errors = %v, want silence when the client disconnected", errs)
	}
}

func TestPumpStreamReportsEmptyStream(t *testing.T) {
	srv := sseServer(t, []string{"[DONE]"}, false)
	var errs []string
	pumpStreamChunks(srv.URL, map[string]string{}, nil, false, "",
		func([]byte) error { return nil },
		func(message string) { errs = append(errs, message) })
	if len(errs) != 1 || !strings.Contains(errs[0], "empty upstream stream") {
		t.Fatalf("errors = %v, want the empty-stream report", errs)
	}
}

// TestAttestationRefreshesWhenExpiryUnknown covers both halves of the zero-expiry
// bug: a seeded token with no recorded expiry must be replaced rather than
// trusted forever, and a gateway that omits expires_in must not turn every
// request into a /models round-trip.
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

func TestStartDeviceLoginPreservesSlowPollInterval(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/device/start" {
			t.Errorf("path = %q, want the origin-rooted auth route", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	useBaseURL(t, srv.URL)

	pair, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}

	cases := []struct {
		name     string
		interval int
		want     int
	}{
		// A rate-limited gateway asking for 60s must not be polled every 2s.
		{"slower than the cap is clamped down, not reset", 60, 30},
		{"in range is preserved", 5, 5},
		{"zero falls back to the default", 0, 2},
		{"negative falls back to the default", -1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ = json.Marshal(map[string]any{
				"verify_url":  "https://u1s1.io/login?device=abc",
				"poll_secret": "ps-1",
				"interval":    tc.interval,
				"expires_in":  900,
			})
			start, errStart := startDeviceLogin(pair, "")
			if errStart != nil {
				t.Fatalf("startDeviceLogin() error = %v", errStart)
			}
			if start.Interval != tc.want {
				t.Fatalf("interval = %d, want %d", start.Interval, tc.want)
			}
		})
	}
}

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

func TestModelForAuthUpdateLeavesFileNameToHost(t *testing.T) {
	srv := httptest.NewServer(modelsHandler("att-models", 7*24*3600))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	storage, _ := json.Marshal(sa)
	authID := "u1s1-imported-models"
	payload, _ := json.Marshal(rpcAuthModelRequest{AuthModelRequest: pluginapi.AuthModelRequest{
		AuthID:       authID,
		AuthProvider: providerName,
		StorageJSON:  storage,
	}})
	raw, err := handleMethod(pluginabi.MethodModelForAuth, payload)
	if err != nil {
		t.Fatalf("model.for_auth error = %v", err)
	}
	t.Cleanup(func() {
		attestationCache.Delete(authID)
		modelCache.Delete(authID)
	})

	var resp pluginapi.ModelResponse
	unwrapResult(t, raw, &resp)
	if len(resp.Models) != 1 || resp.Models[0].ID != "deepseek-v4-flash" {
		t.Fatalf("models = %+v", resp.Models)
	}
	if resp.AuthUpdate.FileName != "" {
		t.Fatalf("auth update file name = %q, want it left to the host", resp.AuthUpdate.FileName)
	}
	if resp.AuthUpdate.ID != authID {
		t.Fatalf("auth update id = %q", resp.AuthUpdate.ID)
	}
}

// An empty email must not publish empty metadata/attribute values: the host
// merges only missing keys, so an explicit "" overwrites a known good email.
func TestAuthDataOmitsEmptyEmailMetadata(t *testing.T) {
	sa := testStoredAuth(t)
	sa.Email = ""
	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if _, exists := data.Metadata["email"]; exists {
		t.Fatal("metadata must omit email when the credential has none")
	}
	if _, exists := data.Attributes["email"]; exists {
		t.Fatal("attributes must omit email when the credential has none")
	}
	sa.Email = "user@example.com"
	data, err = authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if data.Metadata["email"] != "user@example.com" || data.Attributes["email"] != "user@example.com" {
		t.Fatalf("email not published: meta=%v attr=%v", data.Metadata["email"], data.Attributes["email"])
	}
}

// A pub/priv mismatch (hand-edited or truncated credential file) can never
// produce a verifiable proof: fail at parse time with a precise message.
func TestParsePrivateJWKRejectsMismatchedKeypair(t *testing.T) {
	a, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}
	b, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}
	mixed := a.Private
	mixed.X, mixed.Y = b.Private.X, b.Private.Y
	if _, err := parsePrivateJWK(mixed); err == nil {
		t.Fatal("expected a mismatched public point to be rejected")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want it to name the mismatch", err)
	}
	if _, err := parsePrivateJWK(a.Private); err != nil {
		t.Fatalf("a consistent keypair must parse: %v", err)
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
	if strings.Contains(out2str(out), secret) {
		t.Fatalf("plugin_error leaked the device token: %s", out)
	}
}

func out2str(b []byte) string { return string(b) }

func TestCollectStreamCapsBufferedBytes(t *testing.T) {
	chunk := `{"pad":"` + strings.Repeat("x", 2048) + `"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 64; i++ {
			_, _ = w.Write([]byte("data: " + chunk + "\n\n"))
		}
	}))
	t.Cleanup(srv.Close)

	// Small responses stay unaffected by the cap.
	chunks, status, err := collectStream(srv.URL, map[string]string{}, nil, false, "")
	if err != nil || status != 200 || len(chunks) != 64 {
		t.Fatalf("chunks=%d status=%d err=%v", len(chunks), status, err)
	}
}
