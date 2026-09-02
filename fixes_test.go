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

// ---------------------------------------------------------------------------
// 1. re-login must not be overwritten by the stale credential file
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

// ---------------------------------------------------------------------------
// 2. round-tripping the credential must not drop unmodelled keys
// ---------------------------------------------------------------------------

// auth.refresh and model.for_auth decode the credential file into storedAuth and
// re-encode it. Fields the struct does not model (host- and user-owned settings)
// used to disappear on every refresh.
func TestStoredAuthPreservesUnknownKeys(t *testing.T) {
	sa := testStoredAuth(t)
	base, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var withExtras map[string]any
	if err := json.Unmarshal(base, &withExtras); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	extras := map[string]any{
		"priority":        float64(7),
		"note":            "primary account",
		"proxy_url":       "http://proxy.internal:8080",
		"weight":          float64(3),
		"excluded_models": []any{"glm-5.3-free"},
		"disabled":        false,
		"request_retry":   float64(2),
		"headers":         map[string]any{"x-trace": "on"},
	}
	for key, value := range extras {
		withExtras[key] = value
	}
	raw, _ := json.Marshal(withExtras)

	parsed, err := parseStored(raw)
	if err != nil {
		t.Fatalf("parseStored() error = %v", err)
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal round-trip: %v", err)
	}
	var final map[string]any
	if err := json.Unmarshal(out, &final); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}
	for key, want := range extras {
		got, ok := final[key]
		if !ok {
			t.Fatalf("round-trip dropped %q", key)
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("%q = %s, want %s", key, gotJSON, wantJSON)
		}
	}
	// Modelled fields must still win over anything carried in Extra.
	if final["deviceToken"] != sa.DeviceToken {
		t.Fatalf("deviceToken = %v", final["deviceToken"])
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
// 3. the host must actually schedule auth.refresh
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

// ---------------------------------------------------------------------------
// 4. thinking suffix must be split off and translated
// ---------------------------------------------------------------------------

func seedThinkingProfile(t *testing.T, id, requestFormat string, levels []string, canDisable bool, levelMap map[string]string) {
	t.Helper()
	storeThinkingProfile(gatewayModel{
		ID:        id,
		Reasoning: true,
		Thinking: &modelThinking{
			Levels:        levels,
			DefaultLevel:  "high",
			CanDisable:    canDisable,
			LevelMap:      levelMap,
			RequestFormat: requestFormat,
		},
	})
	t.Cleanup(func() { thinkingProfiles.Delete(id) })
}

// The host strips only the auth prefix; the suffix stays on req.Model. Sending
// "deepseek-v4-flash(high)" upstream is a 400 unknown model.
func TestPrepareBodyStripsThinkingSuffix(t *testing.T) {
	seedThinkingProfile(t, "deepseek-v4-flash", "deepseek",
		[]string{"off", "low", "high", "max"}, true,
		map[string]string{"off": "none", "low": "low", "high": "high", "max": "max"})

	body := prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(high)", false)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v, want the suffix stripped", obj["model"])
	}
	thinking, ok := obj["thinking"].(map[string]any)
	if !ok || thinking["type"] != "enabled" {
		t.Fatalf("thinking = %v, want {type:enabled} for the deepseek request format", obj["thinking"])
	}
	if obj["reasoning_effort"] != "high" {
		t.Fatalf("reasoning_effort = %v", obj["reasoning_effort"])
	}
}

func TestPrepareBodyThinkingRequestFormats(t *testing.T) {
	seedThinkingProfile(t, "qwen3.8-flash", "qwen",
		[]string{"off", "low", "medium", "xhigh"}, true,
		map[string]string{"off": "none", "low": "low", "medium": "medium", "xhigh": "xhigh"})
	seedThinkingProfile(t, "glm-5.3-flash", "openai",
		[]string{"low", "high", "max"}, false,
		map[string]string{"low": "low", "high": "high", "max": "max"})

	// qwen: enable_thinking + reasoning_effort.
	var qwen map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "qwen3.8-flash(medium)", false), &qwen)
	if qwen["enable_thinking"] != true || qwen["reasoning_effort"] != "medium" {
		t.Fatalf("qwen body = %v", qwen)
	}
	if _, ok := qwen["thinking"]; ok {
		t.Fatal("qwen format must not carry the deepseek thinking object")
	}

	// qwen off: enable_thinking false and no effort.
	var qwenOff map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "qwen3.8-flash(off)", false), &qwenOff)
	if qwenOff["enable_thinking"] != false {
		t.Fatalf("qwen off body = %v", qwenOff)
	}
	if _, ok := qwenOff["reasoning_effort"]; ok {
		t.Fatal("a disabled request must not carry reasoning_effort")
	}

	// openai: effort only.
	var glm map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "glm-5.3-flash(max)", false), &glm)
	if glm["reasoning_effort"] != "max" {
		t.Fatalf("openai-format body = %v", glm)
	}
	for _, key := range []string{"thinking", "enable_thinking"} {
		if _, ok := glm[key]; ok {
			t.Fatalf("openai format must not carry %q", key)
		}
	}

	// A model that cannot disable thinking must get its lowest level, not a
	// disable the gateway would reject.
	var glmOff map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "glm-5.3-flash(off)", false), &glmOff)
	if glmOff["reasoning_effort"] != "low" {
		t.Fatalf("non-disableable model off -> %v, want the lowest level", glmOff["reasoning_effort"])
	}
}

// A level the model does not advertise must fall back to its default instead of
// being forwarded verbatim.
func TestPrepareBodyUnsupportedLevelFallsBackToDefault(t *testing.T) {
	seedThinkingProfile(t, "deepseek-v4-flash", "deepseek",
		[]string{"off", "low", "high", "max"}, true,
		map[string]string{"off": "none", "low": "low", "high": "high", "max": "max"})

	var obj map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(medium)", false), &obj)
	if obj["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v", obj["model"])
	}
	if obj["reasoning_effort"] != "high" {
		t.Fatalf("reasoning_effort = %v, want the model default", obj["reasoning_effort"])
	}
}

// A numeric budget suffix has no u1s1 equivalent: 0 disables, anything else runs
// at the default level. Either way the suffix must leave the model id.
func TestPrepareBodyNumericBudgetSuffix(t *testing.T) {
	seedThinkingProfile(t, "deepseek-v4-flash", "deepseek",
		[]string{"off", "low", "high", "max"}, true,
		map[string]string{"off": "none", "low": "low", "high": "high", "max": "max"})

	var enabled map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(8192)", false), &enabled)
	if enabled["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v", enabled["model"])
	}
	if thinking, _ := enabled["thinking"].(map[string]any); thinking["type"] != "enabled" {
		t.Fatalf("positive budget -> %v, want thinking enabled", enabled["thinking"])
	}

	var disabled map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(0)", false), &disabled)
	if thinking, _ := disabled["thinking"].(map[string]any); thinking["type"] != "disabled" {
		t.Fatalf("zero budget -> %v, want thinking disabled", disabled["thinking"])
	}
}

// A model with no cached reasoning profile must be left alone: inventing fields
// for an unknown model is what produces 400s.
func TestPrepareBodyLeavesUnknownModelThinkingAlone(t *testing.T) {
	body := prepareBody([]byte(`{"messages":[]}`), nil, "mystery-model(high)", false)
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	if obj["model"] != "mystery-model" {
		t.Fatalf("model = %v, the suffix must still be stripped", obj["model"])
	}
	for _, key := range []string{"thinking", "enable_thinking", "reasoning_effort"} {
		if _, ok := obj[key]; ok {
			t.Fatalf("unknown model must not get %q", key)
		}
	}
}

// A model id that merely contains parentheses is not a thinking suffix.
func TestParseModelSuffix(t *testing.T) {
	for _, tc := range []struct {
		in     string
		base   string
		suffix string
		has    bool
	}{
		{"deepseek-v4-flash", "deepseek-v4-flash", "", false},
		{"deepseek-v4-flash(high)", "deepseek-v4-flash", "high", true},
		{"model(8192)", "model", "8192", true},
		{"model(unclosed", "model(unclosed", "", false},
	} {
		base, suffix, has := parseModelSuffix(tc.in)
		if base != tc.base || suffix != tc.suffix || has != tc.has {
			t.Fatalf("parseModelSuffix(%q) = (%q,%q,%v)", tc.in, base, suffix, has)
		}
	}
}

// fetchModels is the one route every credential path goes through, so it has to
// be what populates the reasoning profiles a chat request later needs.
func TestFetchModelsCachesThinkingProfiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data": []map[string]any{{
				"id": "profiled-model", "object": "model", "reasoning": true,
				"thinking": map[string]any{
					"levels": []string{"off", "high"}, "default_level": "high",
					"can_disable": true, "request_format": "deepseek",
					"level_map": map[string]string{"off": "none", "high": "high"},
				},
			}},
		})
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { thinkingProfiles.Delete("profiled-model") })

	if _, ok := thinkingProfileFor("profiled-model"); ok {
		t.Fatal("profile must not exist before the models call")
	}
	if _, err := fetchModels(storedAuthFor(t, srv.URL), "", ""); err != nil {
		t.Fatalf("fetchModels() error = %v", err)
	}
	profile, ok := thinkingProfileFor("profiled-model")
	if !ok {
		t.Fatal("fetchModels must cache the reasoning profile")
	}
	if profile.RequestFormat != "deepseek" || profile.DefaultLevel != "high" || !profile.CanDisable {
		t.Fatalf("profile = %+v", profile)
	}
}

// ---------------------------------------------------------------------------
// 5. panics must not cross the cgo boundary
// ---------------------------------------------------------------------------

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

// pumpStream's goroutine has no cgo frame to unwind into at all, so a panic
// there kills the process unless it is recovered and reported.
func TestStreamPanicIsReportedNotFatal(t *testing.T) {
	var emitted []string
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("panic escaped the guard: %v", recovered)
			}
		}()
		defer reportStreamPanicTo("stream-1", func(message string) { emitted = append(emitted, message) })
		panic("scan exploded")
	}()
	if len(emitted) != 1 || !strings.Contains(emitted[0], "panic while streaming") {
		t.Fatalf("emitted = %v, want the panic reported as a stream error", emitted)
	}
	// pumpStream must still close the stream after a panic, so the client is not
	// left waiting on an abandoned stream. Verified structurally: streamClose is
	// deferred before the panic guard, so it runs last.
	srv := sseServer(t, []string{`{"i":1}`}, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// No host bridge in tests: emit fails, the pump goes quiet and returns.
		pumpStream(srv.URL, map[string]string{}, nil, false, "stream-2", "")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pumpStream did not return")
	}
}

// ---------------------------------------------------------------------------
// 6. attestation refresh must not serialize concurrent chat requests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 7. usage collection must not be serialized behind the cache lock
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 8. count_tokens must report a usable estimate, not zero
// ---------------------------------------------------------------------------

// A flat zero reads as "empty conversation" in usage logs and disables client
// context-budget warnings.
func TestCountTokensEstimatesPrompt(t *testing.T) {
	body := []byte(`{"model":"deepseek-v4-flash","messages":[
		{"role":"system","content":"You are a helpful assistant."},
		{"role":"user","content":"请帮我审查这段代码的并发安全性"}]}`)
	payload, _ := json.Marshal(rpcExecutorRequest{ExecutorRequest: pluginapi.ExecutorRequest{Payload: body}})
	raw, err := handleMethod(pluginabi.MethodExecutorCountTokens, payload)
	if err != nil {
		t.Fatalf("executor.count_tokens error = %v", err)
	}
	var resp pluginapi.ExecutorResponse
	unwrapResult(t, raw, &resp)

	var out struct {
		TotalTokens int `json:"total_tokens"`
		Usage       struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatalf("unmarshal count payload: %v", err)
	}
	if out.TotalTokens <= 0 {
		t.Fatalf("total_tokens = %d, want a positive estimate", out.TotalTokens)
	}
	if out.Usage.PromptTokens != out.TotalTokens || out.Usage.TotalTokens != out.TotalTokens {
		t.Fatalf("usage block inconsistent: %+v", out)
	}
	// The estimate must scale with the prompt.
	longer := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("word ", 500) + `"}]}`)
	if countTokensEstimate(longer) <= out.TotalTokens {
		t.Fatal("a much longer prompt must estimate higher")
	}
	// CJK counts about one token per rune, Latin about one per four bytes.
	if got := countTokensEstimate([]byte(`{"messages":[{"role":"user","content":"你好世界"}]}`)); got < 8 {
		t.Fatalf("CJK estimate = %d, want at least the rune count plus overhead", got)
	}
	if countTokensEstimate(nil) != 0 {
		t.Fatal("an empty body must estimate zero")
	}
	// An unparseable body must still scale with size rather than report zero.
	if countTokensEstimate([]byte("not json at all, but long enough to matter")) <= 0 {
		t.Fatal("unparseable bodies must fall back to a size-based estimate")
	}
}

// ---------------------------------------------------------------------------
// 9. the live catalogue must carry the pricing metadata clients decide on
// ---------------------------------------------------------------------------

// The gateway's model list is the only place free-package coverage and price
// live. Without them a client picking "the cheap model" has to guess, and on
// u1s1 that guess is the difference between free and paid, so model.for_auth
// mirrors the note the official CLI shows in its picker.
func TestModelDescriptionMirrorsCLINote(t *testing.T) {
	price := func(in, out float64) *modelPrice { return &modelPrice{Input: in, Output: out} }
	yes, no := true, false
	catalogue := []gatewayModel{
		{ID: defaultFreeModelID, FreePackageEligible: &yes, Price: price(0.22, 0.66)},
		{ID: "deepseek-v4-pro", FreePackageEligible: &no, Price: price(0.66, 1.98)},
		{ID: "slightly-dearer", FreePackageEligible: &no, Price: price(0.24, 0.7)},
		{ID: "legacy-gateway-model", Price: price(1, 1)},
	}
	base := baseModelBlendedPrice(catalogue)
	if base != 0.44 {
		t.Fatalf("base blended price = %v, want the default free model's", base)
	}

	free := modelDescription(catalogue[0], base)
	if !strings.Contains(free, "免费用量包可抵扣") || !strings.Contains(free, "$0.22/$0.66") {
		t.Fatalf("free model description = %q", free)
	}
	// 3x the default: the multiple is what stops a user from casually burning
	// paid balance on the Pro model.
	if paid := modelDescription(catalogue[1], base); !strings.Contains(paid, "3 倍") {
		t.Fatalf("paid model description = %q, want the price multiple", paid)
	}
	// Under 2x the multiple is noise; the coverage warning still has to show.
	near := modelDescription(catalogue[2], base)
	if strings.Contains(near, "倍") || !strings.Contains(near, "不走免费包") {
		t.Fatalf("near-price model description = %q", near)
	}
	// An older gateway omits free_package_eligible: no coverage claim either way.
	legacy := modelDescription(catalogue[3], base)
	if strings.Contains(legacy, "免费包") {
		t.Fatalf("unknown coverage must not be described as covered or not: %q", legacy)
	}
	if !strings.Contains(legacy, "每百万 token") {
		t.Fatalf("legacy model description = %q, want the price kept", legacy)
	}
}

// Peak/off-peak models bill at double during Beijing business hours, so the
// note has to name the band that is actually in effect.
func TestModelDescriptionNamesActivePriceBand(t *testing.T) {
	m := gatewayModel{
		ID:         "deepseek-v4-flash",
		Price:      &modelPrice{Input: 0.44, Output: 1.32},
		PriceBands: &modelPriceBands{Current: "peak", Peak: &bandPrice{Input: 0.44, Output: 1.32}, OffPeak: &bandPrice{Input: 0.22, Output: 0.66}},
	}
	if got := modelDescription(m, 0); !strings.Contains(got, "当前峰时价") {
		t.Fatalf("description = %q, want the active band named", got)
	}
	m.PriceBands.Current = "off_peak"
	if got := modelDescription(m, 0); !strings.Contains(got, "当前闲时价") {
		t.Fatalf("description = %q, want the off-peak band named", got)
	}
	// A model without bands must not grow a band label.
	flat := gatewayModel{ID: "qwen3.8-flash", Price: &modelPrice{Input: 0.16, Output: 0.47}}
	if got := modelDescription(flat, 0); strings.Contains(got, "峰") {
		t.Fatalf("flat-priced model description = %q", got)
	}
	// Prices must not gain trailing zeros: the CLI prints 0.075, not 0.08.
	if got := priceNote(gatewayModel{Price: &modelPrice{Input: 0.075, Output: 0.25}}); !strings.Contains(got, "$0.075/$0.25") {
		t.Fatalf("price note = %q", got)
	}
}

// ---------------------------------------------------------------------------
// 10. the gateway announcement must reach the panel
// ---------------------------------------------------------------------------

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

