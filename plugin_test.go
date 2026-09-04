package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func unwrapResult(t *testing.T, raw []byte, out any) {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("envelope not ok: %+v", env.Error)
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
	}
}

func TestRegisterDeclaresCapabilities(t *testing.T) {
	raw, err := handleMethod(pluginabi.MethodPluginRegister, []byte(`{"config_yaml":"","schema_version":1}`))
	if err != nil {
		t.Fatalf("plugin.register error = %v", err)
	}
	var reg registration
	unwrapResult(t, raw, &reg)
	if reg.Metadata.Name != providerName {
		t.Fatalf("metadata name = %q", reg.Metadata.Name)
	}
	if !reg.Capabilities.AuthProvider || !reg.Capabilities.ModelProvider || !reg.Capabilities.Executor {
		t.Fatalf("capabilities = %+v, want auth+model+executor", reg.Capabilities)
	}
	if reg.Capabilities.ExecutorModelScope != pluginapi.ExecutorModelScopeOAuth {
		t.Fatalf("executor scope = %q", reg.Capabilities.ExecutorModelScope)
	}
	if len(reg.Capabilities.ExecutorInputFormats) == 0 || len(reg.Capabilities.ExecutorOutputFormats) == 0 {
		t.Fatal("executor must declare at least one input and output format")
	}
}

func TestReconfigureAppliesConfig(t *testing.T) {
	t.Cleanup(func() {
		cfgMu.Lock()
		pluginCfg = defaultPluginConfig()
		cfgMu.Unlock()
	})
	payload, _ := json.Marshal(map[string]any{
		"config_yaml": []byte("base-url: https://gw.example.com/v1\nclient-version: \"9.9.9\"\n"),
	})
	if _, err := handleMethod(pluginabi.MethodPluginReconfigure, payload); err != nil {
		t.Fatalf("plugin.reconfigure error = %v", err)
	}
	cfg := activeConfig()
	if cfg.BaseURL != "https://gw.example.com/v1" {
		t.Fatalf("base URL = %q", cfg.BaseURL)
	}
	if cfg.ClientVersion != "9.9.9" {
		t.Fatalf("client version = %q", cfg.ClientVersion)
	}
	if cfg.apiOrigin() != "https://gw.example.com" {
		t.Fatalf("apiOrigin() = %q, want the /v1 suffix stripped", cfg.apiOrigin())
	}
}

func TestUnknownMethod(t *testing.T) {
	raw, err := handleMethod("does.not.exist", nil)
	if err != nil {
		t.Fatalf("unexpected error = %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "unknown_method" {
		t.Fatalf("expected unknown_method error, got %+v", env)
	}
}

func TestAuthParseClaimsDeviceCredentials(t *testing.T) {
	sa := testStoredAuth(t)
	storage, _ := json.Marshal(sa)
	payload, _ := json.Marshal(pluginapi.AuthParseRequest{
		Provider: providerName,
		FileName: "u1s1-user-example.com.json",
		RawJSON:  storage,
	})
	raw, err := handleMethod(pluginabi.MethodAuthParse, payload)
	if err != nil {
		t.Fatalf("auth.parse error = %v", err)
	}
	var resp pluginapi.AuthParseResponse
	unwrapResult(t, raw, &resp)
	if !resp.Handled {
		t.Fatal("auth.parse must claim a valid u1s1 credential file")
	}
	if resp.Auth.Provider != providerName {
		t.Fatalf("provider = %q", resp.Auth.Provider)
	}
	if resp.Auth.FileName != "u1s1-user-example.com.json" {
		t.Fatalf("file name = %q, want the discovered name preserved", resp.Auth.FileName)
	}
	if resp.Auth.Label != "user@example.com" {
		t.Fatalf("label = %q", resp.Auth.Label)
	}
	// StorageJSON must round-trip into a usable credential.
	if _, err := parseStored(resp.Auth.StorageJSON); err != nil {
		t.Fatalf("parseStored(StorageJSON) error = %v", err)
	}
	// No email: fall back to a device suffix without exposing the token.
	sa.Email = ""
	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if !strings.HasPrefix(data.ID, "u1s1-device-") {
		t.Fatalf("id = %q, want a u1s1-device- fallback", data.ID)
	}
	if strings.Contains(data.ID, sa.DeviceToken) {
		t.Fatal("identity must not embed the full device token")
	}
}

func TestAuthParseIgnoresForeignFiles(t *testing.T) {
	for name, body := range map[string]string{
		"other provider":  `{"type":"gemini","access_token":"x"}`,
		"no device token": `{"type":"u1s1","apiKey":"u1s1-abc"}`,
		"not json":        `not json at all`,
	} {
		payload, _ := json.Marshal(pluginapi.AuthParseRequest{RawJSON: []byte(body)})
		raw, err := handleMethod(pluginabi.MethodAuthParse, payload)
		if err != nil {
			t.Fatalf("%s: auth.parse error = %v", name, err)
		}
		var resp pluginapi.AuthParseResponse
		unwrapResult(t, raw, &resp)
		if resp.Handled {
			t.Fatalf("%s: must not be claimed by the u1s1 plugin", name)
		}
	}
}

func TestAuthLoginPollUnknownState(t *testing.T) {
	payload, _ := json.Marshal(pluginapi.AuthLoginPollRequest{Provider: providerName, State: "u1s1-missing"})
	raw, err := handleMethod(pluginabi.MethodAuthLoginPoll, payload)
	if err != nil {
		t.Fatalf("auth.login.poll error = %v", err)
	}
	var resp pluginapi.AuthLoginPollResponse
	unwrapResult(t, raw, &resp)
	if resp.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error for an unknown state", resp.Status)
	}
}

func TestPrepareBodyForcesModelAndStream(t *testing.T) {
	in := []byte(`{"model":"alias","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	out := prepareBody(in, nil, "deepseek-v4-flash", true)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v", obj["model"])
	}
	if obj["stream"] != true {
		t.Fatalf("stream = %v", obj["stream"])
	}
	opts, ok := obj["stream_options"].(map[string]any)
	if !ok || opts["include_usage"] != true {
		t.Fatalf("stream_options = %v, want include_usage", obj["stream_options"])
	}

	// Non-streaming requests must not carry stream_options.
	// Decode into a fresh map: json.Unmarshal merges into a non-nil map.
	out = prepareBody(out, nil, "deepseek-v4-flash", false)
	nonStream := map[string]any{}
	if err := json.Unmarshal(out, &nonStream); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nonStream["stream"] != false {
		t.Fatalf("stream = %v", nonStream["stream"])
	}
	if _, exists := nonStream["stream_options"]; exists {
		t.Fatal("stream_options must be removed for non-streaming requests")
	}
}

func TestPrepareBodyFallsBackToOriginal(t *testing.T) {
	original := []byte(`{"model":"x","messages":[]}`)
	out := prepareBody(nil, original, "m", false)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["model"] != "m" {
		t.Fatalf("model = %v", obj["model"])
	}
	// Non-JSON payloads are passed through untouched.
	if got := prepareBody([]byte("not json"), nil, "m", false); string(got) != "not json" {
		t.Fatalf("passthrough = %q", got)
	}
}

func TestSSEFramingDependsOnEntryPath(t *testing.T) {
	if clientNeedsSSEFrame(map[string]any{"request_path": "/v1/chat/completions"}) {
		t.Fatal("native chat-completions path must not be re-framed")
	}
	if !clientNeedsSSEFrame(map[string]any{"request_path": "/v1/messages"}) {
		t.Fatal("cross-format paths need data: framing")
	}
	if !clientNeedsSSEFrame(nil) {
		t.Fatal("unknown path must default to framed output")
	}
	if got := string(framePayload([]byte(`{"a":1}`), true)); got != `data: {"a":1}` {
		t.Fatalf("framePayload = %q", got)
	}
	if got := string(framePayload([]byte(`{"a":1}`), false)); got != `{"a":1}` {
		t.Fatalf("framePayload = %q", got)
	}
}

func TestScanSSEDropsDoneAndInvalidChunks(t *testing.T) {
	body := "data: {\"i\":1}\n\n" +
		"data: not-json\n\n" +
		"data: {\"i\":2}\n\n" +
		"data: [DONE]\n\n" +
		"data: {\"i\":3}\n\n"
	var got []string
	err := scanSSE(newStreamReader(&upstreamStream{direct: newFakeBody(body)}), func(payload []byte) error {
		got = append(got, string(payload))
		return nil
	})
	if err != nil {
		t.Fatalf("scanSSE error = %v", err)
	}
	if len(got) != 2 || got[0] != `{"i":1}` || got[1] != `{"i":2}` {
		t.Fatalf("chunks = %v, want the two valid events before [DONE]", got)
	}
}

func TestGatewayMessageExtractsError(t *testing.T) {
	body := []byte(`{"error":{"message":"客户端完整性校验未通过","type":"forbidden","code":"client_integrity_review","request_id":"req-42"}}`)
	got := gatewayMessage(body, 403)
	// The Chinese sentence must lead (that is what a user reads) and the tail must
	// carry status, code, and request id (that is what support needs).
	if !strings.HasPrefix(got, "客户端完整性校验未通过 (") {
		t.Fatalf("gatewayMessage = %q", got)
	}
	for _, needle := range []string{"HTTP 403", "client_integrity_review", "请求编号 req-42"} {
		if !strings.Contains(got, needle) {
			t.Fatalf("gatewayMessage = %q, want %q in the tail", got, needle)
		}
	}
	// insufficient_quota is the marker that tells clients not to retry; the CLI
	// normalizes both spellings to it, so the plugin must too.
	quota := gatewayMessage([]byte(`{"error":{"message":"额度已用完","type":"insufficient_quota"}}`), 429)
	if !strings.Contains(quota, "insufficient_quota") {
		t.Fatalf("gatewayMessage = %q, want the insufficient_quota marker", quota)
	}
	if got := gatewayMessage([]byte("<html>oops</html>"), 502); !strings.Contains(got, "502") {
		t.Fatalf("gatewayMessage = %q, want the status in the fallback", got)
	}
}

func TestRedactSecrets(t *testing.T) {
	in := "auth failed for u1s1d-deadbeefcafe0123 with key u1s1-secretkey trailing"
	out := redactSecrets(in)
	if strings.Contains(out, "deadbeefcafe0123") || strings.Contains(out, "secretkey") {
		t.Fatalf("redactSecrets leaked material: %q", out)
	}
	if !strings.Contains(out, "u1s1d-[redacted]") || !strings.Contains(out, "u1s1-[redacted]") {
		t.Fatalf("redactSecrets = %q", out)
	}
	if !strings.HasSuffix(out, "trailing") {
		t.Fatalf("redactSecrets dropped trailing text: %q", out)
	}
}

func TestToModelInfoMapsThinkingAndLimits(t *testing.T) {
	info := toModelInfo(gatewayModel{
		ID:            "deepseek-v4-flash",
		Name:          "DeepSeek V4 Flash",
		Reasoning:     true,
		Vision:        true,
		ContextLength: 1048576,
		MaxTokens:     384000,
		Thinking:      &modelThinking{Levels: []string{"off", "low", "high", "max"}, CanDisable: true},
	}, "免费用量包可抵扣")
	if info.ID != "deepseek-v4-flash" || info.DisplayName != "DeepSeek V4 Flash" {
		t.Fatalf("info = %+v", info)
	}
	if info.Description != "免费用量包可抵扣" {
		t.Fatalf("description = %q", info.Description)
	}
	if info.ContextLength != 1048576 || info.MaxCompletionTokens != 384000 {
		t.Fatalf("limits = %d/%d", info.ContextLength, info.MaxCompletionTokens)
	}
	if info.Thinking == nil || len(info.Thinking.Levels) != 4 || !info.Thinking.ZeroAllowed {
		t.Fatalf("thinking = %+v", info.Thinking)
	}
	if len(info.SupportedInputModalities) != 2 {
		t.Fatalf("input modalities = %v, want text+image", info.SupportedInputModalities)
	}

	// Thinking metadata without the reasoning flag still exposes the levels: the
	// CLI treats either signal as sufficient, and the executor needs the levels.
	unflagged := toModelInfo(gatewayModel{
		ID:       "quiet-model",
		Thinking: &modelThinking{Levels: []string{"low", "high"}},
	}, "")
	if unflagged.Thinking == nil || len(unflagged.Thinking.Levels) != 2 {
		t.Fatalf("thinking = %+v, want the advertised levels", unflagged.Thinking)
	}
}

func TestParseStoredRejectsIncompleteCredentials(t *testing.T) {
	if _, err := parseStored(nil); err == nil {
		t.Fatal("expected an error for empty storage")
	}
	if _, err := parseStored([]byte(`{"deviceToken":"u1s1d-abc"}`)); err == nil {
		t.Fatal("expected an error when the keypair is missing")
	}
	sa := testStoredAuth(t)
	storage, _ := json.Marshal(sa)
	parsed, err := parseStored(storage)
	if err != nil {
		t.Fatalf("parseStored() error = %v", err)
	}
	if parsed.baseURL() != defaultBaseURL {
		t.Fatalf("baseURL() = %q", parsed.baseURL())
	}
}

func TestAuthDataEchoesPrefix(t *testing.T) {
	// The host only auto-fills Prefix for natively parsed files; a plugin parser
	// must echo it or a management-set model prefix silently disappears.
	sa := testStoredAuth(t)
	sa.Prefix = "u1s1"
	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if data.Prefix != "u1s1" {
		t.Fatalf("prefix = %q, want it echoed back to the host", data.Prefix)
	}
	if data.Metadata["prefix"] != "u1s1" {
		t.Fatalf("metadata prefix = %v", data.Metadata["prefix"])
	}
	round, err := parseStored(data.StorageJSON)
	if err != nil {
		t.Fatalf("parseStored() error = %v", err)
	}
	if round.Prefix != "u1s1" {
		t.Fatalf("prefix did not survive the storage round-trip: %q", round.Prefix)
	}
}

func TestManagementRegistrationRoutes(t *testing.T) {
	payload, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{
		BasePath:         "/v0/management",
		ResourceBasePath: "/v0/resource/plugins/u1s1",
	})
	raw, err := handleMethod(pluginabi.MethodManagementRegister, payload)
	if err != nil {
		t.Fatalf("management.register error = %v", err)
	}
	var reg managementRegistrationResponse
	unwrapResult(t, raw, &reg)
	if len(reg.Resources) != 1 || reg.Resources[0].Path != "/panel" || reg.Resources[0].Menu != "u1s1" {
		t.Fatalf("resources = %+v", reg.Resources)
	}
	var methods []string
	for _, r := range reg.Routes {
		methods = append(methods, r.Method+" "+r.Path)
	}
	want := map[string]bool{"GET /plugins/u1s1/usage": true, "POST /plugins/u1s1/refresh": true}
	for _, m := range methods {
		delete(want, m)
	}
	if len(want) != 0 {
		t.Fatalf("missing routes %v, got %v", want, methods)
	}
}

func TestPanelResourceServesHTMLWithoutSecrets(t *testing.T) {
	payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
		Method: "GET",
		Path:   "/v0/resource/plugins/u1s1/panel",
	}})
	raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
	if err != nil {
		t.Fatalf("management.handle error = %v", err)
	}
	var resp pluginapi.ManagementResponse
	unwrapResult(t, raw, &resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Headers.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "u1s1") || !strings.Contains(body, "<script>") {
		t.Fatal("panel HTML looks empty")
	}
	// The template placeholder must be substituted with the live base path.
	if strings.Contains(body, "__U1S1_MANAGEMENT_BASE_PATH_JSON__") {
		t.Fatal("management base path placeholder was not replaced")
	}
	if !strings.Contains(body, `"/v0/management"`) {
		t.Fatal("expected the injected management base path in the page")
	}
	// The unauthenticated resource page must not embed any quota or credential data.
	for _, needle := range []string{"u1s1d-", "devicePrivateJwk", "deviceToken", "daily_free_remaining_usd\":"} {
		if strings.Contains(body, needle) {
			t.Fatalf("panel HTML leaked %q", needle)
		}
	}
}

func TestManagementUnknownRoute(t *testing.T) {
	payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
		Method: "GET",
		Path:   "/v0/management/plugins/u1s1/nope",
	}})
	raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
	if err != nil {
		t.Fatalf("management.handle error = %v", err)
	}
	var resp pluginapi.ManagementResponse
	unwrapResult(t, raw, &resp)
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPackageLabelsAndScopeNotes(t *testing.T) {
	if got := packageLabel("free_first"); got != "首月免费包" {
		t.Fatalf("packageLabel = %q", got)
	}
	if got := packageLabel("unknown_kind"); got != "unknown_kind" {
		t.Fatalf("unknown kind should pass through, got %q", got)
	}
	// login_checkin packages work on every model; free-scope ones are restricted.
	if note := packageScopeNote(gatewayPackage{Kind: "login_checkin", Scope: "all"}); !strings.Contains(note, "全模型") {
		t.Fatalf("scope note = %q", note)
	}
	if note := packageScopeNote(gatewayPackage{Kind: "free_first", Scope: "free"}); !strings.Contains(note, "0 点恢复") {
		t.Fatalf("scope note = %q", note)
	}
}

func TestIsU1S1AuthName(t *testing.T) {
	for _, name := range []string{"u1s1-user-example.com.json", "/root/.cli-proxy-api/u1s1-x.json", "U1S1-Upper.JSON"} {
		if !isU1S1AuthName(name) {
			t.Fatalf("%q should be recognized", name)
		}
	}
	for _, name := range []string{"workbuddy-abc.json", "u1s1.json", "u1s1-x.txt", ""} {
		if isU1S1AuthName(name) {
			t.Fatalf("%q must not be claimed", name)
		}
	}
}

func TestMeResponseParsesPackagesAndFreeClaim(t *testing.T) {
	// Shape captured from a real GET /v1/me response.
	body := []byte(`{"email":"u@example.com","daily_free_usd":44.000005,"daily_free_used_usd":0.07,
"daily_free_remaining_usd":43.93,"daily_free_resets_at":"2026-09-02T16:00:00.000Z",
"daily_free_model":"deepseek-v4-flash","mtd_usd":0.012,"remaining_usd":10.56,"tokens_per_usd":2272727,
"packages":[{"id":450,"kind":"free_first","scope":"free","daily_tokens":100000000,"total_tokens":null,
"used_today":1517,"used_tokens":0,"remaining":99998483,"expires_at":"2026-09-24 08:33:29","note":"首月免费包"}]}`)
	var me meResponse
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("unmarshal /me: %v", err)
	}
	if me.TokensPerUSD != 2272727 || me.DailyFreeRemainingUSD != 43.93 {
		t.Fatalf("scalars = %+v", me)
	}
	if len(me.Packages) != 1 {
		t.Fatalf("packages = %d", len(me.Packages))
	}
	p := me.Packages[0]
	if derefInt64(p.DailyTokens) != 100000000 {
		t.Fatalf("daily tokens = %d", derefInt64(p.DailyTokens))
	}
	// total_tokens is null here and must degrade to 0, not panic.
	if derefInt64(p.TotalTokens) != 0 {
		t.Fatalf("total tokens = %d", derefInt64(p.TotalTokens))
	}

	// free_claim is a string enum upstream ("first"/"renew"/null); null must
	// decode as empty, not fail the whole response.
	var first meResponse
	if err := json.Unmarshal([]byte(`{"email":"u@example.com","free_claim":"first"}`), &first); err != nil {
		t.Fatalf("unmarshal /me free_claim: %v", err)
	}
	if first.FreeClaim != "first" {
		t.Fatalf("free_claim = %q", first.FreeClaim)
	}
	var none meResponse
	if err := json.Unmarshal([]byte(`{"email":"u@example.com","free_claim":null}`), &none); err != nil {
		t.Fatalf("unmarshal /me with null free_claim: %v", err)
	}
	if none.FreeClaim != "" {
		t.Fatalf("free_claim = %q, want empty", none.FreeClaim)
	}
}

func TestPanelHasNoLocalThemeSwitchAndFlowToolbar(t *testing.T) {
	body := string(renderPanel())
	// The panel must not own a theme setting: it mirrors the CPA console's
	// data-theme attribute instead.
	for _, needle := range []string{`id="theme"`, "u1s1-theme", "applyTheme"} {
		if strings.Contains(body, needle) {
			t.Fatalf("panel still carries a local theme control: %q", needle)
		}
	}
	if !strings.Contains(body, "__u1s1ThemeSync") || !strings.Contains(body, "MutationObserver") {
		t.Fatal("panel must sync data-theme from the embedding console")
	}
	if !strings.Contains(body, `data-theme="dark"`) || !strings.Contains(body, `data-theme="white"`) {
		t.Fatal("panel must define the console's dark and white theme tokens")
	}
	// Toolbar buttons live in normal flow, not pinned to a corner where host
	// chrome can overlap them.
	for _, needle := range []string{"position:fixed", "position:absolute", "position: fixed", "position: absolute"} {
		if strings.Contains(body, needle) {
			t.Fatalf("panel uses out-of-flow positioning (%q), which can be overlapped", needle)
		}
	}
	if !strings.Contains(body, `<div class="bar">`) {
		t.Fatal("expected the in-flow toolbar container")
	}
	// The reload button must come after the heading in document order.
	h1 := strings.Index(body, "<h1>")
	bar := strings.Index(body, `<div class="bar">`)
	if h1 < 0 || bar < 0 || bar < h1 {
		t.Fatalf("toolbar must render below the title (h1=%d bar=%d)", h1, bar)
	}
	// The panel shows quota only; the gateway's operator notice was dropped, so
	// no announcement surface may come back by accident.
	for _, needle := range []string{`id="notice"`, "renderNotice", "announcement"} {
		if strings.Contains(body, needle) {
			t.Fatalf("panel still carries the announcement banner: %q", needle)
		}
	}
	// External links must open in a new tab without leaking the referrer.
	if strings.Count(body, `rel="noopener noreferrer"`) < 1 {
		t.Fatal("external links must carry rel=noopener noreferrer")
	}
	// Token counts are the unit quota packages are denominated in; the panel must
	// convert amounts with the gateway's own rate rather than showing only USD.
	if !strings.Contains(body, "tokens_per_usd") {
		t.Fatal("panel must convert USD amounts to tokens like the CLI does")
	}
	// The panel is a quota readout for the operator, not a storefront. The CLI's
	// usage report ends with top-up and invite calls to action (dist/usage.js
	// usageCtaLines); those belong in the client a paying user runs, not in a CPA
	// admin console. The one dashboard link that stays is the free_claim badge,
	// which exists because claiming genuinely requires a browser session.
	if strings.Contains(body, "usage-topup-card") {
		t.Fatal("panel must not carry the top-up call to action")
	}
}

// A forced refresh often returns identical numbers (quota moves slowly, and the
// gateway lags), so the click has to acknowledge itself in the UI or the button
// reads as dead.
func TestPanelRefreshShowsInFlightFeedback(t *testing.T) {
	body := string(renderPanel())
	if !strings.Contains(body, "刷新中…") {
		t.Fatal("the reload button must show an in-flight label")
	}
	if !strings.Contains(body, `aria-live="polite"`) {
		t.Fatal("the status line must announce updates to assistive tech")
	}
	// Re-entry guard: the disabled button does not cover the key form's Enter
	// handler or the initial load.
	if !strings.Contains(body, "if (loading) return;") {
		t.Fatal("load() must not run concurrently with itself")
	}
}

func TestDecodeStreamBridgeResponseCarriesErrorStatus(t *testing.T) {
	// Bridged 4xx without a stream id: the status must survive in both the
	// returned code and the error text so callers can report a real http_error.
	result, _ := json.Marshal(hostHTTPStreamResponseWire{StatusCode: http.StatusForbidden})
	raw, _ := json.Marshal(envelope{OK: true, Result: result})
	stream, status, _, err := decodeStreamBridgeResponse(raw)
	if stream != nil || status != http.StatusForbidden {
		t.Fatalf("stream=%v status=%d, want no stream and status 403", stream, status)
	}
	if err == nil || !strings.Contains(err.Error(), "upstream 403") {
		t.Fatalf("error = %v, want the upstream status named", err)
	}

	// Success with a stream id decodes as before.
	okResult, _ := json.Marshal(hostHTTPStreamResponseWire{StatusCode: 200, StreamID: "s-1"})
	okRaw, _ := json.Marshal(envelope{OK: true, Result: okResult})
	stream, status, _, err = decodeStreamBridgeResponse(okRaw)
	if err != nil || status != 200 || stream == nil || stream.streamID != "s-1" {
		t.Fatalf("stream=%v status=%d err=%v", stream, status, err)
	}

	// A 2xx reply without a stream id stays a bridge failure, not an upstream one.
	noResult, _ := json.Marshal(hostHTTPStreamResponseWire{StatusCode: 200})
	noRaw, _ := json.Marshal(envelope{OK: true, Result: noResult})
	_, status, _, err = decodeStreamBridgeResponse(noRaw)
	if status != 200 || err == nil || !strings.Contains(err.Error(), "host stream bridge unavailable") {
		t.Fatalf("status=%d err=%v, want the bridge-unavailable error", status, err)
	}
}

func TestCollectStreamSurfacesUpstreamStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"客户端完整性校验未通过","code":"client_integrity_review"}}`))
	}))
	t.Cleanup(srv.Close)

	chunks, status, err := collectStream(srv.URL, map[string]string{}, nil, false, "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
	if len(chunks) != 0 {
		t.Fatalf("chunks = %d, want none on an error response", len(chunks))
	}
	if err == nil || !strings.Contains(err.Error(), "客户端完整性校验未通过") {
		t.Fatalf("error = %v, want the gateway message", err)
	}
}

func TestCachedUsageKeepsSnapshotWhenEnumerationFails(t *testing.T) {
	// Unit tests have no host bridge, so host.auth.list always fails here: the
	// deterministic path the fix targets.
	stale := time.Now().Add(-2 * usageCacheTTL)
	usageCacheMu.Lock()
	prev := usageCache
	usageCache = &usageSnapshot{
		fetchedAt: stale,
		accounts:  []accountUsage{{Name: "u1s1-seed.json", Email: "seed@example.com"}},
	}
	usageCacheMu.Unlock()
	t.Cleanup(func() {
		usageCacheMu.Lock()
		usageCache = prev
		usageCacheMu.Unlock()
	})

	// A failed refresh must serve the previous snapshot untouched.
	accounts, err := cachedUsage("", true)
	if err != nil {
		t.Fatalf("cachedUsage must fall back to the previous snapshot, got error: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Name != "u1s1-seed.json" {
		t.Fatalf("accounts = %+v, want the seeded snapshot preserved", accounts)
	}
	usageCacheMu.Lock()
	fetchedAt := usageCache.fetchedAt
	usageCacheMu.Unlock()
	if !fetchedAt.Equal(stale) {
		t.Fatal("failed refresh must not bump fetched_at")
	}

	// Without any previous snapshot the error must surface (the 502 route)
	// instead of caching a look-alike empty list.
	usageCacheMu.Lock()
	usageCache = nil
	usageCacheMu.Unlock()
	if _, err := cachedUsage("", true); err == nil {
		t.Fatal("expected an error when enumeration fails with no previous snapshot")
	}
	usageCacheMu.Lock()
	poisoned := usageCache != nil
	usageCacheMu.Unlock()
	if poisoned {
		t.Fatal("failed refresh must not poison the cache")
	}

	// The same failure surfaces as a 502 through the management route: that is
	// the contract the panel depends on — never dress "cannot enumerate" up as
	// "no credentials".
	payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
		Method: "GET",
		Path:   "/v0/management/plugins/u1s1/usage",
	}})
	raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
	if err != nil {
		t.Fatalf("management.handle error = %v", err)
	}
	var resp pluginapi.ManagementResponse
	unwrapResult(t, raw, &resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when enumeration fails with no cache", resp.StatusCode)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.Error == "" {
		t.Fatalf("body = %s, want an error message", resp.Body)
	}
}

func TestAuthDataOmitsEmptyOptionalMetadata(t *testing.T) {
	// An explicit empty value in metadata would overwrite the host's stored value
	// on the next model.for_auth/refresh round-trip. The host merges only *missing*
	// keys back in, so empty optional keys (model prefix, email) must be omitted —
	// "absent" is the signal the host uses to backfill its known value.
	sa := testStoredAuth(t)
	cases := []struct {
		name       string
		set        func(string)
		wantAttr   bool
		wantPrefix bool
	}{
		{"prefix", func(v string) { sa.Prefix = v }, false, true},
		{"email", func(v string) { sa.Email = v }, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.set("")
			data, err := authDataFor(sa)
			if err != nil {
				t.Fatalf("authDataFor() error = %v", err)
			}
			if _, exists := data.Metadata[tc.name]; exists {
				t.Fatalf("metadata must omit %q when the credential has none", tc.name)
			}
			if tc.wantAttr {
				if _, exists := data.Attributes[tc.name]; exists {
					t.Fatalf("attributes must omit %q when the credential has none", tc.name)
				}
			}
			if tc.wantPrefix && data.Prefix != "" {
				t.Fatalf("prefix = %q, want empty so the host backfills it", data.Prefix)
			}
			tc.set("u1s1-test")
			data, err = authDataFor(sa)
			if err != nil {
				t.Fatalf("authDataFor() error = %v", err)
			}
			if data.Metadata[tc.name] != "u1s1-test" {
				t.Fatalf("%q not published to metadata: %v", tc.name, data.Metadata[tc.name])
			}
			if tc.wantAttr && data.Attributes[tc.name] != "u1s1-test" {
				t.Fatalf("%q not published to attributes: %v", tc.name, data.Attributes[tc.name])
			}
			if tc.wantPrefix && data.Prefix != "u1s1-test" {
				t.Fatalf("prefix = %q, want it echoed back to the host", data.Prefix)
			}
		})
	}
}
