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

func TestIdentifiers(t *testing.T) {
	for _, method := range []string{pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier} {
		raw, err := handleMethod(method, nil)
		if err != nil {
			t.Fatalf("%s error = %v", method, err)
		}
		var resp identifierResponse
		unwrapResult(t, raw, &resp)
		if resp.Identifier != providerName {
			t.Fatalf("%s identifier = %q", method, resp.Identifier)
		}
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

func TestAuthIdentityAndFileName(t *testing.T) {
	sa := testStoredAuth(t)
	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if data.ID != "u1s1-user-example.com" {
		t.Fatalf("id = %q", data.ID)
	}
	if data.FileName != "u1s1-user-example.com.json" {
		t.Fatalf("file name = %q", data.FileName)
	}
	// No email: fall back to a device suffix without exposing the token.
	sa.Email = ""
	data, err = authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if !strings.HasPrefix(data.ID, "u1s1-device-") {
		t.Fatalf("id = %q, want a u1s1-device- fallback", data.ID)
	}
	if strings.Contains(data.ID, sa.DeviceToken) {
		t.Fatal("identity must not embed the full device token")
	}
	// StorageJSON must round-trip into a usable credential.
	if _, err := parseStored(data.StorageJSON); err != nil {
		t.Fatalf("parseStored(StorageJSON) error = %v", err)
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
	body := []byte(`{"error":{"message":"客户端完整性校验未通过","type":"forbidden","code":"client_integrity_review"}}`)
	if got := gatewayMessage(body, 403); got != "客户端完整性校验未通过" {
		t.Fatalf("gatewayMessage = %q", got)
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
	})
	if info.ID != "deepseek-v4-flash" || info.DisplayName != "DeepSeek V4 Flash" {
		t.Fatalf("info = %+v", info)
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

func TestMeResponseParsesPackages(t *testing.T) {
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
	// The reload/logout buttons must come after the heading in document order.
	h1 := strings.Index(body, "<h1>")
	bar := strings.Index(body, `<div class="bar">`)
	if h1 < 0 || bar < 0 || bar < h1 {
		t.Fatalf("toolbar must render below the title (h1=%d bar=%d)", h1, bar)
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
}

func TestManagementUsageSurfacesEnumerationFailure(t *testing.T) {
	usageCacheMu.Lock()
	prev := usageCache
	usageCache = nil
	usageCacheMu.Unlock()
	t.Cleanup(func() {
		usageCacheMu.Lock()
		usageCache = prev
		usageCacheMu.Unlock()
	})

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

func TestAuthDataOmitsEmptyPrefixMetadata(t *testing.T) {
	// An explicit "prefix":"" in metadata overwrites the host's stored prefix on
	// the next model.for_auth/refresh round-trip, silently dropping u1s1/*.
	sa := testStoredAuth(t)
	sa.Prefix = ""
	data, err := authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if _, exists := data.Metadata["prefix"]; exists {
		t.Fatal("metadata must omit prefix when the credential has none")
	}
	if data.Prefix != "" {
		t.Fatalf("prefix = %q, want empty so the host backfills it", data.Prefix)
	}
	// With a prefix set, both the field and the metadata key must be present.
	sa.Prefix = "u1s1"
	data, err = authDataFor(sa)
	if err != nil {
		t.Fatalf("authDataFor() error = %v", err)
	}
	if data.Prefix != "u1s1" || data.Metadata["prefix"] != "u1s1" {
		t.Fatalf("prefix not published: field=%q meta=%v", data.Prefix, data.Metadata["prefix"])
	}
}
