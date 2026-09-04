package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// setWebOrigin points the plugin web-origin at a test server for one test.
func setWebOrigin(t *testing.T, origin string) {
	t.Helper()
	cfgMu.Lock()
	pluginCfg.WebOrigin = strings.TrimSuffix(origin, "/")
	cfgMu.Unlock()
	t.Cleanup(func() {
		cfgMu.Lock()
		pluginCfg = defaultPluginConfig()
		cfgMu.Unlock()
	})
}

func TestCheckinSlotsParsesDefaultAndDropsInvalid(t *testing.T) {
	if got := checkinSlots("08:00,20:00"); len(got) != 2 || got[0] != 8*60 || got[1] != 20*60 {
		t.Fatalf("default slots = %v", got)
	}
	// Invalid entries dropped; a fully invalid spec falls back to the default.
	if got := checkinSlots("08:00,junk,25:99"); len(got) != 1 || got[0] != 8*60 {
		t.Fatalf("mixed slots = %v", got)
	}
	if got := checkinSlots("junk"); len(got) != 2 {
		t.Fatalf("all-invalid spec must fall back to default, got %v", got)
	}
	// Dedupe.
	if got := checkinSlots("08:00,08:00"); len(got) != 1 {
		t.Fatalf("duplicate slots not deduped: %v", got)
	}
}

func TestNextCheckinAfterBeijingSlots(t *testing.T) {
	slots := []int{8 * 60, 20 * 60}
	day := func(h, m int) time.Time {
		return time.Date(2026, 9, 4, h, m, 0, 0, beijingLoc)
	}
	cases := []struct {
		now  time.Time
		want string // RFC3339 in Beijing
	}{
		{day(0, 0), "2026-09-04T08:00:00+08:00"},
		{day(8, 0), "2026-09-04T20:00:00+08:00"}, // strictly after: 08:00 itself -> 20:00
		{day(12, 30), "2026-09-04T20:00:00+08:00"},
		{day(20, 0), "2026-09-05T08:00:00+08:00"},
		{day(23, 59), "2026-09-05T08:00:00+08:00"},
	}
	for _, c := range cases {
		got := nextCheckinAfter(c.now, slots)
		if got.Format(time.RFC3339) != c.want {
			t.Errorf("nextCheckinAfter(%s) = %s, want %s", c.now.Format(time.RFC3339), got.Format(time.RFC3339), c.want)
		}
	}
}

func TestCookiePreviewMasksSecret(t *testing.T) {
	if got := cookiePreview(""); got != "" {
		t.Fatalf("empty preview = %q", got)
	}
	if got := cookiePreview("abc"); got != "a…c" {
		t.Fatalf("short preview = %q", got)
	}
	got := cookiePreview("session=0123456789abcdefsecretvalue")
	if strings.Contains(got, "0123456789abcdefsecretvalue") || !strings.HasPrefix(got, "session=") {
		t.Fatalf("preview leaked the secret: %q", got)
	}
}

// TestCheckinSidecarRoundTrip verifies the cookie survives a write/read cycle
// and the file is not world-readable.
func TestCheckinSidecarRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "u1s1-user-example.com.json")
	sc := &checkinSidecar{Cookie: "session=secret", UpdatedAt: nowRFC3339()}
	if err := saveCheckinSidecar(checkinSidecarPath(path), sc); err != nil {
		t.Fatalf("save error = %v", err)
	}
	scPath := checkinSidecarPath(path)
	if !strings.HasSuffix(scPath, checkinSidecarSuffix) || strings.HasSuffix(scPath, ".json") {
		t.Fatalf("sidecar path %q must end in %q and not in .json", scPath, checkinSidecarSuffix)
	}
	info, err := os.Stat(scPath)
	if err != nil {
		t.Fatalf("stat error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar mode = %v, want 0600", info.Mode().Perm())
	}
	loaded, err := loadCheckinSidecar(scPath)
	if err != nil {
		t.Fatalf("load error = %v", err)
	}
	if loaded.Cookie != "session=secret" {
		t.Fatalf("cookie = %q", loaded.Cookie)
	}
	// Missing file => empty state, no error.
	missing, err := loadCheckinSidecar(filepath.Join(dir, "nope.json"))
	if err != nil || missing.Cookie != "" {
		t.Fatalf("missing sidecar = %+v, err %v", missing, err)
	}
}

// TestCheckinSidecarMigratesLegacyJSON ensures a v0.2.4 sidecar (name ended in
// .checkin.json and was picked up by the host as a credential) is renamed on
// first read so the stored cookie survives and the file stops colliding.
func TestCheckinSidecarMigratesLegacyJSON(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "u1s1-user-example.com.json")
	legacy := credPath + ".checkin.json"
	if err := saveCheckinSidecar(legacy, &checkinSidecar{Cookie: "session=legacy"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCheckinSidecar(checkinSidecarPath(credPath))
	if err != nil {
		t.Fatalf("load error = %v", err)
	}
	if loaded.Cookie != "session=legacy" {
		t.Fatalf("cookie = %q, want the legacy value migrated", loaded.Cookie)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy sidecar %q still exists after migration", legacy)
	}
	if _, err := os.Stat(checkinSidecarPath(credPath)); err != nil {
		t.Fatalf("migrated sidecar missing: %v", err)
	}
}

// TestIsU1S1AuthNameRejectsCheckinSidecar pins the root-cause fix: the host
// scans auth-dir for *.json and the legacy sidecar name looked like a
// credential; both the legacy and current names must be excluded.
func TestIsU1S1AuthNameRejectsCheckinSidecar(t *testing.T) {
	if isU1S1AuthName("u1s1-jizni-qq.com.json.checkin.json") {
		t.Fatal("legacy sidecar name must not be treated as a u1s1 credential")
	}
	if isU1S1AuthName("u1s1-jizni-qq.com.json.checkin") {
		t.Fatal("current sidecar name must not be treated as a u1s1 credential")
	}
	if !isU1S1AuthName("u1s1-jizni-qq.com.json") {
		t.Fatal("real credential name must still be recognized")
	}
}

// checkinWebHandler fakes the website /api routes: /api/me reports claimed_today
// and /api/packages/login-checkin/claim records the request and returns success.
type checkinWebHandler struct {
	claimedToday bool
	cookieSeen   string
	claimBody    string
	meEmail      string
}

func (h *checkinWebHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.cookieSeen = r.Header.Get("cookie")
	switch r.URL.Path {
	case "/api/me":
		// Only a cookie the test explicitly set as good authenticates; anything
		// else (empty or stale) is a 401, mirroring the real site.
		if h.cookieSeen != "session=good" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"not logged in"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{"email": h.meEmail, "login_checkin": map[string]any{
			"claimed_today": h.claimedToday,
			"streak":        3,
			"tokens":        2000000,
			"today":         "2026-09-04",
		}}
		_ = json.NewEncoder(w).Encode(body)
	case "/api/packages/login-checkin/claim":
		raw, _ := io.ReadAll(r.Body)
		h.claimBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"bonus_tokens":0}`))
	default:
		http.NotFound(w, r)
	}
}

func TestRunCheckinForFullFlow(t *testing.T) {
	handler := &checkinWebHandler{meEmail: "user@example.com"}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	dir := t.TempDir()
	credPath := filepath.Join(dir, "u1s1-user-example.com.json")
	// Persist a cookie first so the scheduled path (empty cookie arg) picks it up.
	if err := saveCheckinSidecar(checkinSidecarPath(credPath), &checkinSidecar{Cookie: "session=good", UpdatedAt: nowRFC3339()}); err != nil {
		t.Fatal(err)
	}

	// Claim succeeds when /api/me reports not claimed.
	state := runCheckinFor(srv.URL, "", "user@example.com", credPath, "")
	if state.Status != "ok" {
		t.Fatalf("status = %s (%s)", state.Status, state.Message)
	}
	if handler.cookieSeen != "session=good" {
		t.Fatalf("cookie sent = %q", handler.cookieSeen)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(handler.claimBody), &body); err != nil {
		t.Fatalf("claim body = %q: %v", handler.claimBody, err)
	}
	// Both captcha tokens must be explicitly null (fail-open, matching the site).
	if v, ok := body["cap-token"]; !ok || v != nil {
		t.Fatalf("cap-token = %v, want null", v)
	}
	if v, ok := body["cf-turnstile-response"]; !ok || v != nil {
		t.Fatalf("cf-turnstile-response = %v, want null", v)
	}

	// The persisted sidecar records the successful run.
	sc, _ := loadCheckinSidecar(checkinSidecarPath(credPath))
	if sc.LastRun == nil || sc.LastRun.Status != "ok" {
		t.Fatalf("last run not persisted: %+v", sc.LastRun)
	}
}

func TestRunCheckinForDedupesClaimedToday(t *testing.T) {
	handler := &checkinWebHandler{claimedToday: true}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	dir := t.TempDir()
	credPath := filepath.Join(dir, "u1s1-user-example.com.json")
	_ = saveCheckinSidecar(checkinSidecarPath(credPath), &checkinSidecar{Cookie: "session=good"})

	state := runCheckinFor(srv.URL, "", "", credPath, "")
	if state.Status != "already" {
		t.Fatalf("status = %s (%s), want already", state.Status, state.Message)
	}
	if handler.claimBody != "" {
		t.Fatal("claim must not be submitted when today is already claimed")
	}
}

func TestRunCheckinForNoCookie(t *testing.T) {
	srv := httptest.NewServer(&checkinWebHandler{})
	defer srv.Close()
	dir := t.TempDir()
	credPath := filepath.Join(dir, "u1s1-user-example.com.json")
	state := runCheckinFor(srv.URL, "", "", credPath, "")
	if state.Status != "no_cookie" {
		t.Fatalf("status = %s (%s), want no_cookie", state.Status, state.Message)
	}
}

func TestRunCheckinForStaleCookieRejected(t *testing.T) {
	// No cookie in the handler => /api/me 401 => the run reports a login error.
	handler := &checkinWebHandler{}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	dir := t.TempDir()
	credPath := filepath.Join(dir, "u1s1-user-example.com.json")
	_ = saveCheckinSidecar(checkinSidecarPath(credPath), &checkinSidecar{Cookie: "session=stale"})
	state := runCheckinFor(srv.URL, "", "", credPath, "")
	if state.Status != "error" || !strings.Contains(state.Message, "重新登录") {
		t.Fatalf("status = %s (%s), want login error", state.Status, state.Message)
	}
}

func TestCheckinEnabledDefaultAndToggle(t *testing.T) {
	cfg := defaultPluginConfig()
	if cfg.CheckinEnabled == nil || !*cfg.CheckinEnabled {
		t.Fatal("check-in must default to enabled")
	}
	if !checkinEnabled() {
		t.Fatal("checkinEnabled() = false with the default config")
	}
	cfgMu.Lock()
	pluginCfg.CheckinEnabled = boolPtr(false)
	cfgMu.Unlock()
	if checkinEnabled() {
		t.Fatal("checkinEnabled() = true after explicit disable")
	}
	cfgMu.Lock()
	pluginCfg = defaultPluginConfig()
	cfgMu.Unlock()
}

func TestCheckinRoutesRegistered(t *testing.T) {
	raw, err := handleMethod(pluginabi.MethodManagementRegister, []byte(`{"base_path":"/v0/management","resource_base_path":"/v0/resource/plugins/u1s1"}`))
	if err != nil {
		t.Fatalf("management.register error = %v", err)
	}
	var reg managementRegistrationResponse
	unwrapResult(t, raw, &reg)
	found := map[string]bool{}
	for _, r := range reg.Routes {
		found[r.Path] = true
	}
	for _, want := range []string{
		"/plugins/u1s1/checkin/status",
		"/plugins/u1s1/checkin/cookie",
		"/plugins/u1s1/checkin/run",
	} {
		if !found[want] {
			t.Errorf("route %q not registered", want)
		}
	}
}

// TestCheckinStatusEndpointRejectsMissingKey exercises the management route's
// envelope without a host bridge: enumeration fails cleanly (502), not a hang
// or a panic.
func TestCheckinStatusEndpointWithoutHostBridge(t *testing.T) {
	payload, _ := json.Marshal(managementRequestWire{ManagementRequest: pluginapi.ManagementRequest{
		Method: "GET",
		Path:   "/v0/management/plugins/u1s1/checkin/status",
	}})
	raw, err := handleMethod(pluginabi.MethodManagementHandle, payload)
	if err != nil {
		t.Fatalf("management.handle error = %v", err)
	}
	var resp pluginapi.ManagementResponse
	unwrapResult(t, raw, &resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (no host bridge)", resp.StatusCode)
	}
}
