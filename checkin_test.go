package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

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

// TestCheckinSlotsSortedOutOfOrderInput pins the P2 fix: a non-ascending config
// must not skip the earliest slot (nextCheckinAfter / catch-up assume slots[0]
// is the day's first run).
func TestCheckinSlotsSortedOutOfOrderInput(t *testing.T) {
	got := checkinSlots("20:00,08:00,12:00")
	want := []int{8 * 60, 12 * 60, 20 * 60}
	if len(got) != len(want) {
		t.Fatalf("sorted slots = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted slots = %v, want %v", got, want)
		}
	}
	// And nextCheckinAfter must now pick 08:00 the morning after a 20:00 config.
	slots := checkinSlots("20:00,08:00")
	if slots[0] != 8*60 {
		t.Fatalf("slots[0] = %d, want the earliest slot after sorting", slots[0])
	}
	at := time.Date(2026, 9, 4, 21, 0, 0, 0, beijingLoc)
	if got := nextCheckinAfter(at, slots); got.Format("15:04") != "08:00" {
		t.Fatalf("nextCheckinAfter(21:00) = %s, want 08:00 tomorrow", got.Format("15:04"))
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

// TestCookiePreviewMasksAndIsRuneSafe pins the preview contract: the secret
// never surfaces (short or long), and a multi-byte value is never sliced
// mid-rune into invalid UTF-8.
func TestCookiePreviewMasksAndIsRuneSafe(t *testing.T) {
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
	long := "u1s1_session=" + strings.Repeat("字", 20) + "abc1234"
	got = cookiePreview(long)
	if !utf8.ValidString(got) {
		t.Fatalf("preview produced invalid UTF-8: %q", got)
	}
	if strings.Contains(got, "abc1234") {
		t.Fatalf("preview leaked the tail: %q", got)
	}
}

// TestNormalizeCookieStripsDevtoolsNoise pins the P3 fix: users paste cookies
// from browser devtools as "Cookie: name=value" or with surrounding quotes;
// both must be stripped before validation so a valid paste does not 401.
func TestNormalizeCookieStripsDevtoolsNoise(t *testing.T) {
	cases := map[string]string{
		"session=abc":              "session=abc",
		"Cookie: session=abc":      "session=abc",
		"cookie: session=abc":      "session=abc",
		"'session=abc'":            "session=abc",
		"\"Cookie: session=abc\"":  "session=abc",
		"  Cookie:  session=abc  ": "session=abc",
		"  ":                       "",
		"Cookie:  ":                "",
	}
	for in, want := range cases {
		if got := normalizeCookie(in); got != want {
			t.Errorf("normalizeCookie(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCorruptSidecarAutoResets pins the P3 fix: a corrupted sidecar must be
// backed up and reset so save/clear keep working, not brick every write.
func TestCorruptSidecarAutoResets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "u1s1-user-example.com.checkin")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := loadCheckinSidecar(path)
	if err != nil {
		t.Fatalf("corrupt sidecar must reset, not error: %v", err)
	}
	if sc.Cookie != "" || sc.LastRun != nil {
		t.Fatalf("reset sidecar must be empty, got %+v", sc)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt backup missing: %v", err)
	}
	// The file is writable again after the reset.
	if err := saveCheckinSidecar(path, &checkinSidecar{Cookie: "session=ok"}); err != nil {
		t.Fatalf("save after reset error = %v", err)
	}
}

// TestUpdateCheckinSidecarSerializes pins the P1 fix: a concurrent clear and a
// scheduler write-back must not resurrect the cleared cookie. The update runs
// under a per-path lock so the last writer wins on each field, not the whole
// object.
func TestUpdateCheckinSidecarSerializes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "u1s1-user-example.com.checkin")
	if err := saveCheckinSidecar(path, &checkinSidecar{Cookie: "session=a", UpdatedAt: nowRFC3339()}); err != nil {
		t.Fatal(err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half the goroutines clear the cookie, half write a LastRun record.
			if i%2 == 0 {
				_ = updateCheckinSidecar(path, func(sc *checkinSidecar) { sc.Cookie = "" })
			} else {
				_ = updateCheckinSidecar(path, func(sc *checkinSidecar) {
					sc.LastRun = &checkinRunState{At: nowRFC3339(), Status: "ok", Message: "打卡成功"}
				})
			}
		}(i)
	}
	wg.Wait()

	sc, err := readCheckinSidecar(path)
	if err != nil {
		t.Fatalf("read error = %v", err)
	}
	// The cookie field must end up cleared: updateCheckinSidecar never
	// whole-object-writes a stale copy, so a clear can only lose to another
	// explicit cookie write, never to a LastRun update.
	if sc.Cookie != "" {
		t.Fatalf("cookie resurrected after concurrent clear: %q", sc.Cookie)
	}
	if sc.LastRun == nil {
		t.Fatal("LastRun should have been recorded")
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
	state := runCheckinFor(srv.URL, "user@example.com", credPath, "")
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

	state := runCheckinFor(srv.URL, "", credPath, "")
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
	state := runCheckinFor(srv.URL, "", credPath, "")
	if state.Status != "no_cookie" {
		t.Fatalf("status = %s (%s), want no_cookie", state.Status, state.Message)
	}
}

func TestRunCheckinForStaleCookieRejected(t *testing.T) {
	// No cookie in the handler => /api/me 401 => the run records the dedicated
	// auth_expired status (the panel renders it as 会话已失效) rather than the
	// generic error.
	handler := &checkinWebHandler{}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	dir := t.TempDir()
	credPath := filepath.Join(dir, "u1s1-user-example.com.json")
	_ = saveCheckinSidecar(checkinSidecarPath(credPath), &checkinSidecar{Cookie: "session=stale"})
	state := runCheckinFor(srv.URL, "", credPath, "")
	if state.Status != "auth_expired" || !strings.Contains(state.Message, "重新登录") {
		t.Fatalf("status = %s (%s), want auth_expired login error", state.Status, state.Message)
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

// TestIsTruthyQueryAcceptsHandTypedFlags pins the management query-flag parsing.
// The panel always sends "1", but these routes are also driven by hand with
// curl, where "true" is the natural thing to type; a strict == "1" made a
// mistyped flag silently mean "off".
func TestIsTruthyQueryAcceptsHandTypedFlags(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on", " 1 "} {
		if !isTruthyQuery(v) {
			t.Fatalf("isTruthyQuery(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "banana"} {
		if isTruthyQuery(v) {
			t.Fatalf("isTruthyQuery(%q) = true, want false", v)
		}
	}
}

// TestApplyLiveCheckinCopiesWebsiteFields verifies the panel row carries the
// whole login_checkin object. Before this the plugin decoded streak, cycle, and
// milestone fields and then dropped everything except claimed_today, so the
// panel could not answer "am I on a streak" without the user opening the site.
func TestApplyLiveCheckinCopiesWebsiteFields(t *testing.T) {
	var row checkinAccountRow
	row.applyLiveCheckin(&webLoginCheckin{
		Tokens:              2000000,
		ValidDays:           30,
		ClaimedToday:        true,
		Streak:              7,
		LongestStreak:       12,
		CycleDays:           30,
		CycleDay:            7,
		NextMilestoneDay:    14,
		NextMilestoneTokens: 5000000,
		PhoneRequired:       true,
	})
	if !row.TodayClaimed || row.Streak != 7 || row.LongestStreak != 12 {
		t.Fatalf("streak fields not copied: %+v", row)
	}
	if row.CycleDay != 7 || row.CycleDays != 30 {
		t.Fatalf("cycle fields not copied: %+v", row)
	}
	if row.NextMilestoneDay != 14 || row.NextMilestoneTokens != 5000000 {
		t.Fatalf("milestone fields not copied: %+v", row)
	}
	if row.TodayTokens != 2000000 || row.ValidDays != 30 || !row.PhoneRequired {
		t.Fatalf("reward/phone fields not copied: %+v", row)
	}
	// A nil login_checkin (older site payload) must leave the row untouched
	// rather than zeroing fields a caller already set.
	row.applyLiveCheckin(nil)
	if row.Streak != 7 {
		t.Fatalf("nil login_checkin clobbered the row: %+v", row)
	}
}

// TestCheckinStatusLocalReadMakesNoWebRequest pins the default status route as
// network-free. The quota view polls this route for its attention badge, so a
// per-account /api/me here would turn a background hint into a standing cost.
func TestCheckinStatusLocalReadMakesNoWebRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	setWebOrigin(t, srv.URL)

	// No host bridge in unit tests, so enumeration fails; what matters is that
	// the non-live path reached that failure without touching the website.
	if _, err := handleCheckinStatus(false, ""); err == nil {
		t.Fatal("expected host.auth.list to fail without a bridge")
	}
	if hits != 0 {
		t.Fatalf("non-live status made %d web request(s), want 0", hits)
	}
}

// TestFillCheckinRowNonLiveMakesNoWebRequest pins the same zero-network rule at
// the row level: live is the only thing that may touch the website.
func TestFillCheckinRowNonLiveMakesNoWebRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	var row checkinAccountRow
	row.NeedsLogin = true
	fillCheckinRow(&row, &checkinSidecar{Cookie: "session=good"}, false, srv.URL, "")
	if hits != 0 {
		t.Fatalf("non-live fill made %d web request(s), want 0", hits)
	}
	if !row.CookieSet || row.NeedsLogin {
		t.Fatalf("cookie presence must still be reported: %+v", row)
	}
}

// TestFillCheckinRowLive401FlipsNeedsLogin pins the review finding: a live read
// hitting an expired session must surface in the panel's attention badge
// (needs_login) — exactly the case that must not wait for the user to open the
// check-in view to look for it.
func TestFillCheckinRowLive401FlipsNeedsLogin(t *testing.T) {
	srv := httptest.NewServer(&checkinWebHandler{})
	defer srv.Close()
	var row checkinAccountRow
	row.NeedsLogin = true
	fillCheckinRow(&row, &checkinSidecar{Cookie: "session=stale"}, true, srv.URL, "")
	if !row.NeedsLogin {
		t.Fatal("live 401 must flip needs_login so the attention badge fires")
	}
	if !row.CookieSet {
		t.Fatal("cookie presence is unaffected by the session being stale")
	}
	if row.LiveError == "" || !strings.Contains(row.LiveError, "重新登录") {
		t.Fatalf("live_error = %q, want the session-expired hint", row.LiveError)
	}
}

// TestFillCheckinRowLiveSuccessCopiesMeFields verifies a healthy live read
// replaces the local-only row with the website's authoritative state.
func TestFillCheckinRowLiveSuccessCopiesMeFields(t *testing.T) {
	srv := httptest.NewServer(&checkinWebHandler{claimedToday: true, meEmail: "live@example.com"})
	defer srv.Close()
	var row checkinAccountRow
	row.NeedsLogin = true
	fillCheckinRow(&row, &checkinSidecar{Cookie: "session=good"}, true, srv.URL, "")
	if row.NeedsLogin {
		t.Fatal("valid session must clear needs_login")
	}
	if row.Email != "live@example.com" {
		t.Fatalf("email = %q, want the /api/me email", row.Email)
	}
	if !row.TodayClaimed || row.Streak != 3 || row.TodayTokens != 2000000 {
		t.Fatalf("live checkin fields not applied: %+v", row)
	}
	if row.LiveError != "" {
		t.Fatalf("live_error = %q on a successful read", row.LiveError)
	}
}

// TestFillCheckinRowLiveUpstreamErrorKeepsSession separates an upstream failure
// from an expired session: a 500 must keep needs_login false (the cookie is
// still configured) while live_error explains why the row shows local data.
func TestFillCheckinRowLiveUpstreamErrorKeepsSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	var row checkinAccountRow
	row.NeedsLogin = true
	fillCheckinRow(&row, &checkinSidecar{Cookie: "session=good"}, true, srv.URL, "")
	if row.NeedsLogin {
		t.Fatal("upstream 500 must not be treated as an expired session")
	}
	if row.LiveError == "" {
		t.Fatal("live_error must carry the upstream failure")
	}
}
