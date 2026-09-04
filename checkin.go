// checkin.go implements the daily login check-in (每日登录打卡).
//
// The claim endpoint lives on the *website* (u1s1.io), not the gateway:
//
//	POST /api/packages/login-checkin/claim
//	{"cap-token": ..., "cf-turnstile-response": ...}
//
// Both hidden captchas are fail-open: the dashboard submits the claim even when
// the capcat widget or the Turnstile probe returns null (the server records a
// risk event but still processes the claim), so a server-side request carrying
// a valid browser session cookie can complete the check-in without a browser.
// What the plugin cannot do is mint that cookie — it is the browser login
// session, unrelated to the device DPoP credential. The management panel
// therefore asks the user to paste a cookie from a logged-in browser (no
// cookie set = check-in skipped and the panel shows a login prompt).
//
// The cookie is persisted in a sidecar file next to the credential in the host
// auth-dir (<credential-path>.checkin.json), so it survives plugin restarts and
// follows the credential when the auth file is moved or re-imported. It is only
// ever read inside this process; responses and logs carry a redacted preview.
//
// The scheduler is a plain goroutine that wakes at Beijing-time slots (default
// 08:00 and 20:00). On startup it catches up: if the day's first slot has
// already passed and today has not been claimed yet, it claims immediately —
// the server dedupes per day (claimed_today), so a redundant claim is a no-op
// with a clear error, not a double reward.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// defaultCheckinTimes are the Beijing-time slots (08:00 and 20:00).
	defaultCheckinTimes = "08:00,20:00"
	// beijingOffset is China Standard Time: UTC+8 with no DST.
	beijingOffset = 8 * 60 * 60
	// checkinSidecarSuffix marks the cookie/state file next to a credential.
	// Deliberately NOT *.json: the host scans auth-dir for *.json and would
	// otherwise list the sidecar as a second (broken) u1s1 credential.
	checkinSidecarSuffix = ".checkin"
	// legacyCheckinSidecarSuffix is the v0.2.4 suffix that collided with the
	// host credential discovery; loadCheckinSidecar migrates it on first read.
	legacyCheckinSidecarSuffix = ".checkin.json"
)

var beijingLoc = time.FixedZone("Asia/Shanghai", beijingOffset)

// checkinSidecar is the persisted per-credential check-in state. It lives next
// to the credential file (auth-dir) and holds the browser session cookie plus
// the outcome of the last run.
type checkinSidecar struct {
	Cookie    string           `json:"cookie,omitempty"`
	UpdatedAt string           `json:"updated_at,omitempty"`
	LastRun   *checkinRunState `json:"last_run,omitempty"`
}

// checkinRunState records one check-in attempt for the panel.
type checkinRunState struct {
	At      string `json:"at"`
	Status  string `json:"status"` // ok | already | no_cookie | error
	Message string `json:"message,omitempty"`
}

// webLoginCheckin mirrors the login_checkin object on the website /api/me.
type webLoginCheckin struct {
	Tokens              int64  `json:"tokens"`
	ValidDays           int    `json:"valid_days"`
	ClaimedToday        bool   `json:"claimed_today"`
	Today               string `json:"today"`
	Streak              int    `json:"streak"`
	LongestStreak       int    `json:"longest_streak"`
	CycleDays           int    `json:"cycle_days"`
	CycleDay            int    `json:"cycle_day"`
	NextMilestoneDay    int    `json:"next_milestone_day"`
	NextMilestoneTokens int64  `json:"next_milestone_tokens"`
	PhoneRequired       bool   `json:"phone_required"`
}

// webMeResponse is the slice of the website /api/me the check-in needs.
type webMeResponse struct {
	Email        string           `json:"email"`
	LoginCheckin *webLoginCheckin `json:"login_checkin"`
}

// claimResponse is the website claim endpoint's success body; only the
// milestone hint is interesting for the panel.
type claimResponse struct {
	BonusTokens  int64 `json:"bonus_tokens"`
	MilestoneDay int   `json:"milestone_day"`
}

// checkinState carries the in-process check-in scheduler state. The variables
// themselves live in state.go (checkinMu / checkinStarted), the accessors below
// next to their logic.

// checkinEnabled reports whether the scheduler is on.
func checkinEnabled() bool {
	cfg := activeConfig()
	return cfg.CheckinEnabled == nil || *cfg.CheckinEnabled
}

// checkinSlots parses the configured Beijing-time slots ("08:00,20:00") into
// minutes since midnight. Invalid entries are dropped; an empty result falls
// back to the default so a typo cannot silently disable the check-in.
func checkinSlots(spec string) []int {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(spec), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		t, err := time.ParseInLocation("15:04", part, beijingLoc)
		if err != nil {
			continue
		}
		m := t.Hour()*60 + t.Minute()
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return checkinSlots(defaultCheckinTimes)
	}
	return out
}

// beijingNow returns the current time in Beijing (fixed UTC+8).
func beijingNow() time.Time { return time.Now().In(beijingLoc) }

// nextCheckinAfter returns the next Beijing-time slot strictly after now, or
// the first slot tomorrow when all of today's slots have passed.
func nextCheckinAfter(now time.Time, slots []int) time.Time {
	now = now.In(beijingLoc)
	todayMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, beijingLoc)
	nowMin := now.Hour()*60 + now.Minute()
	for _, m := range slots {
		cand := todayMidnight.Add(time.Duration(m) * time.Minute)
		if m > nowMin {
			return cand
		}
	}
	// All slots for today have passed: first slot tomorrow.
	tomorrow := todayMidnight.AddDate(0, 0, 1)
	return tomorrow.Add(time.Duration(slots[0]) * time.Minute)
}

// checkinSidecarPath derives the sidecar path from the credential's physical
// path. host.auth.get reports Path; without it (tests, exotic hosts) the caller
// falls back to a temp-dir name so state still works for the session.
func checkinSidecarPath(credPath string) string {
	if strings.TrimSpace(credPath) == "" {
		return filepath.Join(os.TempDir(), "u1s1-checkin-"+randomHex(8))
	}
	return credPath + checkinSidecarSuffix
}

// loadCheckinSidecar reads the per-credential state; a missing file means no
// cookie configured yet. A file left by v0.2.4 (credPath + ".checkin.json") is
// renamed to the current name on first read so the host stops listing it as a
// credential while the stored cookie survives the upgrade.
func loadCheckinSidecar(path string) (*checkinSidecar, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		legacy := path + ".json"
		if _, errLegacy := os.Stat(legacy); errLegacy == nil {
			if errRename := os.Rename(legacy, path); errRename == nil {
				hostLog("info", "u1s1: migrated legacy check-in sidecar "+filepath.Base(legacy))
			} else {
				// Keep reading the legacy file if rename failed (e.g. cross-device);
				// it still holds the cookie for this session.
				path = legacy
			}
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &checkinSidecar{}, nil
		}
		return nil, err
	}
	var sc checkinSidecar
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil, err
	}
	return &sc, nil
}

// saveCheckinSidecar writes the per-credential state atomically-ish (write +
// rename) so a crash mid-write cannot truncate the cookie.
func saveCheckinSidecar(path string, sc *checkinSidecar) error {
	raw, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cookiePreview masks a cookie for logs/panel: keep the first 8 and last 4
// characters so the operator can tell two accounts apart without exposing the
// session secret.
func cookiePreview(cookie string) string {
	c := strings.TrimSpace(cookie)
	if c == "" {
		return ""
	}
	if len(c) <= 16 {
		return c[:1] + "…" + c[len(c)-1:]
	}
	return c[:8] + "…" + c[len(c)-4:]
}

// webAPIHeaders builds the request headers for website /api/* calls. The
// website authenticates with the session cookie; no DPoP/attestation applies.
func webAPIHeaders(cookie string) map[string]string {
	return map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
		"cookie":       strings.TrimSpace(cookie),
	}
}

// webMe queries the website /api/me with the session cookie. A 401 means the
// cookie is stale (login required); any other non-2xx is an upstream error.
func webMe(origin, cookie, callbackID string) (*webMeResponse, error) {
	resp, err := doRequest("GET", origin+"/api/me", webAPIHeaders(cookie), nil, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("网页会话已失效，请重新登录 u1s1.io 并更新 Cookie")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 web /api/me: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var me webMeResponse
	if err := json.Unmarshal(resp.Body, &me); err != nil {
		return nil, fmt.Errorf("u1s1 web /api/me: decode: %w", err)
	}
	return &me, nil
}

// claimLoginCheckin submits the daily check-in with the session cookie. Both
// captcha tokens are null: the dashboard itself submits null when the hidden
// widgets fail, and the server processes the claim anyway.
func claimLoginCheckin(origin, cookie, callbackID string) (*claimResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"cap-token":             nil,
		"cf-turnstile-response": nil,
	})
	resp, err := doRequest("POST", origin+"/api/packages/login-checkin/claim", webAPIHeaders(cookie), body, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("网页会话已失效，请重新登录 u1s1.io 并更新 Cookie")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 web claim: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var claimed claimResponse
	_ = json.Unmarshal(resp.Body, &claimed)
	return &claimed, nil
}

// runCheckinFor performs one full check-in pass for one credential: read the
// sidecar, skip without a cookie, query /api/me to dedupe, then claim. The
// result is persisted and returned for the panel.
func runCheckinFor(origin, cookie, email, credPath, callbackID string) *checkinRunState {
	sidecarPath := checkinSidecarPath(credPath)
	sc, err := loadCheckinSidecar(sidecarPath)
	if err != nil {
		return &checkinRunState{At: nowRFC3339(), Status: "error", Message: "读取打卡状态失败: " + redactSecrets(err.Error())}
	}
	if strings.TrimSpace(cookie) == "" && strings.TrimSpace(sc.Cookie) == "" {
		return &checkinRunState{At: nowRFC3339(), Status: "no_cookie", Message: "未设置网页 Cookie，请登录 u1s1.io 后更新"}
	}
	if strings.TrimSpace(cookie) != "" {
		sc.Cookie = strings.TrimSpace(cookie)
		sc.UpdatedAt = nowRFC3339()
	}
	if email == "" {
		email = "account"
	}

	// Dedupe: if /api/me says today is already claimed, record it and stop.
	me, errMe := webMe(origin, sc.Cookie, "")
	if errMe != nil {
		state := &checkinRunState{At: nowRFC3339(), Status: "error", Message: redactSecrets(errMe.Error())}
		sc.LastRun = state
		_ = saveCheckinSidecar(sidecarPath, sc)
		return state
	}
	if me.LoginCheckin != nil && me.LoginCheckin.ClaimedToday {
		state := &checkinRunState{At: nowRFC3339(), Status: "already", Message: "今日已打卡"}
		sc.LastRun = state
		_ = saveCheckinSidecar(sidecarPath, sc)
		return state
	}

	claimed, errClaim := claimLoginCheckin(origin, sc.Cookie, "")
	if errClaim != nil {
		state := &checkinRunState{At: nowRFC3339(), Status: "error", Message: redactSecrets(errClaim.Error())}
		sc.LastRun = state
		_ = saveCheckinSidecar(sidecarPath, sc)
		return state
	}
	msg := "打卡成功"
	if claimed.BonusTokens > 0 {
		msg = fmt.Sprintf("打卡成功，解锁连续第 %d 天奖励 %d Token", claimed.MilestoneDay, claimed.BonusTokens)
	}
	state := &checkinRunState{At: nowRFC3339(), Status: "ok", Message: msg}
	sc.LastRun = state
	_ = saveCheckinSidecar(sidecarPath, sc)
	return state
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// startCheckinScheduler launches the background check-in loop exactly once.
// It is called from the plugin register path (dispatch.go) so the loop is alive
// even before the management panel is ever opened. Without a host bridge the
// loop could never read credentials, so it stays dormant in unit tests.
func startCheckinScheduler() {
	checkinMu.Lock()
	defer checkinMu.Unlock()
	if checkinStarted {
		return
	}
	if !hostBridgeAvailable() || !checkinEnabled() {
		return
	}
	checkinStarted = true
	go checkinLoop()
}

// checkinLoop waits until the next Beijing-time slot, then runs a full pass for
// every u1s1 credential, then loops. The startup catch-up is handled by the
// first pass running immediately when the day's first slot has already passed.
func checkinLoop() {
	cfg := activeConfig()
	origin := cfg.webOrigin()
	slots := checkinSlots(cfg.CheckinTimes)
	hostLog("info", "u1s1: check-in scheduler started at "+cfg.CheckinTimes+" (Beijing), web origin "+origin)

	// Catch-up: if we start after today's first slot, claim right away (the
	// server dedupes per day). If we start before it, sleep until the first slot.
	now := beijingNow()
	if now.Hour()*60+now.Minute() < slots[0] {
		time.Sleep(time.Until(nextCheckinAfter(now, slots)))
	}
	runScheduledCheckins(origin)

	for {
		next := nextCheckinAfter(beijingNow(), slots)
		time.Sleep(time.Until(next))
		runScheduledCheckins(origin)
	}
}

// runScheduledCheckins walks every u1s1 credential the host knows about and
// runs the check-in where a cookie exists. The callback ID is empty: this is a
// background pass, not a management request. The enabled check runs here (not
// only at loop start) so a runtime reconfigure that turns the check-in off
// takes effect at the next slot instead of the next plugin load.
func runScheduledCheckins(origin string) {
	if !checkinEnabled() {
		return
	}
	entries, err := hostAuthList()
	if err != nil {
		hostLog("warn", "u1s1: check-in pass aborted, host.auth.list failed: "+redactSecrets(err.Error()))
		return
	}
	for _, entry := range entries {
		sa, resp, errGet := hostAuthGet(entry.AuthIndex)
		if errGet != nil {
			continue
		}
		state := runCheckinFor(origin, "", sa.Email, resp.Path, "")
		// Log the email, not the file name: redactSecrets treats any u1s1-
		// prefix as a credential and would swallow the whole file name.
		hostLog("info", fmt.Sprintf("u1s1: check-in %s (%s): %s", sa.Email, state.Status, state.Message))
	}
}

// ---------------------------------------------------------------------------
// management routes
// ---------------------------------------------------------------------------

type checkinStatusResponse struct {
	Enabled   bool                `json:"enabled"`
	Times     string              `json:"times"`
	WebOrigin string              `json:"web_origin"`
	NextRun   string              `json:"next_run,omitempty"`
	Accounts  []checkinAccountRow `json:"accounts"`
}

type checkinAccountRow struct {
	AuthIndex    string           `json:"auth_index"`
	Name         string           `json:"name"`
	Email        string           `json:"email"`
	CookieSet    bool             `json:"cookie_set"`
	CookieHint   string           `json:"cookie_hint,omitempty"`
	LastRun      *checkinRunState `json:"last_run,omitempty"`
	NeedsLogin   bool             `json:"needs_login"`
	TodayClaimed bool             `json:"today_claimed,omitempty"`
}

// handleCheckinStatus reports per-credential check-in state for the panel. It
// avoids touching the website (no live /api/me call per account): the panel
// shows the persisted last run and cookie presence, which is exactly what a
// status view needs without minting extra requests.
func handleCheckinStatus() (*checkinStatusResponse, error) {
	cfg := activeConfig()
	out := &checkinStatusResponse{
		Enabled:   checkinEnabled(),
		Times:     cfg.CheckinTimes,
		WebOrigin: cfg.webOrigin(),
	}
	if slots := checkinSlots(cfg.CheckinTimes); checkinEnabled() && len(slots) > 0 {
		out.NextRun = nextCheckinAfter(beijingNow(), slots).Format(time.RFC3339)
	}
	entries, err := hostAuthList()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		row := checkinAccountRow{
			AuthIndex:  entry.AuthIndex,
			Name:       entry.Name,
			Email:      entry.Label,
			NeedsLogin: true,
		}
		sa, resp, errGet := hostAuthGet(entry.AuthIndex)
		if errGet == nil {
			if sa.Email != "" {
				row.Email = sa.Email
			}
			sc, errLoad := loadCheckinSidecar(checkinSidecarPath(resp.Path))
			if errLoad == nil {
				if sc.Cookie != "" {
					row.CookieSet = true
					row.CookieHint = cookiePreview(sc.Cookie)
					row.NeedsLogin = false
				}
				row.LastRun = sc.LastRun
			}
		}
		out.Accounts = append(out.Accounts, row)
	}
	return out, nil
}

// handleCheckinSetCookie validates and persists a browser session cookie for
// one credential. Validation is a live /api/me round-trip: a 401 means the
// cookie is stale and we refuse to store it.
func handleCheckinSetCookie(authIndex, cookie, callbackID string) (*checkinAccountRow, error) {
	sa, resp, err := hostAuthGet(authIndex)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cookie) == "" {
		return nil, fmt.Errorf("cookie 不能为空")
	}
	me, errMe := webMe(activeConfig().webOrigin(), cookie, callbackID)
	if errMe != nil {
		return nil, fmt.Errorf("Cookie 验证失败: %s", redactSecrets(errMe.Error()))
	}
	sc, errLoad := loadCheckinSidecar(checkinSidecarPath(resp.Path))
	if errLoad != nil {
		return nil, errLoad
	}
	sc.Cookie = strings.TrimSpace(cookie)
	sc.UpdatedAt = nowRFC3339()
	if err := saveCheckinSidecar(checkinSidecarPath(resp.Path), sc); err != nil {
		return nil, err
	}
	row := checkinAccountRow{
		AuthIndex:  authIndex,
		Name:       resp.Name,
		Email:      sa.Email,
		CookieSet:  true,
		CookieHint: cookiePreview(sc.Cookie),
		LastRun:    sc.LastRun,
	}
	if me.Email != "" {
		row.Email = me.Email
	}
	if me.LoginCheckin != nil {
		row.TodayClaimed = me.LoginCheckin.ClaimedToday
	}
	hostLog("info", "u1s1: check-in cookie updated for "+sa.Email)
	return &row, nil
}

// handleCheckinClearCookie removes the persisted cookie for one credential.
func handleCheckinClearCookie(authIndex string) error {
	sa, resp, err := hostAuthGet(authIndex)
	if err != nil {
		return err
	}
	sc, errLoad := loadCheckinSidecar(checkinSidecarPath(resp.Path))
	if errLoad != nil {
		return errLoad
	}
	sc.Cookie = ""
	if err := saveCheckinSidecar(checkinSidecarPath(resp.Path), sc); err != nil {
		return err
	}
	hostLog("info", "u1s1: check-in cookie cleared for "+sa.Email)
	return nil
}

// handleCheckinRun triggers an immediate check-in for one credential (authIndex
// empty = all credentials) and returns the resulting states.
func handleCheckinRun(authIndex, callbackID string) ([]checkinRunResult, error) {
	entries, err := hostAuthList()
	if err != nil {
		return nil, err
	}
	var out []checkinRunResult
	origin := activeConfig().webOrigin()
	for _, entry := range entries {
		if authIndex != "" && entry.AuthIndex != authIndex {
			continue
		}
		sa, resp, errGet := hostAuthGet(entry.AuthIndex)
		if errGet != nil {
			out = append(out, checkinRunResult{AuthIndex: entry.AuthIndex, Name: entry.Name, Status: "error", Message: redactSecrets(errGet.Error())})
			continue
		}
		state := runCheckinFor(origin, "", sa.Email, resp.Path, callbackID)
		out = append(out, checkinRunResult{AuthIndex: entry.AuthIndex, Name: entry.Name, Email: sa.Email, Status: state.Status, Message: state.Message})
	}
	return out, nil
}

type checkinRunResult struct {
	AuthIndex string `json:"auth_index"`
	Name      string `json:"name"`
	Email     string `json:"email,omitempty"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}
