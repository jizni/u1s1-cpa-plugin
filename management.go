// management.go exposes the plugin's own management routes plus a browser panel
// that shows u1s1 quota (the /v1/me packages view the CLI renders as `u1s1 usage`).
//
// Route boundaries follow the host contract:
//   - /v0/management/plugins/u1s1/*   requires the management key.
//   - /v0/resource/plugins/u1s1/panel serves the unauthenticated HTML shell; the
//     page itself calls the management routes with the stored management key.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type managementRoute struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

type resourceRoute struct {
	Path        string `json:"path"`
	Menu        string `json:"menu,omitempty"`
	Description string `json:"description,omitempty"`
}

type managementRegistrationResponse struct {
	Routes    []managementRoute `json:"routes,omitempty"`
	Resources []resourceRoute   `json:"resources,omitempty"`
}

type managementRequestWire struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// The host injects its own prefixes at management.register; keep the historical
// defaults for older hosts that do not send them (state in state.go).
func setManagementBasePath(p string) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		return
	}
	basePathMu.Lock()
	managementBase = p
	basePathMu.Unlock()
}

func setResourceBasePath(p string) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		return
	}
	basePathMu.Lock()
	resourceBase = p
	basePathMu.Unlock()
}

func loadedManagementBase() string {
	basePathMu.RLock()
	defer basePathMu.RUnlock()
	return managementBase
}

func loadedResourceBase() string {
	basePathMu.RLock()
	defer basePathMu.RUnlock()
	return resourceBase
}

func managementRegistration() managementRegistrationResponse {
	base := "/plugins/" + providerName
	return managementRegistrationResponse{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: base + "/usage", Description: "u1s1 quota for all credentials: daily free allowance, balance, and packages."},
			{Method: http.MethodPost, Path: base + "/refresh", Description: "Drop the cached quota snapshot and re-read /v1/me."},
			{Method: http.MethodGet, Path: base + "/diagnostics", Description: "Recent upstream failures with their gateway request ids, for support reports."},
			{Method: http.MethodGet, Path: base + "/checkin/status", Description: "Per-credential daily login check-in state: cookie presence and last run."},
			{Method: http.MethodPost, Path: base + "/checkin/cookie", Description: "Validate and store a u1s1.io browser session cookie for one credential (body: auth_index + cookie)."},
			{Method: http.MethodDelete, Path: base + "/checkin/cookie", Description: "Remove the stored check-in cookie for one credential (query: auth_index)."},
			{Method: http.MethodPost, Path: base + "/checkin/run", Description: "Trigger an immediate check-in for one credential or all (query: auth_index)."},
		},
		Resources: []resourceRoute{
			{Path: "/panel", Menu: "u1s1", Description: "u1s1 dashboard: free allowance, balance, and quota packages."},
		},
	}
}

// ---------------------------------------------------------------------------
// quota snapshot cache
// ---------------------------------------------------------------------------

// usageCacheTTL keeps the panel's automatic loads from spamming /v1/me. The
// gateway updates package counters with some lag anyway, so a short cache costs
// no accuracy. An explicit refresh ignores the TTL — see freshUsageSnapshot.
const usageCacheTTL = 30 * time.Second

type usageSnapshot struct {
	fetchedAt time.Time
	accounts  []accountUsage
}

type accountUsage struct {
	AuthIndex string `json:"auth_index"`
	Name      string `json:"name"`
	Label     string `json:"label"`
	Email     string `json:"email"`
	Disabled  bool   `json:"disabled"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`

	DailyFreeUSD          float64 `json:"daily_free_usd"`
	DailyFreeUsedUSD      float64 `json:"daily_free_used_usd"`
	DailyFreeRemainingUSD float64 `json:"daily_free_remaining_usd"`
	DailyFreeResetsAt     string  `json:"daily_free_resets_at"`
	DailyFreeModel        string  `json:"daily_free_model"`
	// RemainingUSD is the gateway's USD conversion of the account's remaining
	// package tokens. The dashboard does not show it (its balance metric is
	// bonus_balance_usd), so the panel no longer renders it as a balance; the
	// field stays in the JSON for anyone scripting the route.
	RemainingUSD    float64 `json:"remaining_usd"`
	BonusBalanceUSD float64 `json:"bonus_balance_usd"`
	MTDUSD          float64 `json:"mtd_usd"`
	TokensPerUSD    float64 `json:"tokens_per_usd"`
	// FreeClaim is "first" or "renew" when a free quota package is waiting to be
	// claimed on the website. The claim itself needs a browser session plus two
	// captchas, so the panel can only point the user there.
	FreeClaim string `json:"free_claim,omitempty"`

	Packages []packageUsage `json:"packages"`

	// Aggregates over Packages so the panel does not recompute them.
	TotalRemainingTokens int64 `json:"total_remaining_tokens"`
	TotalUsedToday       int64 `json:"total_used_today"`
}

type packageUsage struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	KindLabel   string `json:"kind_label"`
	Scope       string `json:"scope"`
	ScopeNote   string `json:"scope_note"`
	DailyTokens int64  `json:"daily_tokens"`
	TotalTokens int64  `json:"total_tokens"`
	UsedToday   int64  `json:"used_today"`
	UsedTokens  int64  `json:"used_tokens"`
	Remaining   int64  `json:"remaining"`
	ExpiresAt   string `json:"expires_at"`
	Note        string `json:"note"`

	// Merged-row fields (see groupPackagesForPanel): Count is how many raw
	// packages collapsed into this row; ExpiryDates lists every distinct expiry
	// date across them; HasNeverExpiring reports a member with no expiry.
	Count            int64    `json:"count"`
	ExpiryDates      []string `json:"expiry_dates,omitempty"`
	HasNeverExpiring bool     `json:"has_never_expiring,omitempty"`
}

// groupPackagesForPanel merges same-kind packages into one row, mirroring the
// dashboard's mergePkgs (app.js): the key is kind|scope|daily-ness|note, with
// the note part applied only to admin_grant whose note is user-facing copy
// that must not be lost. login_checkin mints one package per day; unmerged the
// table would grow to dozens of identical rows.
func groupPackagesForPanel(rows []packageUsage) []packageUsage {
	order := make([]*packageUsage, 0, len(rows))
	byKey := make(map[string]*packageUsage, len(rows))
	for i := range rows {
		p := rows[i]
		visibleNote := ""
		if p.Kind == "admin_grant" {
			visibleNote = strings.TrimSpace(p.Note)
		}
		key := p.Kind + "|" + p.Scope + "|" + strconv.FormatBool(p.DailyTokens != 0) + "|" + visibleNote
		g := byKey[key]
		if g == nil {
			cp := p
			cp.Count = 1
			if p.ExpiresAt != "" {
				cp.ExpiryDates = []string{p.ExpiresAt}
			}
			cp.HasNeverExpiring = p.ExpiresAt == ""
			byKey[key] = &cp
			order = append(order, &cp)
			continue
		}
		g.Count++
		g.DailyTokens += p.DailyTokens
		g.TotalTokens += p.TotalTokens
		g.UsedToday += p.UsedToday
		g.UsedTokens += p.UsedTokens
		g.Remaining += p.Remaining
		if p.ExpiresAt != "" {
			g.ExpiryDates = appendDistinct(g.ExpiryDates, p.ExpiresAt)
		} else {
			g.HasNeverExpiring = true
		}
	}
	out := make([]packageUsage, 0, len(order))
	for _, g := range order {
		sort.Strings(g.ExpiryDates)
		out = append(out, *g)
	}
	return out
}

func appendDistinct(list []string, items ...string) []string {
	for _, it := range items {
		found := false
		for _, have := range list {
			if have == it {
				found = true
				break
			}
		}
		if !found {
			list = append(list, it)
		}
	}
	return list
}

// packageLabels mirrors the CLI's PACKAGE_LABELS so the panel shows the same
// Chinese names users see in `u1s1 usage`.
var packageLabels = map[string]string{
	"free_first":          "首月免费包",
	"free_yearly":         "年度免费包",
	"invite":              "邀请赠送",
	"new_user":            "新用户赠送",
	"login_checkin":       "登录打卡",
	"login_checkin_bonus": "打卡加成",
	"payment_delay_gift":  "临时加量包",
	"topup_daily":         "每日加量包",
	"admin_grant":         "官方赠送",
}

func packageLabel(kind string) string {
	if label, ok := packageLabels[kind]; ok {
		return label
	}
	return kind
}

// packageScopeNote explains where a package can be spent, matching the CLI text.
func packageScopeNote(p gatewayPackage) string {
	if p.Kind == "login_checkin" {
		return "仅限 u1s1 客户端使用 · 全模型可用"
	}
	if p.Scope == "free" {
		return "免费包适用模型 · 0 点恢复"
	}
	return "仅限 u1s1 客户端使用 · 免费包适用模型"
}

func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// collectUsage reads /v1/me for every u1s1 credential the host knows about.
// An error means enumeration itself failed (host bridge hiccup); per-credential
// read failures are reported inline via accountUsage.Error instead.
// isTransientCancel reports whether an upstream error is the host cancelling
// the request context (context canceled). It is momentary by nature — the panel
// aborted the fetch it no longer wants, or a connection blip — so callers give
// it exactly one retry instead of surfacing a failure card over a blip.
func isTransientCancel(err error) bool {
	return err != nil && strings.Contains(err.Error(), "context canceled")
}

func collectUsage(callbackID string) ([]accountUsage, error) {
	entries, err := hostAuthList()
	if err != nil {
		return nil, fmt.Errorf("host.auth.list: %w", err)
	}
	out := make([]accountUsage, 0, len(entries))
	for _, entry := range entries {
		item := accountUsage{
			AuthIndex: entry.AuthIndex,
			Name:      entry.Name,
			Label:     entry.Label,
			Disabled:  entry.Disabled,
			Status:    entry.Status,
		}
		sa, _, errGet := hostAuthGet(entry.AuthIndex)
		if errGet != nil {
			item.Error = redactSecrets(errGet.Error())
			out = append(out, item)
			continue
		}
		item.Email = sa.Email
		attestation := attestationFor(entry.AuthIndex, sa, callbackID)
		me, errMe := fetchMe(sa, attestation, callbackID)
		if errMe != nil && isTransientCancel(errMe) {
			// The host tears the upstream down together with the management
			// request's context (a view switch aborts the panel's fetch, a
			// connection hiccup). That is momentary by nature: one retry clears
			// most of these without punishing the panel with a per-account
			// failure card over a blip.
			time.Sleep(500 * time.Millisecond)
			me, errMe = fetchMe(sa, attestation, callbackID)
		}
		if errMe != nil {
			item.Error = redactSecrets(errMe.Error())
			out = append(out, item)
			continue
		}
		if me.Email != "" {
			item.Email = me.Email
		}
		item.DailyFreeUSD = me.DailyFreeUSD
		item.DailyFreeUsedUSD = me.DailyFreeUsedUSD
		item.DailyFreeRemainingUSD = me.DailyFreeRemainingUSD
		item.DailyFreeResetsAt = me.DailyFreeResetsAt
		item.DailyFreeModel = me.DailyFreeModel
		item.RemainingUSD = me.RemainingUSD
		item.BonusBalanceUSD = me.BonusBalanceUSD
		item.MTDUSD = me.MTDUSD
		item.TokensPerUSD = me.TokensPerUSD
		if me.FreeClaim == "first" || me.FreeClaim == "renew" {
			item.FreeClaim = me.FreeClaim
		}
		for _, p := range me.Packages {
			item.Packages = append(item.Packages, packageUsage{
				ID:          p.ID,
				Kind:        p.Kind,
				KindLabel:   packageLabel(p.Kind),
				Scope:       p.Scope,
				ScopeNote:   packageScopeNote(p),
				DailyTokens: derefInt64(p.DailyTokens),
				TotalTokens: derefInt64(p.TotalTokens),
				UsedToday:   p.UsedToday,
				UsedTokens:  p.UsedTokens,
				Remaining:   p.Remaining,
				ExpiresAt:   p.ExpiresAt,
				Note:        p.Note,
			})
			item.TotalRemainingTokens += p.Remaining
			item.TotalUsedToday += p.UsedToday
		}
		// The panel mirrors the dashboard's merged view, not the raw per-day
		// packages (login_checkin mints one per day; unmerged the table grows
		// into dozens of identical rows).
		item.Packages = groupPackagesForPanel(item.Packages)
		out = append(out, item)
	}
	return out, nil
}

func cachedUsage(callbackID string, force bool) ([]accountUsage, error) {
	// requestedAt is the freshness bar for a forced refresh: only a snapshot
	// collected after this instant can satisfy it.
	requestedAt := time.Now()
	if accounts, ok := freshUsageSnapshot(force, requestedAt); ok {
		return accounts, nil
	}

	// Collect outside usageCacheMu: /v1/me is one round-trip per credential, and
	// blocking cache readers (including snapshotTime) for that long turns one slow
	// account into a stalled panel.
	usageCollectMu.Lock()
	defer usageCollectMu.Unlock()

	// A concurrent collection may have finished while we waited for the lock, so
	// re-check before starting another pass. The check must carry force through:
	// asking with force=false here made a forced refresh hand back the very
	// snapshot it was told to replace whenever one existed inside the TTL, which
	// is the panel's normal state (its initial load fills the cache moments
	// before the user reaches the 刷新 button).
	if accounts, ok := freshUsageSnapshot(force, requestedAt); ok {
		return accounts, nil
	}

	accounts, err := collectUsage(callbackID)
	if err != nil {
		// Enumeration hiccup: keep the previous snapshot rather than poisoning
		// the cache with an empty list, which would make every credential
		// vanish (with a fresh-looking timestamp) until the TTL expires.
		hostLog("warn", "u1s1: usage refresh failed, keeping previous snapshot: "+redactSecrets(err.Error()))
		usageCacheMu.Lock()
		defer usageCacheMu.Unlock()
		if usageCache != nil {
			return usageCache.accounts, nil
		}
		return nil, err
	}
	usageCacheMu.Lock()
	usageCache = &usageSnapshot{fetchedAt: time.Now(), accounts: accounts}
	usageCacheMu.Unlock()
	return accounts, nil
}

// freshUsageSnapshot returns the cached accounts when they satisfy the caller.
//
// A plain caller accepts any snapshot inside usageCacheTTL. A forced caller (the
// panel's 刷新 button) accepts only a snapshot collected after requestedAt: one
// produced by a collection that overlapped this call, so concurrent refreshes
// still collapse into a single /v1/me pass instead of N. The TTL says nothing
// about the freshness a forced caller asked for, so it is not consulted there.
func freshUsageSnapshot(force bool, requestedAt time.Time) ([]accountUsage, bool) {
	usageCacheMu.Lock()
	defer usageCacheMu.Unlock()
	if usageCache == nil {
		return nil, false
	}
	if force {
		if usageCache.fetchedAt.After(requestedAt) {
			return usageCache.accounts, true
		}
		return nil, false
	}
	if time.Since(usageCache.fetchedAt) < usageCacheTTL {
		return usageCache.accounts, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// request handling
// ---------------------------------------------------------------------------

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequestWire
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	path := strings.TrimRight(req.Path, "/")

	// Unauthenticated browser resource: serve the panel shell only. It carries no
	// quota data; the page fetches that from the authenticated route below.
	// Exact match only: a loose prefix would also swallow the bare base path,
	// arbitrary subpaths, and sibling resources like .../u1s1-other/panel.
	resPrefix := loadedResourceBase()
	if req.Method == http.MethodGet && path == resPrefix+"/panel" {
		return okEnvelope(htmlResponse(renderPanel()))
	}

	base := loadedManagementBase() + "/plugins/" + providerName
	switch {
	case req.Method == http.MethodGet && path == base+"/usage":
		accounts, errUsage := cachedUsage(req.HostCallbackID, isTruthyQuery(req.Query.Get("refresh")))
		if errUsage != nil {
			// Nothing cached to fall back on: tell the client the enumeration
			// failed instead of answering 200 with a look-alike empty list.
			return okEnvelope(jsonResponse(http.StatusBadGateway, map[string]any{
				"error": redactSecrets(errUsage.Error()),
			}))
		}
		return okEnvelope(jsonResponse(http.StatusOK, map[string]any{
			"accounts":    accounts,
			"fetched_at":  snapshotTime(),
			"cache_ttl_s": int(usageCacheTTL.Seconds()),
		}))

	case req.Method == http.MethodPost && path == base+"/refresh":
		accounts, errUsage := cachedUsage(req.HostCallbackID, true)
		if errUsage != nil {
			return okEnvelope(jsonResponse(http.StatusBadGateway, map[string]any{
				"error": redactSecrets(errUsage.Error()),
			}))
		}
		return okEnvelope(jsonResponse(http.StatusOK, map[string]any{
			"status":     "ok",
			"accounts":   accounts,
			"fetched_at": snapshotTime(),
		}))

	// The gateway mints a request id for every failure and support looks requests
	// up by it. Without this route the id lives only in the error text of the one
	// response that failed, so by the time anyone asks for it, it is gone.
	case req.Method == http.MethodGet && path == base+"/diagnostics":
		return okEnvelope(jsonResponse(http.StatusOK, map[string]any{
			"errors":         recentUpstreamErrors(),
			"max_records":    maxDiagnosticRecords,
			"client_version": activeConfig().ClientVersion,
			"plugin_version": pluginVersion,
		}))

	// --- daily login check-in ------------------------------------------------
	// live=1 additionally reads the website /api/me per account so the panel can
	// state whether today is claimed instead of inferring it from the last run.
	// The quota view's attention badge polls this route without live, so the
	// default stays free of per-account network calls.
	case req.Method == http.MethodGet && path == base+"/checkin/status":
		live := isTruthyQuery(req.Query.Get("live"))
		status, errStatus := handleCheckinStatus(live, req.HostCallbackID)
		if errStatus != nil {
			return okEnvelope(jsonResponse(http.StatusBadGateway, map[string]any{"error": redactSecrets(errStatus.Error())}))
		}
		return okEnvelope(jsonResponse(http.StatusOK, status))

	case req.Method == http.MethodPost && path == base+"/checkin/cookie":
		var in struct {
			AuthIndex string `json:"auth_index"`
			Cookie    string `json:"cookie"`
		}
		_ = json.Unmarshal(req.Body, &in)
		row, errSet := handleCheckinSetCookie(strings.TrimSpace(in.AuthIndex), in.Cookie, req.HostCallbackID)
		if errSet != nil {
			return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": redactSecrets(errSet.Error())}))
		}
		return okEnvelope(jsonResponse(http.StatusOK, row))

	case req.Method == http.MethodDelete && path == base+"/checkin/cookie":
		authIndex := strings.TrimSpace(req.Query.Get("auth_index"))
		if authIndex == "" {
			return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "missing auth_index"}))
		}
		if errClear := handleCheckinClearCookie(authIndex); errClear != nil {
			return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": redactSecrets(errClear.Error())}))
		}
		return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"status": "ok"}))

	case req.Method == http.MethodPost && path == base+"/checkin/run":
		authIndex := strings.TrimSpace(req.Query.Get("auth_index"))
		results, errRun := handleCheckinRun(authIndex, req.HostCallbackID)
		if errRun != nil {
			return okEnvelope(jsonResponse(http.StatusBadGateway, map[string]any{"error": redactSecrets(errRun.Error())}))
		}
		return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"results": results}))

	default:
		return okEnvelope(jsonResponse(http.StatusNotFound, map[string]any{"error": "unknown route: " + path}))
	}
}

func snapshotTime() string {
	usageCacheMu.Lock()
	defer usageCacheMu.Unlock()
	if usageCache == nil {
		return ""
	}
	return usageCache.fetchedAt.UTC().Format(time.RFC3339)
}

func jsonResponse(status int, v any) pluginapi.ManagementResponse {
	body, _ := json.Marshal(v)
	h := http.Header{}
	h.Set("Content-Type", "application/json; charset=utf-8")
	return pluginapi.ManagementResponse{StatusCode: status, Headers: h, Body: body}
}

func htmlResponse(body []byte) pluginapi.ManagementResponse {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: h, Body: body}
}
