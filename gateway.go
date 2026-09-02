// gateway.go builds signed u1s1 requests and wraps the gateway endpoints the
// plugin needs: device login (start/poll), /v1/me, /v1/models (which also hands
// out the client_attestation token), and the chat completions call.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// storedAuth is the on-disk credential shape written to the host auth-dir as
// u1s1-<email>.json. Field names match ~/.u1s1/config.json so an existing CLI
// install can be imported verbatim.
type storedAuth struct {
	Type             string `json:"type"`
	BaseURL          string `json:"baseUrl,omitempty"`
	APIKey           string `json:"apiKey,omitempty"`
	DeviceToken      string `json:"deviceToken"`
	DeviceID         int64  `json:"deviceId,omitempty"`
	DevicePrivateJwk jwk    `json:"devicePrivateJwk"`
	DevicePublicJwk  jwk    `json:"devicePublicJwk"`
	Email            string `json:"email,omitempty"`
	// Prefix is the optional model prefix for this credential. The host writes it
	// into this file via PATCH /auth-files/fields, and plugin-parsed credentials
	// only get a prefix if the plugin echoes it back in AuthData.
	Prefix string `json:"prefix,omitempty"`
	// Attestation is the cached client_attestation token plus its expiry so a
	// restart does not need a models round-trip before the first chat request.
	Attestation          string `json:"attestation,omitempty"`
	AttestationExpiresAt int64  `json:"attestationExpiresAt,omitempty"`
	CreatedAt            string `json:"createdAt,omitempty"`
	// Extra preserves every credential-file key this struct does not model.
	// auth.refresh and model.for_auth decode the file and re-encode it, so
	// without this the round-trip would drop host- and user-owned fields:
	// priority, note, proxy_url, weight, excluded_models, headers, disabled,
	// request_retry, model_aliases, ...
	Extra map[string]json.RawMessage `json:"-"`
}

// storedAuthAlias breaks the Marshal/Unmarshal recursion below.
type storedAuthAlias storedAuth

// storedAuthKnownKeys is derived from the struct tags so it cannot drift when a
// field is added or renamed.
var storedAuthKnownKeys = func() map[string]struct{} {
	out := make(map[string]struct{})
	t := reflect.TypeOf(storedAuthAlias{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		if idx := strings.Index(tag, ","); idx >= 0 {
			tag = tag[:idx]
		}
		if tag != "" {
			out[tag] = struct{}{}
		}
	}
	return out
}()

func (s *storedAuth) UnmarshalJSON(raw []byte) error {
	var alias storedAuthAlias
	if err := json.Unmarshal(raw, &alias); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return err
	}
	for key := range storedAuthKnownKeys {
		delete(all, key)
	}
	*s = storedAuth(alias)
	if len(all) > 0 {
		s.Extra = all
	}
	return nil
}

func (s storedAuth) MarshalJSON() ([]byte, error) {
	known, err := json.Marshal(storedAuthAlias(s))
	if err != nil {
		return nil, err
	}
	if len(s.Extra) == 0 {
		return known, nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(known, &out); err != nil {
		return nil, err
	}
	for key, value := range s.Extra {
		// Modelled fields always win; Extra only carries unmodelled keys.
		if _, owned := storedAuthKnownKeys[key]; owned {
			continue
		}
		if _, exists := out[key]; exists {
			continue
		}
		out[key] = value
	}
	return json.Marshal(out)
}

func (s storedAuth) hasDeviceCredential() bool {
	return strings.HasPrefix(s.DeviceToken, "u1s1d-") &&
		s.DevicePrivateJwk.Kty == "EC" && s.DevicePrivateJwk.Crv == "P-256" && s.DevicePrivateJwk.D != "" &&
		s.DevicePublicJwk.Kty == "EC" && s.DevicePublicJwk.Crv == "P-256"
}

func (s storedAuth) baseURL() string {
	if strings.TrimSpace(s.BaseURL) != "" {
		return strings.TrimSuffix(strings.TrimSpace(s.BaseURL), "/")
	}
	return activeConfig().BaseURL
}

func parseStored(raw []byte) (storedAuth, error) {
	var sa storedAuth
	if len(raw) == 0 {
		return sa, fmt.Errorf("u1s1: empty auth storage")
	}
	if err := json.Unmarshal(raw, &sa); err != nil {
		return sa, fmt.Errorf("u1s1: decode auth storage: %w", err)
	}
	if !sa.hasDeviceCredential() {
		return sa, fmt.Errorf("u1s1: auth storage has no usable device credential")
	}
	return sa, nil
}

// ---------------------------------------------------------------------------
// request headers
// ---------------------------------------------------------------------------

// clientHeaders reproduces the fingerprint the gateway expects from a genuine
// u1s1 client. The gateway rejects requests that only carry a valid DPoP proof
// with 403 client_integrity_review, so these headers are mandatory, not cosmetic.
func clientHeaders(cfg pluginConfig) map[string]string {
	return map[string]string{
		"accept":                      "application/json",
		"content-type":                "application/json",
		"user-agent":                  cfg.UserAgent,
		"x-u1s1-client":               cfg.Client,
		"x-u1s1-version":              cfg.ClientVersion,
		"x-u1s1-platform":             "linux-x64",
		"x-stainless-arch":            "x64",
		"x-stainless-lang":            "js",
		"x-stainless-os":              "Linux",
		"x-stainless-package-version": stainlessPackageVersion,
		"x-stainless-retry-count":     "0",
		"x-stainless-runtime":         "node",
		"x-stainless-runtime-version": stainlessRuntimeVersion,
		"x-stainless-timeout":         "300",
	}
}

// signedHeaders returns the full header set for one authenticated request:
// client fingerprint + fresh DPoP proof + cached attestation token.
func signedHeaders(sa storedAuth, method, url string, attestation string) (map[string]string, error) {
	cfg := activeConfig()
	headers := clientHeaders(cfg)
	proof, err := dpopHeaders(sa.DeviceToken, sa.DevicePrivateJwk, sa.DevicePublicJwk, method, url)
	if err != nil {
		return nil, err
	}
	for k, v := range proof {
		headers[k] = v
	}
	if strings.TrimSpace(attestation) != "" {
		headers["x-u1s1-attestation"] = attestation
	}
	return headers, nil
}

// ---------------------------------------------------------------------------
// attestation cache
// ---------------------------------------------------------------------------

// The gateway hands out a client_attestation token with /v1/models. It lives 7
// days; refresh a day early, and back off after a failure so a flaky gateway is
// not hammered per request.
const (
	attestationRefreshMargin = 24 * time.Hour
	attestationFailCooldown  = 30 * time.Second
	// Bounds how long a token with unknown lifetime may be reused. It must stay
	// above attestationRefreshMargin: with a missing expires_in the entry is
	// refreshed once a day (48h TTL minus 24h margin) instead of either never
	// (zero expiry reads as fresh) or on every request (reads as stale).
	attestationUnknownTTL = 48 * time.Hour
)

// attestationFreshUntil derives the cache expiry for a fetched token. A missing
// expires_in must not yield a zero expiry: attestationFor treats zero as stale
// and would then re-fetch on every single request.
func attestationFreshUntil(expiresIn int64) time.Time {
	if expiresIn > 0 {
		return time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	return time.Now().Add(attestationUnknownTTL)
}

type attestationEntry struct {
	token       string
	expiresAt   time.Time
	lastFailure time.Time
	// mu guards the fields above. It is never held across a gateway round-trip.
	mu sync.Mutex
	// fetching serializes the /models refresh itself, so concurrent chat requests
	// for one credential produce a single refresh instead of one per request,
	// while still letting readers see the current token without blocking.
	fetching sync.Mutex
}

var attestationCache sync.Map // authID -> *attestationEntry

// attestationCacheKey is the single definition of the cache key. Refresh paths
// must derive it the same way as attestationFor, otherwise an empty AuthID
// makes them update a different entry than the one chat requests read.
func attestationCacheKey(authID string, sa storedAuth) string {
	if strings.TrimSpace(authID) != "" {
		return authID
	}
	return sa.DeviceToken
}

// setAttestation records a freshly issued token plus its expiry. The expiry is
// always written (see attestationFreshUntil) so a restart never trusts a token
// for an unknown remaining lifetime just because the gateway omitted expires_in.
func (s *storedAuth) setAttestation(token string, expiresIn int64) {
	if strings.TrimSpace(token) == "" {
		return
	}
	s.Attestation = token
	s.AttestationExpiresAt = attestationFreshUntil(expiresIn).Unix()
}

// cacheAttestation aligns the in-memory entry with a token a refresh path just
// fetched out of band, so the next chat request reuses it instead of re-fetching.
func cacheAttestation(authID string, sa storedAuth) {
	if sa.Attestation == "" {
		return
	}
	v, _ := attestationCache.LoadOrStore(attestationCacheKey(authID, sa), &attestationEntry{})
	entry := v.(*attestationEntry)
	entry.mu.Lock()
	entry.token = sa.Attestation
	if sa.AttestationExpiresAt > 0 {
		entry.expiresAt = time.Unix(sa.AttestationExpiresAt, 0)
	}
	entry.lastFailure = time.Time{}
	entry.mu.Unlock()
}

func attestationFor(authID string, sa storedAuth, callbackID string) string {
	v, _ := attestationCache.LoadOrStore(attestationCacheKey(authID, sa), &attestationEntry{})
	entry := v.(*attestationEntry)

	// Phase 1: decide under the short lock whether a refresh is needed.
	entry.mu.Lock()
	// Seed from the credential file on first use after a restart. A seed with
	// an unknown expiry stays zero on purpose: the stale check below then
	// replaces the untrusted token with a fresh one instead of trusting it for
	// an unknown remaining lifetime.
	if entry.token == "" && sa.Attestation != "" {
		entry.token = sa.Attestation
		if sa.AttestationExpiresAt > 0 {
			entry.expiresAt = time.Unix(sa.AttestationExpiresAt, 0)
		}
	}
	current := entry.token
	stale := entry.token == "" || entry.expiresAt.IsZero() ||
		time.Now().After(entry.expiresAt.Add(-attestationRefreshMargin))
	coolingDown := !entry.lastFailure.IsZero() && time.Since(entry.lastFailure) < attestationFailCooldown
	entry.mu.Unlock()

	if !stale || coolingDown {
		return current
	}

	// Phase 2: refresh outside entry.mu so readers of the still-valid token are
	// not blocked behind a gateway round-trip. fetching collapses the concurrent
	// refreshes for this credential into one.
	entry.fetching.Lock()
	defer entry.fetching.Unlock()

	// Another goroutine may have refreshed while we waited for fetching.
	entry.mu.Lock()
	current = entry.token
	stillStale := entry.token == "" || entry.expiresAt.IsZero() ||
		time.Now().After(entry.expiresAt.Add(-attestationRefreshMargin))
	coolingDown = !entry.lastFailure.IsZero() && time.Since(entry.lastFailure) < attestationFailCooldown
	entry.mu.Unlock()
	if !stillStale || coolingDown {
		return current
	}

	token, expiresIn, err := fetchAttestation(sa, callbackID)

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if err != nil || token == "" {
		entry.lastFailure = time.Now()
		return entry.token
	}
	entry.token = token
	entry.lastFailure = time.Time{}
	entry.expiresAt = attestationFreshUntil(expiresIn)
	return entry.token
}

func fetchAttestation(sa storedAuth, callbackID string) (string, int64, error) {
	resp, err := fetchModels(sa, "", callbackID)
	if err != nil {
		return "", 0, err
	}
	if resp.ClientAttestation == nil {
		return "", 0, nil
	}
	return resp.ClientAttestation.Token, resp.ClientAttestation.ExpiresIn, nil
}

// ---------------------------------------------------------------------------
// gateway endpoints
// ---------------------------------------------------------------------------

type gatewayError struct {
	Error struct {
		Message   string `json:"message"`
		Type      string `json:"type"`
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// gatewayMessage extracts { error: { message } } and appends the tail the
// official CLI shows (dist/error-humanize.js): HTTP status, error code, and the
// gateway request id. The plain message alone is often all a client renders, so
// without the tail a user reporting a problem has no id to quote and the
// quota-exhausted case is indistinguishable from a transient failure.
func gatewayMessage(body []byte, status int) string {
	var ge gatewayError
	if err := json.Unmarshal(body, &ge); err == nil && ge.Error.Message != "" {
		return ge.Error.Message + errorTail(ge, status)
	}
	return fmt.Sprintf("upstream %d: %s", status, truncate(strings.TrimSpace(string(body)), 200))
}

// errorTail formats the " (HTTP 429 · insufficient_quota · 请求编号 …)" suffix.
// The code names follow the CLI so the same text keeps its meaning on both
// clients; insufficient_quota in particular marks "do not retry, the quota is
// gone" rather than a rate limit.
func errorTail(ge gatewayError, status int) string {
	code := ge.Error.Code
	if ge.Error.Type == "insufficient_quota" || code == "quota_exceeded" {
		code = "insufficient_quota"
	}
	tags := make([]string, 0, 3)
	if status > 0 {
		tags = append(tags, fmt.Sprintf("HTTP %d", status))
	}
	if strings.TrimSpace(code) != "" {
		tags = append(tags, code)
	}
	if id := strings.TrimSpace(ge.Error.RequestID); id != "" {
		tags = append(tags, "请求编号 "+truncate(id, 64))
	}
	if len(tags) == 0 {
		return ""
	}
	return " (" + strings.Join(tags, " · ") + ")"
}

type modelThinking struct {
	Levels        []string          `json:"levels"`
	DefaultLevel  string            `json:"default_level"`
	CanDisable    bool              `json:"can_disable"`
	LevelMap      map[string]string `json:"level_map"`
	RequestFormat string            `json:"request_format"`
}

// thinkingProfile is the per-model reasoning contract the plugin needs when it
// translates a host thinking suffix into upstream request fields. It mirrors the
// official CLI's parseThinkingCapabilities (dist/config.js).
type thinkingProfile struct {
	Levels        []string
	DefaultLevel  string
	CanDisable    bool
	LevelMap      map[string]string
	RequestFormat string
}

// thinkingProfiles caches the per-model reasoning contract from /v1/models,
// keyed by upstream model id. The executor needs it to turn a suffix like
// "(high)" into the request fields the gateway expects, and the suffix arrives
// on a chat request that carries no model table of its own.
var thinkingProfiles sync.Map // model id -> thinkingProfile

func storeThinkingProfile(m gatewayModel) {
	id := strings.TrimSpace(m.ID)
	if id == "" {
		return
	}
	if !m.hasThinking() {
		thinkingProfiles.Delete(id)
		return
	}
	levelMap := make(map[string]string, len(m.Thinking.LevelMap))
	for level, mapped := range m.Thinking.LevelMap {
		if strings.TrimSpace(mapped) != "" {
			levelMap[strings.ToLower(strings.TrimSpace(level))] = mapped
		}
	}
	thinkingProfiles.Store(id, thinkingProfile{
		Levels:        append([]string(nil), m.Thinking.Levels...),
		DefaultLevel:  strings.ToLower(strings.TrimSpace(m.Thinking.DefaultLevel)),
		CanDisable:    m.Thinking.CanDisable,
		LevelMap:      levelMap,
		RequestFormat: strings.ToLower(strings.TrimSpace(m.Thinking.RequestFormat)),
	})
}

func thinkingProfileFor(model string) (thinkingProfile, bool) {
	v, ok := thinkingProfiles.Load(strings.TrimSpace(model))
	if !ok {
		return thinkingProfile{}, false
	}
	profile, ok := v.(thinkingProfile)
	return profile, ok
}

// supportsLevel reports whether the gateway accepts this reasoning level for the
// model. Levels outside the advertised set would be rejected upstream.
func (p thinkingProfile) supportsLevel(level string) bool {
	level = strings.ToLower(strings.TrimSpace(level))
	for _, candidate := range p.Levels {
		if strings.EqualFold(strings.TrimSpace(candidate), level) {
			return true
		}
	}
	return false
}

// upstreamLevel maps a canonical level onto the gateway's own vocabulary.
func (p thinkingProfile) upstreamLevel(level string) string {
	level = strings.ToLower(strings.TrimSpace(level))
	if mapped, ok := p.LevelMap[level]; ok && strings.TrimSpace(mapped) != "" {
		return mapped
	}
	return level
}

type gatewayModel struct {
	ID            string         `json:"id"`
	Object        string         `json:"object"`
	OwnedBy       string         `json:"owned_by"`
	Name          string         `json:"name"`
	Reasoning     bool           `json:"reasoning"`
	Vision        bool           `json:"vision"`
	ContextLength int64          `json:"context_length"`
	MaxTokens     int64          `json:"max_tokens"`
	Thinking      *modelThinking `json:"thinking"`
	// FreePackageEligible reports whether the free quota package pays for this
	// model. A pointer because older gateways omit it, and "unknown" must not
	// read as "not covered".
	FreePackageEligible *bool            `json:"free_package_eligible"`
	Price               *modelPrice      `json:"price"`
	PriceBands          *modelPriceBands `json:"price_bands"`
}

// modelPrice is USD per million tokens, display only: billing is server-side.
type modelPrice struct {
	Input     float64  `json:"input"`
	Output    float64  `json:"output"`
	CacheRead *float64 `json:"cache_read"`
}

// blended averages input and output price, matching the CLI's cost comparison.
func (p *modelPrice) blended() float64 {
	if p == nil {
		return 0
	}
	return (p.Input + p.Output) / 2
}

// modelPriceBands carries peak/off-peak rates for models that switch during
// Beijing business hours. Current names the band in effect right now; the
// band objects use camelCase keys upstream, unlike price.cache_read.
type modelPriceBands struct {
	Current string     `json:"current"`
	Peak    *bandPrice `json:"peak"`
	OffPeak *bandPrice `json:"off_peak"`
}

type bandPrice struct {
	Input     float64 `json:"input"`
	Output    float64 `json:"output"`
	CacheRead float64 `json:"cacheRead"`
}

// hasThinking reports whether the gateway advertised usable reasoning levels.
// The reasoning flag alone is not the test: the CLI treats thinking metadata as
// sufficient (apiModelToDef), and levels are what the executor actually needs.
func (m gatewayModel) hasThinking() bool {
	return m.Thinking != nil && len(m.Thinking.Levels) > 0
}

// freeEligible reports free-package coverage, defaulting to false when the
// gateway omits the field. Callers that must distinguish "unknown" from "not
// covered" test FreePackageEligible directly.
func (m gatewayModel) freeEligible() bool {
	return m.FreePackageEligible != nil && *m.FreePackageEligible
}

type clientAttestation struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

type modelsResponse struct {
	Object            string               `json:"object"`
	Data              []gatewayModel       `json:"data"`
	Features          map[string]any       `json:"features"`
	Announcement      *gatewayAnnouncement `json:"announcement"`
	ClientAttestation *clientAttestation   `json:"client_attestation"`
}

// gatewayAnnouncement is the operator notice the gateway ships with every
// models response. The official CLI polls for it during a session because a
// maintenance window otherwise only surfaces as bare request failures; the
// panel is the equivalent surface here.
type gatewayAnnouncement struct {
	Text string `json:"text"`
	URL  string `json:"url,omitempty"`
}

const maxAnnouncementChars = 2000

// announcementTTL bounds how stale the panel's copy of the notice may get. It
// matches modelCacheTTL: both are refreshed by the same /v1/models call.
const announcementTTL = 5 * time.Minute

var (
	announcementMu        sync.RWMutex
	announcementSeen      *gatewayAnnouncement
	announcementFetchedAt time.Time
)

// storeAnnouncement records the notice from the latest models response,
// including its absence: a cleared announcement must disappear from the panel.
// The URL is validated here because the panel renders it as a link.
func storeAnnouncement(a *gatewayAnnouncement) {
	var next *gatewayAnnouncement
	if a != nil && strings.TrimSpace(a.Text) != "" {
		next = &gatewayAnnouncement{Text: truncate(strings.TrimSpace(a.Text), maxAnnouncementChars)}
		if url := strings.TrimSpace(a.URL); isHTTPURL(url) {
			next.URL = url
		}
	}
	announcementMu.Lock()
	announcementSeen = next
	announcementFetchedAt = time.Now()
	announcementMu.Unlock()
}

func currentAnnouncement() *gatewayAnnouncement {
	announcementMu.RLock()
	defer announcementMu.RUnlock()
	if announcementSeen == nil {
		return nil
	}
	copied := *announcementSeen
	return &copied
}

// refreshAnnouncementIfStale re-reads /v1/models when the cached notice is older
// than announcementTTL. Chat traffic refreshes it as a side effect, but a host
// that only serves a fixed model would otherwise keep a maintenance notice from
// hours ago; the panel is the only place this plugin can show one at all.
// Failures are ignored: a stale notice beats a failed panel load.
func refreshAnnouncementIfStale(sa storedAuth, attestation, callbackID string) {
	announcementMu.RLock()
	fresh := !announcementFetchedAt.IsZero() && time.Since(announcementFetchedAt) < announcementTTL
	announcementMu.RUnlock()
	if fresh {
		return
	}
	if _, err := fetchModels(sa, attestation, callbackID); err != nil {
		hostLog("debug", "u1s1: announcement refresh failed: "+redactSecrets(err.Error()))
	}
}

// isHTTPURL keeps javascript:/data: payloads out of the panel's link href.
func isHTTPURL(raw string) bool {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	if len(raw) > 2048 {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return false
		}
	}
	return true
}

// fetchModels calls GET /v1/models. attestation may be empty: the models route
// itself does not require it (that is how the token is first obtained).
func fetchModels(sa storedAuth, attestation, callbackID string) (*modelsResponse, error) {
	url := sa.baseURL() + "/models"
	headers, err := signedHeaders(sa, "GET", url, attestation)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest("GET", url, headers, nil, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 models: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded modelsResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, fmt.Errorf("u1s1 models: decode: %w", err)
	}
	// Cache the reasoning contract for every model here rather than only in
	// model.for_auth: chat requests carry a thinking suffix but no model table,
	// and this is the one route every credential path already goes through.
	for _, m := range decoded.Data {
		storeThinkingProfile(m)
	}
	storeAnnouncement(decoded.Announcement)
	return &decoded, nil
}

type meResponse struct {
	Email                 string  `json:"email"`
	SignupCreditUSD       float64 `json:"signup_credit_usd"`
	DailyFreeUSD          float64 `json:"daily_free_usd"`
	DailyFreeUsedUSD      float64 `json:"daily_free_used_usd"`
	DailyFreeRemainingUSD float64 `json:"daily_free_remaining_usd"`
	DailyFreeResetsAt     string  `json:"daily_free_resets_at"`
	DailyFreeModel        string  `json:"daily_free_model"`
	MonthlyFreeUSD        float64 `json:"monthly_free_usd"`
	MTDUSD                float64 `json:"mtd_usd"`
	BalanceSpentUSD       float64 `json:"balance_spent_usd"`
	BonusBalanceUSD       float64 `json:"bonus_balance_usd"`
	RemainingUSD          float64 `json:"remaining_usd"`
	// FreeClaim is "first" (signup package) or "renew" (yearly package) when the
	// account has a free quota package waiting to be claimed on the website, and
	// null/absent otherwise.
	FreeClaim    string           `json:"free_claim"`
	TokensPerUSD float64          `json:"tokens_per_usd"`
	Packages     []gatewayPackage `json:"packages"`
}

// gatewayPackage is one quota package as reported by /v1/me.
type gatewayPackage struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	Scope       string `json:"scope"`
	DailyTokens *int64 `json:"daily_tokens"`
	TotalTokens *int64 `json:"total_tokens"`
	UsedToday   int64  `json:"used_today"`
	UsedTokens  int64  `json:"used_tokens"`
	Remaining   int64  `json:"remaining"`
	ExpiresAt   string `json:"expires_at"`
	Note        string `json:"note"`
	CreatedAt   string `json:"created_at"`
}

func fetchMe(sa storedAuth, attestation, callbackID string) (*meResponse, error) {
	url := sa.baseURL() + "/me"
	headers, err := signedHeaders(sa, "GET", url, attestation)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest("GET", url, headers, nil, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 me: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded meResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, fmt.Errorf("u1s1 me: decode: %w", err)
	}
	return &decoded, nil
}

// ---------------------------------------------------------------------------
// device login
// ---------------------------------------------------------------------------

type deviceStartResponse struct {
	VerifyURL  string `json:"verify_url"`
	PollSecret string `json:"poll_secret"`
	Interval   int    `json:"interval"`
	ExpiresIn  int    `json:"expires_in"`
}

type devicePollResponse struct {
	Status      string `json:"status"`
	APIKey      string `json:"api_key"`
	DeviceToken string `json:"device_token"`
	DeviceID    int64  `json:"device_id"`
}

// startDeviceLogin posts a fresh public key to /auth/device/start and returns
// the browser verification URL plus the polling secret.
func startDeviceLogin(pair *deviceKeyPair, callbackID string) (*deviceStartResponse, error) {
	cfg := activeConfig()
	url := cfg.apiOrigin() + "/auth/device/start"
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "cli-proxy-api"
	}
	body, err := json.Marshal(map[string]any{
		"public_jwk":     pair.Public,
		"device_name":    fmt.Sprintf("%s (linux via CLIProxyAPI)", hostname),
		"client_version": cfg.ClientVersion,
	})
	if err != nil {
		return nil, err
	}
	resp, err := doRequest("POST", url, map[string]string{
		"content-type": "application/json",
		"user-agent":   cfg.UserAgent,
	}, body, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 device start: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded deviceStartResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, fmt.Errorf("u1s1 device start: decode: %w", err)
	}
	if decoded.VerifyURL == "" || decoded.PollSecret == "" {
		return nil, fmt.Errorf("u1s1 device start: gateway returned no verify_url/poll_secret")
	}
	if decoded.ExpiresIn <= 0 || decoded.ExpiresIn > 1800 {
		decoded.ExpiresIn = 900
	}
	if !strings.HasPrefix(decoded.VerifyURL, "http://") && !strings.HasPrefix(decoded.VerifyURL, "https://") {
		return nil, fmt.Errorf("u1s1 device start: unexpected verify_url scheme")
	}
	// Clamp the gateway's poll hint into [2,30]s while preserving a requested
	// slower cadence: a rate-limited 60s hint must not become a 2s hammer.
	decoded.Interval = min(max(decoded.Interval, 2), 30)
	return &decoded, nil
}

// pollDeviceLogin performs one poll against /auth/device/poll. The host drives
// the polling cadence via repeated auth.login.poll calls, so this is one shot.
// The HTTP status is surfaced so the caller can end the session on permanent
// client errors instead of spinning until the session expires.
func pollDeviceLogin(pollSecret, callbackID string) (*devicePollResponse, int, error) {
	cfg := activeConfig()
	url := cfg.apiOrigin() + "/auth/device/poll"
	body, err := json.Marshal(map[string]any{"poll_secret": pollSecret})
	if err != nil {
		return nil, 0, err
	}
	resp, err := doRequest("POST", url, map[string]string{
		"content-type": "application/json",
		"user-agent":   cfg.UserAgent,
	}, body, callbackID)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("u1s1 device poll: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded devicePollResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("u1s1 device poll: decode: %w", err)
	}
	return &decoded, resp.StatusCode, nil
}

func validCredential(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) > 4096 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}
