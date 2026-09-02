// auth.go implements the auth_provider capability: browser device login,
// polling, credential file parsing, and refresh. Credentials are persisted by
// the host into auth-dir as u1s1-<email>.json (see storedAuth in gateway.go).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// loginSession keeps the device keypair and poll secret between
// auth.login.start and the host's repeated auth.login.poll calls.
type loginSession struct {
	Pair       *deviceKeyPair
	PollSecret string
	ExpiresAt  time.Time
}

var loginSessions sync.Map // state -> *loginSession

// rpcAuthLoginStartRequest / poll mirror internal/pluginhost/rpc_schema.go: the
// host adds host_callback_id so nested host.http.* calls are attributed.
type rpcAuthLoginStartRequest struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcAuthLoginPollRequest struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcAuthRefreshRequest struct {
	pluginapi.AuthRefreshRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// handleAuthLoginStart generates a device keypair, asks the gateway for a
// verification URL, and returns it for the user to approve in a browser.
func handleAuthLoginStart(raw []byte) ([]byte, error) {
	var req rpcAuthLoginStartRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
	}
	pair, err := generateDeviceKeyPair()
	if err != nil {
		return nil, fmt.Errorf("u1s1: generate device key: %w", err)
	}
	start, err := startDeviceLogin(pair, req.HostCallbackID)
	if err != nil {
		return nil, err
	}
	// State must satisfy the host's ValidateOAuthState (alphanumerics, -, _, .).
	state := "u1s1-" + randomHex(16)
	expiresAt := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	loginSessions.Store(state, &loginSession{
		Pair:       pair,
		PollSecret: start.PollSecret,
		ExpiresAt:  expiresAt,
	})
	pruneLoginSessions()
	hostLog("info", "u1s1: device login started, awaiting browser approval")
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  providerName,
		URL:       start.VerifyURL,
		State:     state,
		ExpiresAt: expiresAt,
		Metadata: map[string]any{
			"poll_interval": start.Interval,
		},
	})
}

// handleAuthLoginPoll performs one gateway poll. Pending is reported until the
// browser approval lands; on success the credential file content is returned as
// StorageJSON and the host writes it into auth-dir.
func handleAuthLoginPoll(raw []byte) ([]byte, error) {
	var req rpcAuthLoginPollRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
	}
	state := strings.TrimSpace(req.State)
	v, ok := loginSessions.Load(state)
	if !ok {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "登录会话已失效，请重新发起 u1s1 登录",
		})
	}
	session := v.(*loginSession)
	if time.Now().After(session.ExpiresAt) {
		loginSessions.Delete(state)
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "登录链接已过期，请重新发起 u1s1 登录",
		})
	}

	poll, pollStatus, err := pollDeviceLogin(session.PollSecret, req.HostCallbackID)
	if err != nil {
		// A permanent client error (bad or revoked poll secret, banned device)
		// will never succeed: end the session instead of spinning "pending"
		// until it expires. 429, 5xx, and transport failures stay retryable.
		if pollStatus >= 400 && pollStatus < 500 && pollStatus != http.StatusTooManyRequests {
			loginSessions.Delete(state)
			return okEnvelope(pluginapi.AuthLoginPollResponse{
				Status:  pluginapi.AuthLoginStatusError,
				Message: "登录状态轮询失败，请重新发起 u1s1 登录：" + redactSecrets(err.Error()),
			})
		}
		// Network hiccup or transient gateway error: keep the session alive.
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "等待浏览器批准…",
		})
	}
	switch poll.Status {
	case "ok":
		if !validCredential(poll.DeviceToken, "u1s1d-") {
			return okEnvelope(pluginapi.AuthLoginPollResponse{
				Status:  pluginapi.AuthLoginStatusError,
				Message: "网关返回的设备凭证格式不正确",
			})
		}
		loginSessions.Delete(state)
		sa := storedAuth{
			Type:             providerName,
			BaseURL:          activeConfig().BaseURL,
			DeviceToken:      poll.DeviceToken,
			DeviceID:         poll.DeviceID,
			DevicePrivateJwk: session.Pair.Private,
			DevicePublicJwk:  session.Pair.Public,
			CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		}
		if validCredential(poll.APIKey, "u1s1-") {
			sa.APIKey = poll.APIKey
		}
		// Prime the attestation token first: /models is the one route that does
		// not require it, and every later call must carry the full four-layer
		// fingerprint — a bare-DPoP /me risks 403 client_integrity_review.
		if token, expiresIn, errAtt := fetchAttestation(sa, req.HostCallbackID); errAtt == nil && token != "" {
			sa.setAttestation(token, expiresIn)
		} else if errAtt != nil {
			hostLog("warn", "u1s1: device approved but attestation fetch failed: "+redactSecrets(errAtt.Error()))
		}
		// Confirm the credential and learn the account email for the file name.
		// A failure here is not fatal: the device is already approved.
		if me, errMe := fetchMe(sa, sa.Attestation, req.HostCallbackID); errMe == nil {
			sa.Email = me.Email
		} else {
			hostLog("warn", "u1s1: device approved but /me check failed: "+redactSecrets(errMe.Error()))
		}
		authData, err := authDataFor(sa)
		if err != nil {
			return nil, err
		}
		hostLog("info", "u1s1: device login completed")
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusSuccess,
			Message: "u1s1 设备已批准，凭证已保存",
			Auth:    authData,
		})
	case "expired":
		loginSessions.Delete(state)
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "登录链接已失效，请重新发起 u1s1 登录",
		})
	default:
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "等待浏览器批准…",
		})
	}
}

func pruneLoginSessions() {
	now := time.Now()
	loginSessions.Range(func(key, value any) bool {
		if session, ok := value.(*loginSession); ok && now.After(session.ExpiresAt) {
			loginSessions.Delete(key)
		}
		return true
	})
}

// refreshIntervalSeconds tells the host how often to call auth.refresh.
//
// Without it the credential is never refreshed at all: the host's shouldRefresh()
// falls through to ProviderRefreshLead("u1s1"), and only the built-in providers
// (codex/claude/antigravity/kimi/xai) register a lead factory, so it returns nil
// and the auth is not even entered into the auto-refresh heap. AuthData.
// NextRefreshAfter alone does not schedule anything — it only gates a refresh
// that some other rule already asked for.
//
// 12 hours keeps the attestation token well inside its 7-day life and inside
// attestationUnknownTTL (48h) when the gateway omits expires_in.
const refreshIntervalSeconds = 12 * 60 * 60

// credentialMetadata converts the credential into the host metadata map.
//
// Every credential-owned key must be published here, not only the display ones.
// Before writing, the host merges the *existing* credential file into this map
// (management.saveTokenRecord -> MergeExistingAuthMetadata) and metadata then
// wins over StorageJSON (mergedStorageJSON). Any key we omit is therefore
// refilled from the old file: after re-approving a device the stale
// deviceToken/keypair would overwrite the freshly issued ones and the new
// credential would be silently discarded. The host's own protection
// (IsAuthTokenPayloadKey) only covers access_token-family names, and u1s1 uses
// none of those.
//
// The mirror image of that rule is what prefix/email rely on: omitempty keeps
// them *absent* rather than empty, and absent is exactly what lets the host
// backfill a value it already knows.
func credentialMetadata(sa storedAuth) (map[string]any, error) {
	storage, err := json.Marshal(sa)
	if err != nil {
		return nil, err
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(storage, &metadata); err != nil {
		return nil, err
	}
	// Attestation is omitempty, so an empty one would be backfilled from the old
	// file. Publish it explicitly: a credential whose attestation we could not
	// fetch must start with none and re-fetch, not inherit a token issued for a
	// device registration that no longer exists.
	metadata["attestation"] = sa.Attestation
	metadata["attestationExpiresAt"] = sa.AttestationExpiresAt
	metadata["type"] = providerName
	metadata["refresh_interval_seconds"] = refreshIntervalSeconds
	return metadata, nil
}

// authDataFor builds the host AuthData record (file name, label, attributes)
// from a credential. The file lands in auth-dir as u1s1-<email>.json.
func authDataFor(sa storedAuth) (pluginapi.AuthData, error) {
	storage, err := json.Marshal(sa)
	if err != nil {
		return pluginapi.AuthData{}, err
	}
	id := authIdentity(sa)
	label := sa.Email
	if label == "" {
		label = "u1s1 device"
	}
	metadata, err := credentialMetadata(sa)
	if err != nil {
		return pluginapi.AuthData{}, err
	}
	attributes := map[string]string{
		"provider": providerName,
		// Mirrored into attributes so the interval also applies to the in-memory
		// record before the first file write.
		"refresh_interval_seconds": strconv.Itoa(refreshIntervalSeconds),
	}
	// Same rule as prefix below: the host merges only *missing* keys from the
	// existing record, so an explicit empty value would clobber a known email.
	if sa.Email != "" {
		attributes["email"] = sa.Email
	}
	return pluginapi.AuthData{
		Provider: providerName,
		ID:       id,
		FileName: id + ".json",
		Label:    label,
		// Echo the stored prefix so a management-set model prefix survives the
		// plugin parse path (the host only auto-fills prefix for native files).
		// When empty the host backfills it from the existing auth record.
		Prefix:      sa.Prefix,
		StorageJSON: storage,
		Metadata:    metadata,
		Attributes:  attributes,
	}, nil
}

// authIdentity derives a stable, filesystem-safe identity for a credential.
func authIdentity(sa storedAuth) string {
	if email := sanitizeIdentity(sa.Email); email != "" {
		return providerName + "-" + email
	}
	// Fall back to a device-token suffix; never expose the token itself.
	token := sa.DeviceToken
	if len(token) > 8 {
		token = token[len(token)-8:]
	}
	return providerName + "-device-" + sanitizeIdentity(token)
}

func sanitizeIdentity(in string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(in)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			sb.WriteRune(r)
		case r == '@':
			sb.WriteRune('-')
		}
	}
	return strings.Trim(sb.String(), "-._")
}

// handleAuthParse claims u1s1 credential files discovered in auth-dir. It also
// accepts a verbatim ~/.u1s1/config.json copy so an existing CLI login can be
// imported by dropping the file in.
func handleAuthParse(raw []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
	}
	if req.Provider != "" && !strings.EqualFold(req.Provider, providerName) {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	var sa storedAuth
	if err := json.Unmarshal(req.RawJSON, &sa); err != nil {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	// Only claim files that are unmistakably u1s1: a device token plus keypair.
	if !sa.hasDeviceCredential() {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	if sa.Type == "" {
		sa.Type = providerName
	}
	authData, err := authDataFor(sa)
	if err != nil {
		return nil, err
	}
	// Preserve the discovered file name so the host does not rewrite the file.
	if strings.TrimSpace(req.FileName) != "" {
		authData.FileName = req.FileName
	}
	return okEnvelope(pluginapi.AuthParseResponse{Handled: true, Auth: authData})
}

// handleAuthRefresh re-validates the device credential and refreshes the cached
// attestation token. u1s1 device tokens themselves do not expire on a schedule;
// the gateway revokes them when the device is removed, which surfaces as 401.
func handleAuthRefresh(raw []byte) ([]byte, error) {
	var req rpcAuthRefreshRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	models, err := fetchModels(sa, "", req.HostCallbackID)
	if err != nil {
		return nil, err
	}
	if models.ClientAttestation != nil && models.ClientAttestation.Token != "" {
		sa.setAttestation(models.ClientAttestation.Token, models.ClientAttestation.ExpiresIn)
		// Keep the in-memory cache aligned with what we just persisted.
		cacheAttestation(req.AuthID, sa)
	}
	authData, err := authDataFor(sa)
	if err != nil {
		return nil, err
	}
	if req.AuthID != "" {
		authData.ID = req.AuthID
	}
	// Leave FileName empty: authDataFor derives it from the email, which would
	// rename credentials imported under a different file name (the parse path
	// preserves the discovered name). The host backfills an empty FileName from
	// the existing record instead.
	authData.FileName = ""
	// Refresh twice a day: keeps the attestation token well inside its 7-day
	// life and inside attestationUnknownTTL when the gateway omits expires_in.
	authData.NextRefreshAfter = time.Now().Add(12 * time.Hour)
	return okEnvelope(pluginapi.AuthRefreshResponse{
		Auth:             authData,
		NextRefreshAfter: authData.NextRefreshAfter,
	})
}
