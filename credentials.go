// credentials.go owns the on-disk credential model: storedAuth is what the host
// persists into auth-dir as u1s1-<email>.json. Field names match
// ~/.u1s1/config.json so an existing CLI install can be imported verbatim, and
// the custom JSON round-trip preserves every key the struct does not model.
package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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
	if v := strings.TrimSpace(s.BaseURL); v != "" {
		return migrateStoredBaseURL(v)
	}
	return activeConfig().BaseURL
}

// withMigratedBaseURL returns a copy whose BaseURL is normalized to the current
// site, so every write-back path (auth.parse, login poll, auth.refresh) persists
// the new domain instead of echoing a legacy value from an older CLI install.
// Mirrors u1s1-cli's migrateStoredBaseUrl, which rewrites the stored base on the
// next save. A credential with no stored base is left untouched: the host keeps
// its existing value and baseURL() falls back to the configured default.
func (s storedAuth) withMigratedBaseURL() storedAuth {
	if strings.TrimSpace(s.BaseURL) == "" {
		return s
	}
	s.BaseURL = migrateStoredBaseURL(s.BaseURL)
	return s
}

// legacyCNBases are the historic China-site API roots. u1s1-cli's site.js
// (migrateStoredBaseUrl) rewrites a stored base that matches one of these to
// the current SITES.cn.apiBase; older CLI installs and credential files copied
// from ~/.u1s1/config.json still carry api.u1s1.io. The site moved to
// u1s1app.com (u1s1.io pages 308-redirect, but signed POSTs must not be sent to
// a host the CLI has left behind), so a stored legacy base must be migrated
// rather than trusted verbatim.
var legacyCNBases = map[string]bool{
	"https://api.u1s1.io/v1": true,
}

// migrateStoredBaseURL rewrites a legacy China-site API root to the plugin's
// configured base URL. International-site (u1s1.dev), the current China-site
// base, and custom gateway URLs are returned unchanged: they are different
// accounts/endpoints, and the plugin must not redirect them to the China site.
// Trailing slashes are trimmed before comparison, matching the CLI's
// normalization.
func migrateStoredBaseURL(stored string) string {
	normalized := strings.TrimSuffix(strings.TrimSpace(stored), "/")
	if legacyCNBases[normalized] {
		return activeConfig().BaseURL
	}
	return normalized
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

// validCredential checks a token-shaped value: the right prefix, bounded length,
// and no control characters.
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
