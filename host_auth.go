// host_auth.go wraps the host credential callbacks (host.auth.list / host.auth.get)
// so the management panel can enumerate u1s1 credentials without reading auth-dir
// directly. Credential JSON never leaves this process.
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

type hostAuthGetResponse struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

// isU1S1AuthName recognizes credential files owned by this plugin. File name is
// the reliable discriminator across host versions; Type/Provider may be absent
// on hand-placed files. Check-in sidecars (any *.checkin*) are never
// credentials, even though the legacy v0.2.4 name ended in .json — the host
// scans auth-dir for *.json and must not see the sidecar as a second account.
func isU1S1AuthName(name string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		return false
	}
	base := trimmed
	if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
		base = base[idx+1:]
	}
	if strings.Contains(base, ".checkin") {
		return false
	}
	return strings.HasPrefix(base, providerName+"-") && strings.HasSuffix(base, ".json")
}

// isCheckinSidecarName reports whether a host-listed file is a check-in sidecar.
// This is checked unconditionally in hostAuthList, before the Provider/Type
// shortcut: a host that tags the legacy .checkin.json with Provider=u1s1 would
// otherwise let the sidecar back in as a phantom credential even though
// isU1S1AuthName rejects it.
func isCheckinSidecarName(name string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		return false
	}
	base := trimmed
	if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
		base = base[idx+1:]
	}
	return strings.Contains(base, ".checkin")
}

// hostAuthList returns the u1s1 credential records known to the host.
func hostAuthList() ([]pluginapi.HostAuthFileEntry, error) {
	raw, err := hostCall(pluginabi.MethodHostAuthList, nil)
	if err != nil {
		return nil, err
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostAuthList)
	if err != nil {
		return nil, err
	}
	var resp hostAuthListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("decode host.auth.list response: %w", err)
	}
	out := make([]pluginapi.HostAuthFileEntry, 0, len(resp.Files))
	for _, f := range resp.Files {
		// Sidecars are never credentials, regardless of what the host inferred
		// for Provider/Type from the legacy .checkin.json file name.
		if isCheckinSidecarName(f.Name) {
			continue
		}
		if strings.EqualFold(f.Provider, providerName) || strings.EqualFold(f.Type, providerName) || isU1S1AuthName(f.Name) {
			out = append(out, f)
		}
	}
	return out, nil
}

// hostAuthGet reads and parses one credential by its runtime auth index.
func hostAuthGet(authIndex string) (storedAuth, *hostAuthGetResponse, error) {
	payload, err := json.Marshal(map[string]string{"auth_index": authIndex})
	if err != nil {
		return storedAuth{}, nil, err
	}
	raw, err := hostCall(pluginabi.MethodHostAuthGet, payload)
	if err != nil {
		return storedAuth{}, nil, err
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostAuthGet)
	if err != nil {
		return storedAuth{}, nil, err
	}
	var resp hostAuthGetResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return storedAuth{}, nil, fmt.Errorf("decode host.auth.get response: %w", err)
	}
	sa, err := parseStored(resp.JSON)
	if err != nil {
		return storedAuth{}, &resp, err
	}
	return sa, &resp, nil
}
