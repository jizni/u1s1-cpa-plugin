// models.go implements the model_provider capability: model.for_auth asks the
// gateway for the live catalog (GET /v1/models) for a given credential and maps
// it to host ModelInfo records.
package main

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// modelCacheTTL keeps repeated model.for_auth calls (config reloads, management
// refreshes) from hitting the gateway on every request.
const modelCacheTTL = 5 * time.Minute

type modelCacheEntry struct {
	models    []pluginapi.ModelInfo
	fetchedAt time.Time
}

var modelCache sync.Map // authID -> modelCacheEntry

type rpcAuthModelRequest struct {
	pluginapi.AuthModelRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func handleModelForAuth(raw []byte) ([]byte, error) {
	var req rpcAuthModelRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
	}
	if req.AuthProvider != "" && !strings.EqualFold(req.AuthProvider, providerName) {
		return okEnvelope(pluginapi.ModelResponse{})
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	cacheKey := req.AuthID
	if cacheKey == "" {
		cacheKey = authIdentity(sa)
	}
	if v, ok := modelCache.Load(cacheKey); ok {
		if entry, ok := v.(modelCacheEntry); ok && time.Since(entry.fetchedAt) < modelCacheTTL {
			return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: entry.models})
		}
	}

	resp, err := fetchModels(sa, attestationFor(req.AuthID, sa, req.HostCallbackID), req.HostCallbackID)
	if err != nil {
		return nil, err
	}
	models := make([]pluginapi.ModelInfo, 0, len(resp.Data))
	for _, m := range resp.Data {
		if strings.TrimSpace(m.ID) == "" {
			continue
		}
		models = append(models, toModelInfo(m))
	}
	modelCache.Store(cacheKey, modelCacheEntry{models: models, fetchedAt: time.Now()})

	out := pluginapi.ModelResponse{Provider: providerName, Models: models}
	// Persist a freshly issued attestation token alongside the credential so a
	// restart can sign the first chat request without an extra models hop.
	if resp.ClientAttestation != nil && resp.ClientAttestation.Token != "" && resp.ClientAttestation.Token != sa.Attestation {
		sa.setAttestation(resp.ClientAttestation.Token, resp.ClientAttestation.ExpiresIn)
		if authData, errAuth := authDataFor(sa); errAuth == nil {
			if req.AuthID != "" {
				authData.ID = req.AuthID
			}
			// Empty FileName: authDataFor would rename credentials imported under
			// a different file name; the host backfills the existing name.
			authData.FileName = ""
			out.AuthUpdate = authData
		}
	}
	return okEnvelope(out)
}

func toModelInfo(m gatewayModel) pluginapi.ModelInfo {
	display := m.Name
	if display == "" {
		display = m.ID
	}
	owned := m.OwnedBy
	if owned == "" {
		owned = providerName
	}
	info := pluginapi.ModelInfo{
		ID:                         m.ID,
		Object:                     "model",
		OwnedBy:                    owned,
		DisplayName:                display,
		Name:                       m.ID,
		SupportedGenerationMethods: []string{"chat"},
		ContextLength:              m.ContextLength,
		InputTokenLimit:            m.ContextLength,
		OutputTokenLimit:           m.MaxTokens,
		MaxCompletionTokens:        m.MaxTokens,
	}
	inputs := []string{"text"}
	if m.Vision {
		inputs = append(inputs, "image")
	}
	info.SupportedInputModalities = inputs
	info.SupportedOutputModalities = []string{"text"}
	if m.Reasoning && m.Thinking != nil {
		info.Thinking = &pluginapi.ThinkingSupport{
			ZeroAllowed:    m.Thinking.CanDisable,
			DynamicAllowed: true,
			Levels:         m.Thinking.Levels,
		}
	}
	return info
}
