// models.go implements the model_provider capability: model.for_auth asks the
// gateway for the live catalog (GET /v1/models) for a given credential and maps
// it to host ModelInfo records.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
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
	baseBlended := baseModelBlendedPrice(resp.Data)
	for _, m := range resp.Data {
		if strings.TrimSpace(m.ID) == "" {
			continue
		}
		models = append(models, toModelInfo(m, modelDescription(m, baseBlended)))
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

func toModelInfo(m gatewayModel, description string) pluginapi.ModelInfo {
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
		Description:                description,
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
	// Thinking metadata alone marks a reasoning model, as in the CLI's
	// apiModelToDef (reasoning = m.reasoning || thinking !== undefined): the
	// gateway may ship levels for a model whose reasoning flag is false.
	if m.hasThinking() {
		info.Thinking = &pluginapi.ThinkingSupport{
			ZeroAllowed:    m.Thinking.CanDisable,
			DynamicAllowed: true,
			Levels:         m.Thinking.Levels,
		}
	}
	return info
}

// defaultFreeModelID is the gateway's own reference model for quota accounting
// (/v1/me reports daily_free_model), and the CLI's built-in default. Price
// multiples in model notes are relative to it.
const defaultFreeModelID = "deepseek-v4-flash"

// baseModelBlendedPrice returns the blended price the "N times the default
// model" note compares against: the default free model, else the first
// free-package-eligible one, mirroring the CLI's deriveModelNote base pick.
func baseModelBlendedPrice(models []gatewayModel) float64 {
	var fallback *modelPrice
	for i := range models {
		if models[i].ID == defaultFreeModelID {
			return models[i].Price.blended()
		}
		if fallback == nil && models[i].freeEligible() {
			fallback = models[i].Price
		}
	}
	return fallback.blended()
}

// modelDescription is the one-line note clients see next to the model id. It
// mirrors what the official CLI puts in its model picker: whether the free quota
// package pays for this model, how much dearer it is than the default, and the
// current price — the three things that decide whether a request costs money.
func modelDescription(m gatewayModel, baseBlended float64) string {
	parts := make([]string, 0, 2)
	if note := freePackageNote(m, baseBlended); note != "" {
		parts = append(parts, note)
	}
	if note := priceNote(m); note != "" {
		parts = append(parts, note)
	}
	return strings.Join(parts, " · ")
}

// freePackageNote renders the free-package coverage of one model. An absent
// free_package_eligible field (older gateway) yields no note at all rather than
// a guess in either direction.
func freePackageNote(m gatewayModel, baseBlended float64) string {
	if m.FreePackageEligible == nil {
		return ""
	}
	if *m.FreePackageEligible {
		return "免费用量包可抵扣"
	}
	if baseBlended > 0 {
		if mult := int(math.Round(m.Price.blended() / baseBlended)); mult >= 2 {
			return fmt.Sprintf("不走免费包 · 费用约为默认模型 %d 倍", mult)
		}
	}
	return "不走免费包，用余额或全模型包"
}

// priceNote formats USD per million tokens, naming the active band for models
// that switch between peak and off-peak rates during Beijing business hours.
func priceNote(m gatewayModel) string {
	if m.Price == nil {
		return ""
	}
	note := "$" + formatUSD(m.Price.Input) + "/$" + formatUSD(m.Price.Output) + " 每百万 token"
	switch {
	case m.PriceBands == nil:
		return note
	case m.PriceBands.Current == "peak":
		return note + "（峰/闲价 · 当前峰时价）"
	case m.PriceBands.Current == "off_peak":
		return note + "（峰/闲价 · 当前闲时价）"
	default:
		return note + "（峰/闲价）"
	}
}

// formatUSD prints a price without trailing zeros: 0.22, 0.075, 0.
func formatUSD(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
