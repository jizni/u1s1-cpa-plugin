// gateway_models.go wraps GET /v1/models: the wire response types and the fetch
// call. The route also hands out the client_attestation token (see
// attestation.go) and feeds the thinking-profile and announcement caches
// (profiles.go, announcement.go).
package main

import (
	"encoding/json"
	"fmt"
)

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
