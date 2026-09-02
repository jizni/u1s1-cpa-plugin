// models_test.go covers the model_provider capability: /v1/models fetching, the
// mapping to host ModelInfo records, the pricing/free-package descriptions, and
// the thinking-profile cache the models route feeds.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// fetchModels is the one route every credential path goes through, so it has to
// be what populates the reasoning profiles a chat request later needs.
func TestFetchModelsCachesThinkingProfiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data": []map[string]any{{
				"id": "profiled-model", "object": "model", "reasoning": true,
				"thinking": map[string]any{
					"levels": []string{"off", "high"}, "default_level": "high",
					"can_disable": true, "request_format": "deepseek",
					"level_map": map[string]string{"off": "none", "high": "high"},
				},
			}},
		})
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { thinkingProfiles.Delete("profiled-model") })

	if _, ok := thinkingProfileFor("profiled-model"); ok {
		t.Fatal("profile must not exist before the models call")
	}
	if _, err := fetchModels(storedAuthFor(t, srv.URL), "", ""); err != nil {
		t.Fatalf("fetchModels() error = %v", err)
	}
	profile, ok := thinkingProfileFor("profiled-model")
	if !ok {
		t.Fatal("fetchModels must cache the reasoning profile")
	}
	if profile.RequestFormat != "deepseek" || profile.DefaultLevel != "high" || !profile.CanDisable {
		t.Fatalf("profile = %+v", profile)
	}
}

// model.for_auth must not hand back a recomputed FileName: it would rename
// credentials imported under a different name. The host backfills an empty
// FileName from the record.
func TestModelForAuthUpdateLeavesFileNameToHost(t *testing.T) {
	srv := httptest.NewServer(modelsHandler("att-models", 7*24*3600))
	t.Cleanup(srv.Close)

	sa := storedAuthFor(t, srv.URL)
	storage, _ := json.Marshal(sa)
	authID := "u1s1-imported-models"
	payload, _ := json.Marshal(rpcAuthModelRequest{AuthModelRequest: pluginapi.AuthModelRequest{
		AuthID:       authID,
		AuthProvider: providerName,
		StorageJSON:  storage,
	}})
	raw, err := handleMethod(pluginabi.MethodModelForAuth, payload)
	if err != nil {
		t.Fatalf("model.for_auth error = %v", err)
	}
	t.Cleanup(func() {
		attestationCache.Delete(authID)
		modelCache.Delete(authID)
	})

	var resp pluginapi.ModelResponse
	unwrapResult(t, raw, &resp)
	if len(resp.Models) != 1 || resp.Models[0].ID != "deepseek-v4-flash" {
		t.Fatalf("models = %+v", resp.Models)
	}
	if resp.AuthUpdate.FileName != "" {
		t.Fatalf("auth update file name = %q, want it left to the host", resp.AuthUpdate.FileName)
	}
	if resp.AuthUpdate.ID != authID {
		t.Fatalf("auth update id = %q", resp.AuthUpdate.ID)
	}
}

// ---------------------------------------------------------------------------
// model descriptions (pricing + free-package notes)
// ---------------------------------------------------------------------------

// The gateway's model list is the only place free-package coverage and price
// live. Without them a client picking "the cheap model" has to guess, and on
// u1s1 that guess is the difference between free and paid, so model.for_auth
// mirrors the note the official CLI shows in its picker.
func TestModelDescriptionMirrorsCLINote(t *testing.T) {
	price := func(in, out float64) *modelPrice { return &modelPrice{Input: in, Output: out} }
	yes, no := true, false
	catalogue := []gatewayModel{
		{ID: defaultFreeModelID, FreePackageEligible: &yes, Price: price(0.22, 0.66)},
		{ID: "deepseek-v4-pro", FreePackageEligible: &no, Price: price(0.66, 1.98)},
		{ID: "slightly-dearer", FreePackageEligible: &no, Price: price(0.24, 0.7)},
		{ID: "legacy-gateway-model", Price: price(1, 1)},
	}
	base := baseModelBlendedPrice(catalogue)
	if base != 0.44 {
		t.Fatalf("base blended price = %v, want the default free model's", base)
	}

	free := modelDescription(catalogue[0], base)
	if !strings.Contains(free, "免费用量包可抵扣") || !strings.Contains(free, "$0.22/$0.66") {
		t.Fatalf("free model description = %q", free)
	}
	// 3x the default: the multiple is what stops a user from casually burning
	// paid balance on the Pro model.
	if paid := modelDescription(catalogue[1], base); !strings.Contains(paid, "3 倍") {
		t.Fatalf("paid model description = %q, want the price multiple", paid)
	}
	// Under 2x the multiple is noise; the coverage warning still has to show.
	near := modelDescription(catalogue[2], base)
	if strings.Contains(near, "倍") || !strings.Contains(near, "不走免费包") {
		t.Fatalf("near-price model description = %q", near)
	}
	// An older gateway omits free_package_eligible: no coverage claim either way.
	legacy := modelDescription(catalogue[3], base)
	if strings.Contains(legacy, "免费包") {
		t.Fatalf("unknown coverage must not be described as covered or not: %q", legacy)
	}
	if !strings.Contains(legacy, "每百万 token") {
		t.Fatalf("legacy model description = %q, want the price kept", legacy)
	}
}

// Peak/off-peak models bill at double during Beijing business hours, so the
// note has to name the band that is actually in effect.
func TestModelDescriptionNamesActivePriceBand(t *testing.T) {
	m := gatewayModel{
		ID:         "deepseek-v4-flash",
		Price:      &modelPrice{Input: 0.44, Output: 1.32},
		PriceBands: &modelPriceBands{Current: "peak", Peak: &bandPrice{Input: 0.44, Output: 1.32}, OffPeak: &bandPrice{Input: 0.22, Output: 0.66}},
	}
	if got := modelDescription(m, 0); !strings.Contains(got, "当前峰时价") {
		t.Fatalf("description = %q, want the active band named", got)
	}
	m.PriceBands.Current = "off_peak"
	if got := modelDescription(m, 0); !strings.Contains(got, "当前闲时价") {
		t.Fatalf("description = %q, want the off-peak band named", got)
	}
	// A model without bands must not grow a band label.
	flat := gatewayModel{ID: "qwen3.8-flash", Price: &modelPrice{Input: 0.16, Output: 0.47}}
	if got := modelDescription(flat, 0); strings.Contains(got, "峰") {
		t.Fatalf("flat-priced model description = %q", got)
	}
	// Prices must not gain trailing zeros: the CLI prints 0.075, not 0.08.
	if got := priceNote(gatewayModel{Price: &modelPrice{Input: 0.075, Output: 0.25}}); !strings.Contains(got, "$0.075/$0.25") {
		t.Fatalf("price note = %q", got)
	}
}
