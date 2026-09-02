// thinking.go resolves the host's model thinking suffix.
//
// The plugin advertises per-model reasoning levels in model.for_auth, so clients
// may request "u1s1/deepseek-v4-flash(high)". The host strips only the auth
// prefix (rewriteModelForAuth) and leaves the suffix on req.Model: every native
// CPA executor calls thinking.ParseSuffix() itself. Forwarding the suffixed id
// verbatim makes the gateway answer 400 unknown model, so the plugin has to
// split it and translate the level into the upstream request fields the official
// CLI sends for this model's request_format.
package main

import (
	"strconv"
	"strings"
)

// parseModelSuffix splits "model(raw)" into its parts, mirroring
// internal/thinking.ParseSuffix so host and plugin agree on the boundary.
func parseModelSuffix(model string) (base string, rawSuffix string, hasSuffix bool) {
	model = strings.TrimSpace(model)
	open := strings.LastIndex(model, "(")
	if open < 0 || !strings.HasSuffix(model, ")") {
		return model, "", false
	}
	return model[:open], model[open+1 : len(model)-1], true
}

// canonicalThinkingLevels are the effort names CPA and the u1s1 CLI share.
var canonicalThinkingLevels = map[string]struct{}{
	"off": {}, "none": {}, "minimal": {}, "low": {}, "medium": {}, "high": {}, "xhigh": {}, "max": {},
}

// thinkingIntent is the request-shaping decision derived from one model suffix.
type thinkingIntent struct {
	// Level is the canonical effort name, "" when the suffix carried none.
	Level string
	// Disable is true when the suffix asks for thinking to be turned off.
	Disable bool
	// Budget is a numeric token budget suffix, e.g. "(8192)". The u1s1 gateway
	// has no budget field, so it only serves to enable/disable thinking.
	Budget int
	// HasBudget distinguishes "(0)" from a missing budget.
	HasBudget bool
}

// parseThinkingSuffix interprets a raw suffix. Unrecognized suffixes yield
// ok=false so the caller strips them without inventing request fields.
func parseThinkingSuffix(raw string) (thinkingIntent, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return thinkingIntent{}, false
	}
	if budget, err := strconv.Atoi(raw); err == nil {
		if budget < 0 {
			// -1 means "dynamic" upstream of here; u1s1 has no budget field, so
			// treat any negative value as "let the model decide" (enabled).
			return thinkingIntent{HasBudget: true, Budget: budget}, true
		}
		return thinkingIntent{HasBudget: true, Budget: budget, Disable: budget == 0}, true
	}
	if _, ok := canonicalThinkingLevels[raw]; !ok {
		return thinkingIntent{}, false
	}
	if raw == "off" || raw == "none" {
		return thinkingIntent{Level: raw, Disable: true}, true
	}
	return thinkingIntent{Level: raw}, true
}

// applyThinking writes the upstream reasoning fields for one request, following
// the branch the official pi client uses for this model's request_format
// (node_modules/@earendil-works/pi-coding-agent openai-completions):
//
//	deepseek: thinking:{type:enabled|disabled} + reasoning_effort
//	qwen:     enable_thinking:bool             + reasoning_effort
//	openai:   reasoning_effort only
//
// A model with no cached profile gets nothing: guessing fields on an unknown
// model is what produces 400s.
func applyThinking(obj map[string]any, model string, intent thinkingIntent, hasIntent bool) {
	profile, known := thinkingProfileFor(model)
	if !known {
		// Without a profile the only safe action is to drop client-supplied
		// reasoning fields that the gateway may not accept for this model.
		return
	}

	// Resolve the effort the gateway should see.
	level := ""
	enabled := true
	switch {
	case hasIntent && intent.Disable:
		enabled = false
	case hasIntent && intent.Level != "" && profile.supportsLevel(intent.Level):
		level = profile.upstreamLevel(intent.Level)
	case hasIntent && intent.Level != "":
		// Level not offered for this model (e.g. "(medium)" on a model that only
		// has off/low/high/max): fall back to the model default rather than
		// sending a value the gateway rejects.
		level = profile.upstreamLevel(profile.DefaultLevel)
	case hasIntent && intent.HasBudget:
		// Numeric budget: u1s1 has no budget field, so a positive budget just
		// means "thinking on" at the model's default level.
		level = profile.upstreamLevel(profile.DefaultLevel)
	default:
		// No suffix: respect an explicit client reasoning_effort when the model
		// supports it, otherwise leave the body untouched.
		if raw, ok := obj["reasoning_effort"].(string); ok && strings.TrimSpace(raw) != "" {
			if profile.supportsLevel(raw) {
				level = profile.upstreamLevel(raw)
			} else {
				level = profile.upstreamLevel(profile.DefaultLevel)
			}
		} else {
			return
		}
	}

	if !enabled && !profile.CanDisable {
		// The model cannot turn thinking off; use its lowest offered level
		// instead of sending a disable the gateway would reject.
		enabled = true
		level = profile.upstreamLevel(lowestLevel(profile))
	}

	switch profile.RequestFormat {
	case "deepseek":
		if enabled {
			obj["thinking"] = map[string]any{"type": "enabled"}
			obj["reasoning_effort"] = level
		} else {
			obj["thinking"] = map[string]any{"type": "disabled"}
			delete(obj, "reasoning_effort")
		}
	case "qwen":
		obj["enable_thinking"] = enabled
		if enabled {
			obj["reasoning_effort"] = level
		} else {
			delete(obj, "reasoning_effort")
		}
	default: // "openai" and anything else advertised: effort field only.
		if enabled {
			obj["reasoning_effort"] = level
		} else {
			delete(obj, "reasoning_effort")
		}
	}
}

// lowestLevel returns the least-effort level the model offers, skipping the
// off/none entries (which are unavailable when CanDisable is false).
func lowestLevel(profile thinkingProfile) string {
	order := []string{"minimal", "low", "medium", "high", "xhigh", "max"}
	for _, candidate := range order {
		if profile.supportsLevel(candidate) {
			return candidate
		}
	}
	if profile.DefaultLevel != "" {
		return profile.DefaultLevel
	}
	return "low"
}
