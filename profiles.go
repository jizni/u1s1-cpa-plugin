// profiles.go caches the per-model reasoning contract (thinkingProfile) that
// /v1/models advertises. The executor needs it to translate a host thinking
// suffix like "(high)" into the upstream request fields, and the suffix arrives
// on a chat request that carries no model table of its own. The cache itself
// lives in state.go.
package main

import "strings"

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
