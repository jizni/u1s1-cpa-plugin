// thinking_test.go covers the thinking suffix handling: splitting "model(raw)"
// off the request model id and translating the level into the upstream fields
// for the model's request_format.
package main

import (
	"encoding/json"
	"testing"
)

func seedThinkingProfile(t *testing.T, id, requestFormat string, levels []string, canDisable bool, levelMap map[string]string) {
	t.Helper()
	storeThinkingProfile(gatewayModel{
		ID:        id,
		Reasoning: true,
		Thinking: &modelThinking{
			Levels:        levels,
			DefaultLevel:  "high",
			CanDisable:    canDisable,
			LevelMap:      levelMap,
			RequestFormat: requestFormat,
		},
	})
	t.Cleanup(func() { thinkingProfiles.Delete(id) })
}

// The host strips only the auth prefix; the suffix stays on req.Model. Sending
// "deepseek-v4-flash(high)" upstream is a 400 unknown model.
func TestPrepareBodyStripsThinkingSuffix(t *testing.T) {
	seedThinkingProfile(t, "deepseek-v4-flash", "deepseek",
		[]string{"off", "low", "high", "max"}, true,
		map[string]string{"off": "none", "low": "low", "high": "high", "max": "max"})

	body := prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(high)", false)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v, want the suffix stripped", obj["model"])
	}
	thinking, ok := obj["thinking"].(map[string]any)
	if !ok || thinking["type"] != "enabled" {
		t.Fatalf("thinking = %v, want {type:enabled} for the deepseek request format", obj["thinking"])
	}
	if obj["reasoning_effort"] != "high" {
		t.Fatalf("reasoning_effort = %v", obj["reasoning_effort"])
	}
}

func TestPrepareBodyThinkingRequestFormats(t *testing.T) {
	seedThinkingProfile(t, "qwen3.8-flash", "qwen",
		[]string{"off", "low", "medium", "xhigh"}, true,
		map[string]string{"off": "none", "low": "low", "medium": "medium", "xhigh": "xhigh"})
	seedThinkingProfile(t, "glm-5.3-flash", "openai",
		[]string{"low", "high", "max"}, false,
		map[string]string{"low": "low", "high": "high", "max": "max"})

	// qwen: enable_thinking + reasoning_effort.
	var qwen map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "qwen3.8-flash(medium)", false), &qwen)
	if qwen["enable_thinking"] != true || qwen["reasoning_effort"] != "medium" {
		t.Fatalf("qwen body = %v", qwen)
	}
	if _, ok := qwen["thinking"]; ok {
		t.Fatal("qwen format must not carry the deepseek thinking object")
	}

	// qwen off: enable_thinking false and no effort.
	var qwenOff map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "qwen3.8-flash(off)", false), &qwenOff)
	if qwenOff["enable_thinking"] != false {
		t.Fatalf("qwen off body = %v", qwenOff)
	}
	if _, ok := qwenOff["reasoning_effort"]; ok {
		t.Fatal("a disabled request must not carry reasoning_effort")
	}

	// openai: effort only.
	var glm map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "glm-5.3-flash(max)", false), &glm)
	if glm["reasoning_effort"] != "max" {
		t.Fatalf("openai-format body = %v", glm)
	}
	for _, key := range []string{"thinking", "enable_thinking"} {
		if _, ok := glm[key]; ok {
			t.Fatalf("openai format must not carry %q", key)
		}
	}

	// A model that cannot disable thinking must get its lowest level, not a
	// disable the gateway would reject.
	var glmOff map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "glm-5.3-flash(off)", false), &glmOff)
	if glmOff["reasoning_effort"] != "low" {
		t.Fatalf("non-disableable model off -> %v, want the lowest level", glmOff["reasoning_effort"])
	}
}

// A level the model does not advertise must fall back to its default instead of
// being forwarded verbatim.
func TestPrepareBodyUnsupportedLevelFallsBackToDefault(t *testing.T) {
	seedThinkingProfile(t, "deepseek-v4-flash", "deepseek",
		[]string{"off", "low", "high", "max"}, true,
		map[string]string{"off": "none", "low": "low", "high": "high", "max": "max"})

	var obj map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(medium)", false), &obj)
	if obj["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v", obj["model"])
	}
	if obj["reasoning_effort"] != "high" {
		t.Fatalf("reasoning_effort = %v, want the model default", obj["reasoning_effort"])
	}
}

// A numeric budget suffix has no u1s1 equivalent: 0 disables, anything else runs
// at the default level. Either way the suffix must leave the model id.
func TestPrepareBodyNumericBudgetSuffix(t *testing.T) {
	seedThinkingProfile(t, "deepseek-v4-flash", "deepseek",
		[]string{"off", "low", "high", "max"}, true,
		map[string]string{"off": "none", "low": "low", "high": "high", "max": "max"})

	var enabled map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(8192)", false), &enabled)
	if enabled["model"] != "deepseek-v4-flash" {
		t.Fatalf("model = %v", enabled["model"])
	}
	if thinking, _ := enabled["thinking"].(map[string]any); thinking["type"] != "enabled" {
		t.Fatalf("positive budget -> %v, want thinking enabled", enabled["thinking"])
	}

	var disabled map[string]any
	_ = json.Unmarshal(prepareBody([]byte(`{"messages":[]}`), nil, "deepseek-v4-flash(0)", false), &disabled)
	if thinking, _ := disabled["thinking"].(map[string]any); thinking["type"] != "disabled" {
		t.Fatalf("zero budget -> %v, want thinking disabled", disabled["thinking"])
	}
}

// A model with no cached reasoning profile must be left alone: inventing fields
// for an unknown model is what produces 400s.
func TestPrepareBodyLeavesUnknownModelThinkingAlone(t *testing.T) {
	body := prepareBody([]byte(`{"messages":[]}`), nil, "mystery-model(high)", false)
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	if obj["model"] != "mystery-model" {
		t.Fatalf("model = %v, the suffix must still be stripped", obj["model"])
	}
	for _, key := range []string{"thinking", "enable_thinking", "reasoning_effort"} {
		if _, ok := obj[key]; ok {
			t.Fatalf("unknown model must not get %q", key)
		}
	}
}

// A model id that merely contains parentheses is not a thinking suffix.
func TestParseModelSuffix(t *testing.T) {
	for _, tc := range []struct {
		in     string
		base   string
		suffix string
		has    bool
	}{
		{"deepseek-v4-flash", "deepseek-v4-flash", "", false},
		{"deepseek-v4-flash(high)", "deepseek-v4-flash", "high", true},
		{"model(8192)", "model", "8192", true},
		{"model(unclosed", "model(unclosed", "", false},
	} {
		base, suffix, has := parseModelSuffix(tc.in)
		if base != tc.base || suffix != tc.suffix || has != tc.has {
			t.Fatalf("parseModelSuffix(%q) = (%q,%q,%v)", tc.in, base, suffix, has)
		}
	}
}
