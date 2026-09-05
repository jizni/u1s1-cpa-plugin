package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	providerName   = "u1s1"
	defaultBaseURL = "https://api.u1s1.io/v1"
	defaultClient  = "terminal"
	// defaultWebOrigin is the website that hosts the dashboard API (/api/me,
	// /api/packages/login-checkin/claim). It is a different host from the
	// gateway (api.u1s1.io) and authenticates with browser session cookies.
	defaultWebOrigin = "https://u1s1.io"
	// Client version reported to the gateway; matches the installed u1s1 CLI
	// (u1s1-cli 1.8.1). The gateway's integrity check tells users to "升级并重新
	// 登录 u1s1", so this must track real CLI releases.
	defaultClientVersion = "1.8.1"
	defaultUserAgent     = "pi (linux 6.12.86+deb13-cloud-amd64; x64)"
	// OpenAI SDK fingerprint echoed by the pi coding agent.
	stainlessPackageVersion = "6.40.0"
	stainlessRuntimeVersion = "v22.23.2"
)

// pluginConfig carries plugin-owned settings from plugins.configs.u1s1.
type pluginConfig struct {
	BaseURL       string `yaml:"base-url"`
	Client        string `yaml:"client"`
	ClientVersion string `yaml:"client-version"`
	UserAgent     string `yaml:"user-agent"`
	// WebOrigin is the website origin whose /api/* routes host the dashboard
	// (login check-in claim). Defaults to https://u1s1.io.
	WebOrigin string `yaml:"web-origin"`
	// CheckinEnabled turns the daily login check-in scheduler on/off.
	CheckinEnabled *bool `yaml:"checkin-enabled"`
	// CheckinTimes is a comma-separated list of Beijing-time HH:MM slots at
	// which the check-in runs (default "08:00,20:00").
	CheckinTimes string `yaml:"checkin-times"`
}

func defaultPluginConfig() pluginConfig {
	return pluginConfig{
		BaseURL:        envOr("U1S1_BASE_URL", defaultBaseURL),
		Client:         envOr("U1S1_CLIENT", defaultClient),
		ClientVersion:  envOr("U1S1_CLIENT_VERSION", defaultClientVersion),
		UserAgent:      envOr("U1S1_USER_AGENT", defaultUserAgent),
		WebOrigin:      envOr("U1S1_WEB_ORIGIN", defaultWebOrigin),
		CheckinEnabled: envBoolPtr("U1S1_CHECKIN_ENABLED", true),
		CheckinTimes:   envOr("U1S1_CHECKIN_TIMES", defaultCheckinTimes),
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// envBoolPtr reads a boolean environment variable; absent or unparseable
// values fall back to the default. A pointer keeps the zero value (false)
// distinguishable from "unset" for the YAML merge path.
func envBoolPtr(key string, fallback bool) *bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return boolPtr(fallback)
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return boolPtr(fallback)
	}
	return boolPtr(parsed)
}

// apiOrigin strips the trailing /v1 from the base URL; auth routes hang off the origin root.
func (c pluginConfig) apiOrigin() string {
	trimmed := strings.TrimSuffix(strings.TrimSuffix(c.BaseURL, "/"), "/")
	if strings.HasSuffix(trimmed, "/v1") {
		trimmed = strings.TrimSuffix(trimmed, "/v1")
	}
	return trimmed
}

// applyRegistrationConfig merges plugins.configs.u1s1 YAML into the active config.
func applyRegistrationConfig(configYAML []byte) {
	if len(configYAML) == 0 {
		return
	}
	var raw map[string]any
	if err := yaml.Unmarshal(configYAML, &raw); err != nil {
		return
	}
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if v, ok := raw["base-url"].(string); ok && strings.TrimSpace(v) != "" {
		pluginCfg.BaseURL = strings.TrimSpace(v)
	}
	if v, ok := raw["client"].(string); ok && strings.TrimSpace(v) != "" {
		pluginCfg.Client = strings.TrimSpace(v)
	}
	if v, ok := raw["client-version"].(string); ok && strings.TrimSpace(v) != "" {
		pluginCfg.ClientVersion = strings.TrimSpace(v)
	}
	if v, ok := raw["user-agent"].(string); ok && strings.TrimSpace(v) != "" {
		pluginCfg.UserAgent = strings.TrimSpace(v)
	}
	if v, ok := raw["web-origin"].(string); ok && strings.TrimSpace(v) != "" {
		pluginCfg.WebOrigin = strings.TrimSpace(v)
	}
	if v, ok := raw["checkin-enabled"].(bool); ok {
		pluginCfg.CheckinEnabled = boolPtr(v)
	}
	if v, ok := raw["checkin-times"].(string); ok && strings.TrimSpace(v) != "" {
		pluginCfg.CheckinTimes = strings.TrimSpace(v)
	}
}

func activeConfig() pluginConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return pluginCfg
}

// webOrigin returns the website origin (for dashboard API routes), defaulting
// to https://u1s1.io when the config leaves it empty.
func (c pluginConfig) webOrigin() string {
	if strings.TrimSpace(c.WebOrigin) != "" {
		return strings.TrimSuffix(strings.TrimSpace(c.WebOrigin), "/")
	}
	return defaultWebOrigin
}

// pluginVersion is the plugin's own release version, reported in the
// registration metadata. It is injected at build time via
//
//	-ldflags "-X main.pluginVersion=$(VERSION)"
//
// (see Makefile / .github/workflows/release.yml). "dev" marks builds without
// an injected version, e.g. plain `go build` or the CI test build.
var pluginVersion = "dev"

func registrationResponse() registration {
	return registration{
		SchemaVersion: 1,
		Metadata: pluginapi.Metadata{
			Name:             providerName,
			Version:          pluginVersion,
			Author:           "jizni",
			GitHubRepository: "https://github.com/jizni/u1s1-cpa-plugin",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "base-url", Type: pluginapi.ConfigFieldTypeString, Description: "u1s1 gateway base URL including /v1 (default https://api.u1s1.io/v1)."},
				{Name: "client", Type: pluginapi.ConfigFieldTypeString, Description: "Value of the x-u1s1-client header (default terminal)."},
				{Name: "client-version", Type: pluginapi.ConfigFieldTypeString, Description: "Value of the x-u1s1-version header (default 1.8.1)."},
				{Name: "user-agent", Type: pluginapi.ConfigFieldTypeString, Description: "User-Agent sent upstream; the gateway checks the pi client fingerprint."},
				{Name: "web-origin", Type: pluginapi.ConfigFieldTypeString, Description: "Website origin hosting the dashboard API (default https://u1s1.io)."},
				{Name: "checkin-enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Run the daily login check-in scheduler (default true)."},
				{Name: "checkin-times", Type: pluginapi.ConfigFieldTypeString, Description: "Beijing-time HH:MM slots for the check-in, comma-separated (default 08:00,20:00)."},
			},
		},
		Capabilities: registrationCapability{
			ModelProvider:         true,
			AuthProvider:          true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeOAuth,
			ExecutorInputFormats:  []string{"chat-completions"},
			ExecutorOutputFormats: []string{"chat-completions"},
			ManagementAPI:         true,
		},
	}
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	ModelRegistrar                bool                         `json:"model_registrar"`
	ModelProvider                 bool                         `json:"model_provider"`
	AuthProvider                  bool                         `json:"auth_provider"`
	FrontendAuthProvider          bool                         `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive bool                         `json:"frontend_auth_provider_exclusive"`
	Scheduler                     bool                         `json:"scheduler"`
	ModelRouter                   bool                         `json:"model_router"`
	Executor                      bool                         `json:"executor"`
	ExecutorModelScope            pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats          []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats         []string                     `json:"executor_output_formats,omitempty"`
	RequestTranslator             bool                         `json:"request_translator"`
	RequestNormalizer             bool                         `json:"request_normalizer"`
	RequestInterceptor            bool                         `json:"request_interceptor"`
	RequestLifecyclePlugin        bool                         `json:"request_lifecycle_plugin"`
	ResponseTranslator            bool                         `json:"response_translator"`
	ResponseBeforeTranslator      bool                         `json:"response_before_translator"`
	ResponseAfterTranslator       bool                         `json:"response_after_translator"`
	ResponseInterceptor           bool                         `json:"response_interceptor"`
	StreamChunkInterceptor        bool                         `json:"response_stream_interceptor"`
	ThinkingApplier               bool                         `json:"thinking_applier"`
	UsagePlugin                   bool                         `json:"usage_plugin"`
	CommandLinePlugin             bool                         `json:"command_line_plugin"`
	ManagementAPI                 bool                         `json:"management_api"`
}
