// state.go is the single home for every piece of package-level mutable state.
// Each block documents who reads and writes it, so the concurrency model of the
// plugin is visible in one place instead of being scattered across files. The
// accessors that guard this state live next to their logic (activeConfig in
// config.go, attestationFor in attestation.go, ...); nothing below is read or
// written without going through those accessors.
package main

import (
	"net/http"
	"sync"
)

// --- plugin config (config.go) ---
// Read by every capability via activeConfig(); written by
// applyRegistrationConfig on register/reconfigure.
var (
	cfgMu     sync.RWMutex
	pluginCfg = defaultPluginConfig()
)

// --- device login sessions (auth.go) ---
// state -> *loginSession, written by handleAuthLoginStart and pruned on poll.
var loginSessions sync.Map

// --- DPoP private-key parse cache (dpop.go) ---
// jwk -> *ecdsa.PrivateKey, filled lazily by cachedPrivateKey.
var keyCache sync.Map

// --- client_attestation token cache (attestation.go) ---
// authID -> *attestationEntry, read/written by attestationFor and refresh paths.
var attestationCache sync.Map

// --- per-model reasoning contracts (profiles.go) ---
// model id -> thinkingProfile, fed by fetchModels, read by thinking.go /
// executor.go through thinkingProfileFor.
var thinkingProfiles sync.Map

// --- model catalog cache (models.go) ---
// authID -> modelCacheEntry, read/written by handleModelForAuth.
var modelCache sync.Map

// --- management route base paths (management.go) ---
// Injected by the host at management.register; read by handleManagement and
// renderPanel through loadedManagementBase / loadedResourceBase.
var (
	basePathMu     sync.RWMutex
	managementBase = "/v0/management"
	resourceBase   = "/v0/resource/plugins/" + providerName
)

// --- quota snapshot cache (management.go) ---
// usageCacheMu guards the snapshot; usageCollectMu serializes the /v1/me
// collection pass itself. See cachedUsage / freshUsageSnapshot.
var (
	usageCacheMu   sync.Mutex
	usageCache     *usageSnapshot
	usageCollectMu sync.Mutex
)

// --- shared direct HTTP client (upstream.go) ---
// Built once by sharedHTTPClient; used only when the host bridge is unavailable
// (unit tests / older hosts).
var (
	httpClientOnce sync.Once
	sharedClient   *http.Client
)
