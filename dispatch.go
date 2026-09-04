// dispatch.go routes incoming host method calls to the capability handlers and
// wraps them with the error-envelope and panic-barrier contracts. The cgo entry
// points live in abi.go; envelopes and the host bridge protocol in bridge.go.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// dispatchMethod wraps handleMethod with the error envelope contract. Handler
// errors can embed upstream messages, so they pass through redactSecrets like
// every other path that may reach logs or clients.
func dispatchMethod(method string, request []byte) ([]byte, int) {
	return guardDispatchPanic(method, func() ([]byte, int) {
		result, errHandle := handleMethod(method, request)
		if errHandle != nil {
			return errorEnvelope("plugin_error", redactSecrets(errHandle.Error())), 1
		}
		return result, 0
	})
}

// guardDispatchPanic turns a panic into a plugin_panic envelope.
//
// This is load-bearing, not defensive boilerplate: dispatchMethod runs directly
// under a cgo entry point, so a panic that unwinds past it crosses the C ABI
// boundary and takes the whole CPA process down instead of becoming an error the
// host can fuse the plugin on.
func guardDispatchPanic(method string, fn func() ([]byte, int)) (out []byte, rc int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			out = errorEnvelope("plugin_panic", redactSecrets(fmt.Sprintf("u1s1 plugin panic in %s: %v", method, recovered)))
			rc = 1
		}
	}()
	return fn()
}

// registrationRequest mirrors internal/pluginhost/rpc_schema.go.
type registrationRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		var regReq registrationRequest
		if len(request) > 0 {
			_ = json.Unmarshal(request, &regReq)
		}
		applyRegistrationConfig(regReq.ConfigYAML)
		startCheckinScheduler()
		return okEnvelope(registrationResponse())

	case pluginabi.MethodModelStatic:
		return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: nil})

	case pluginabi.MethodModelForAuth:
		return handleModelForAuth(request)

	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier:
		return okEnvelope(identifierResponse{Identifier: providerName})

	case pluginabi.MethodAuthParse:
		return handleAuthParse(request)

	case pluginabi.MethodAuthLoginStart:
		return handleAuthLoginStart(request)

	case pluginabi.MethodAuthLoginPoll:
		return handleAuthLoginPoll(request)

	case pluginabi.MethodAuthRefresh:
		return handleAuthRefresh(request)

	case pluginabi.MethodExecutorExecute:
		return handleExecExecute(request)

	case pluginabi.MethodExecutorExecuteStream:
		return handleExecStream(request)

	case pluginabi.MethodExecutorCountTokens:
		return handleCountTokens(request)

	case pluginabi.MethodManagementRegister:
		// Cache the host-injected prefixes so handleManagement does not hardcode
		// /v0/management or the resource base.
		var regReq pluginapi.ManagementRegistrationRequest
		if err := json.Unmarshal(request, &regReq); err == nil {
			setManagementBasePath(regReq.BasePath)
			setResourceBasePath(regReq.ResourceBasePath)
		}
		return okEnvelope(managementRegistration())

	case pluginabi.MethodManagementHandle:
		return handleManagement(request)

	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}
