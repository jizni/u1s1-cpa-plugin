// u1s1 provider plugin for CLIProxyAPI.
//
// Proxies the u1s1 gateway (https://api.u1s1.io/v1) through CPA:
//   - auth_provider: browser device login (ECDSA P-256 keypair + /auth/device/start|poll),
//     credentials persisted as u1s1-<email>.json in the host auth-dir.
//   - model_provider: dynamic model discovery via GET /v1/models.
//   - executor: OpenAI chat-completions passthrough with per-request DPoP (ES256)
//     signing, the client_attestation token from /v1/models, and the u1s1 client
//     fingerprint headers (x-u1s1-*, x-stainless-*, pi user-agent).
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const abiVersion = pluginabi.ABIVersion

var hostAPI *C.cliproxy_host_api

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	hostAPI = host
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var raw []byte
	if requestLen > 0 && request != nil {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	out, rc := dispatchMethod(C.GoString(method), raw)
	writeResponse(response, out)
	return C.int(rc)
}

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

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = len
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	// Intentionally a no-op. The host calls this on its own exit path, after the
	// host Go runtime has begun tearing down, and dlclose()es this library right
	// afterwards. Touching Go runtime state here (sync.Map ranges, mutexes,
	// channel closes) risks a SIGSEGV inside cgo on every restart. Nothing the
	// plugin holds outlives the process: login sessions are in-memory only and
	// the OS reclaims everything else.
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

// -----------------------------------------------------------------------------
// envelopes
// -----------------------------------------------------------------------------

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

func okEnvelope(v any) ([]byte, error) {
	result, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: result})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func errorEnvelopeWithStatus(code, message string, status int) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message, HTTPStatus: status}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func hostCall(method string, payload []byte) ([]byte, error) {
	if hostAPI == nil {
		return nil, fmt.Errorf("host bridge unavailable")
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var req *C.uint8_t
	if len(payload) > 0 {
		req = (*C.uint8_t)(C.CBytes(payload))
		defer C.free(unsafe.Pointer(req))
	}
	var response C.cliproxy_buffer
	rc := C.call_host_api(cMethod, req, C.size_t(len(payload)), &response)
	if rc != 0 || response.ptr == nil {
		return nil, fmt.Errorf("%s: host call failed (rc=%d)", method, rc)
	}
	out := C.GoBytes(response.ptr, C.int(response.len))
	C.free_host_buffer(response.ptr, response.len)
	return out, nil
}

func hostBridgeUnwrap(raw []byte, method string) (json.RawMessage, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: decode envelope: %w", method, err)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: host error %s: %s", method, env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("%s: host returned not-ok", method)
	}
	return env.Result, nil
}
