// u1s1 provider plugin for CLIProxyAPI.
//
// Proxies the u1s1 gateway (https://api.u1s1.io/v1) through CPA:
//   - auth_provider: browser device login (ECDSA P-256 keypair + /auth/device/start|poll),
//     credentials persisted as u1s1-<email>.json in the host auth-dir.
//   - model_provider: dynamic model discovery via GET /v1/models.
//   - executor: OpenAI chat-completions passthrough with per-request DPoP (ES256)
//     signing, the client_attestation token from /v1/models, and the u1s1 client
//     fingerprint headers (x-u1s1-*, x-stainless-*, pi user-agent).
//
// abi.go is the cgo boundary and nothing else: the C preamble, the four
// exported plugin entry points, and the two helpers that touch C symbols
// (writeResponse, hostCall). Everything past this file is pure Go: method
// dispatch lives in dispatch.go, the host bridge envelope protocol in
// bridge.go.
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
	"fmt"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
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

// writeResponse marshals the result into a C-owned buffer the host frees. It
// lives here because it touches C symbols; every dispatch path funnels through
// it.
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

// hostCall makes one call back into the CPA host (host.http.do, host.auth.list,
// ...). It lives here because it touches C symbols; upstream.go and the
// capability handlers call it through this single boundary.
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
