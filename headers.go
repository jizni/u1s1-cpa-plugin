// headers.go builds the request header set the gateway fingerprint check
// requires: the clientHeaders identity block plus, for authenticated routes,
// the DPoP proof and the cached attestation token.
package main

import "strings"

// clientHeaders reproduces the fingerprint the gateway expects from a genuine
// u1s1 client. The gateway rejects requests that only carry a valid DPoP proof
// with 403 client_integrity_review, so these headers are mandatory, not cosmetic.
func clientHeaders(cfg pluginConfig) map[string]string {
	return map[string]string{
		"accept":                      "application/json",
		"content-type":                "application/json",
		"user-agent":                  cfg.UserAgent,
		"x-u1s1-client":               cfg.Client,
		"x-u1s1-version":              cfg.ClientVersion,
		"x-u1s1-platform":             "linux-x64",
		"x-stainless-arch":            "x64",
		"x-stainless-lang":            "js",
		"x-stainless-os":              "Linux",
		"x-stainless-package-version": stainlessPackageVersion,
		"x-stainless-retry-count":     "0",
		"x-stainless-runtime":         "node",
		"x-stainless-runtime-version": stainlessRuntimeVersion,
		"x-stainless-timeout":         "300",
	}
}

// signedHeaders returns the full header set for one authenticated request:
// client fingerprint + fresh DPoP proof + cached attestation token.
func signedHeaders(sa storedAuth, method, url string, attestation string) (map[string]string, error) {
	cfg := activeConfig()
	headers := clientHeaders(cfg)
	proof, err := dpopHeaders(sa.DeviceToken, sa.DevicePrivateJwk, sa.DevicePublicJwk, method, url)
	if err != nil {
		return nil, err
	}
	for k, v := range proof {
		headers[k] = v
	}
	if strings.TrimSpace(attestation) != "" {
		headers["x-u1s1-attestation"] = attestation
	}
	return headers, nil
}
