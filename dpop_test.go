package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// TestDPoPProofVerifies checks the full proof: header/payload shape and that the
// P1363 signature verifies against the embedded public JWK.
func TestDPoPProofVerifies(t *testing.T) {
	pair, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}
	token := "u1s1d-" + strings.Repeat("a", 64)
	headers, err := dpopHeaders(token, pair.Private, pair.Public, "post", "https://api.u1s1.io/v1/chat/completions?x=1#frag")
	if err != nil {
		t.Fatalf("dpopHeaders() error = %v", err)
	}
	if headers["authorization"] != "DPoP "+token {
		t.Fatalf("authorization = %q", headers["authorization"])
	}
	parts := strings.Split(headers["dpop"], ".")
	if len(parts) != 3 {
		t.Fatalf("dpop must have 3 segments, got %d", len(parts))
	}

	var hdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK jwk    `json:"jwk"`
	}
	decodeSegment(t, parts[0], &hdr)
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" {
		t.Fatalf("header typ/alg = %q/%q", hdr.Typ, hdr.Alg)
	}
	if hdr.JWK.D != "" {
		t.Fatal("header jwk must not leak the private scalar")
	}
	if hdr.JWK.Kty != "EC" || hdr.JWK.Crv != "P-256" {
		t.Fatalf("header jwk kty/crv = %q/%q", hdr.JWK.Kty, hdr.JWK.Crv)
	}

	var payload struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	decodeSegment(t, parts[1], &payload)
	if payload.HTM != "POST" {
		t.Fatalf("htm = %q, want POST (uppercased)", payload.HTM)
	}
	if payload.HTU != "https://api.u1s1.io/v1/chat/completions" {
		t.Fatalf("htu = %q, query and fragment must be stripped", payload.HTU)
	}
	if strings.Contains(payload.JTI, "-") || len(payload.JTI) != 32 {
		t.Fatalf("jti = %q, want 32 hex chars without dashes", payload.JTI)
	}
	if payload.IAT == 0 {
		t.Fatal("iat must be set")
	}
	sum := sha256.Sum256([]byte(token))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); payload.ATH != want {
		t.Fatalf("ath = %q, want base64url(sha256(token))", payload.ATH)
	}

	// Verify the raw r||s signature against the public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64 (IEEE P1363 r||s)", len(sig))
	}
	priv, err := parsePrivateJWK(pair.Private)
	if err != nil {
		t.Fatalf("parsePrivateJWK() error = %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify against the device public key")
	}
}

func decodeSegment(t *testing.T, segment string, out any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}

func TestDPoPRejectsBadToken(t *testing.T) {
	pair, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}
	if _, err := dpopHeaders("nope-1234", pair.Private, pair.Public, "GET", "https://api.u1s1.io/v1/me"); err == nil {
		t.Fatal("expected an error for a token without the u1s1d- prefix")
	}
}

func TestClientHeadersCarryFingerprint(t *testing.T) {
	// The gateway answers 403 client_integrity_review when these are missing.
	headers := clientHeaders(defaultPluginConfig())
	for _, key := range []string{
		"user-agent", "x-u1s1-client", "x-u1s1-version", "x-u1s1-platform",
		"x-stainless-arch", "x-stainless-lang", "x-stainless-os",
		"x-stainless-package-version", "x-stainless-runtime", "x-stainless-runtime-version",
	} {
		if strings.TrimSpace(headers[key]) == "" {
			t.Fatalf("missing fingerprint header %q", key)
		}
	}
	if !strings.HasPrefix(headers["user-agent"], "pi (") {
		t.Fatalf("user-agent = %q, want the pi client fingerprint", headers["user-agent"])
	}
}

func TestSignedHeadersIncludeAttestation(t *testing.T) {
	sa := testStoredAuth(t)
	headers, err := signedHeaders(sa, "POST", "https://api.u1s1.io/v1/chat/completions", "att-token")
	if err != nil {
		t.Fatalf("signedHeaders() error = %v", err)
	}
	if headers["x-u1s1-attestation"] != "att-token" {
		t.Fatalf("x-u1s1-attestation = %q", headers["x-u1s1-attestation"])
	}
	if !strings.HasPrefix(headers["authorization"], "DPoP ") || headers["dpop"] == "" {
		t.Fatal("signed headers must carry the DPoP proof")
	}

	// An empty attestation token must not produce an empty header.
	headers, err = signedHeaders(sa, "GET", "https://api.u1s1.io/v1/models", "")
	if err != nil {
		t.Fatalf("signedHeaders() error = %v", err)
	}
	if _, ok := headers["x-u1s1-attestation"]; ok {
		t.Fatal("x-u1s1-attestation must be omitted when no token is cached")
	}
}

func testStoredAuth(t *testing.T) storedAuth {
	t.Helper()
	pair, err := generateDeviceKeyPair()
	if err != nil {
		t.Fatalf("generateDeviceKeyPair() error = %v", err)
	}
	return storedAuth{
		Type:             providerName,
		BaseURL:          defaultBaseURL,
		DeviceToken:      "u1s1d-" + strings.Repeat("b", 64),
		DevicePrivateJwk: pair.Private,
		DevicePublicJwk:  pair.Public,
		Email:            "user@example.com",
	}
}
