// dpop.go implements the u1s1 sender-constrained device credential:
// ECDSA P-256 keypairs in JWK form and per-request DPoP (ES256) proofs.
// Signature format is IEEE P1363 (raw r||s, 64 bytes) to match WebCrypto,
// which is what the official u1s1 CLI uses.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

// jwk is the subset of the JSON Web Key format used by u1s1.
type jwk struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	D      string   `json:"d,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Ext    *bool    `json:"ext,omitempty"`
}

type deviceKeyPair struct {
	Private jwk
	Public  jwk
}

var b64url = base64.RawURLEncoding

// parsePrivateJWK converts an EC P-256 private JWK into an ecdsa.PrivateKey.
func parsePrivateJWK(k jwk) (*ecdsa.PrivateKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" || k.D == "" {
		return nil, errors.New("u1s1: private jwk is not EC P-256 with d")
	}
	key, err := parsePrivateParts(k.X, k.Y, k.D)
	if err != nil {
		return nil, err
	}
	// The DPoP header publishes this public point next to proofs signed with the
	// private scalar; a mismatched pair can never verify upstream, so fail fast
	// with a precise message instead of opaque gateway 401s.
	if x, y := key.Curve.ScalarBaseMult(key.D.Bytes()); x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return nil, errors.New("u1s1: jwk public point does not match the private scalar")
	}
	return key, nil
}

func parsePrivateParts(xb64, yb64, db64 string) (*ecdsa.PrivateKey, error) {
	x, err := b64url.DecodeString(xb64)
	if err != nil {
		return nil, fmt.Errorf("u1s1: jwk x: %w", err)
	}
	y, err := b64url.DecodeString(yb64)
	if err != nil {
		return nil, fmt.Errorf("u1s1: jwk y: %w", err)
	}
	d, err := b64url.DecodeString(db64)
	if err != nil {
		return nil, fmt.Errorf("u1s1: jwk d: %w", err)
	}
	curve := elliptic.P256()
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	if !key.PublicKey.Curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) {
		return nil, errors.New("u1s1: jwk public point not on P-256")
	}
	return key, nil
}

// signP1363 signs digest-compatible data with ECDSA over P-256/SHA-256 and
// returns the raw 64-byte r||s signature (WebCrypto IEEE P1363 form).
func signP1363(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// publicJWKFromPrivate builds the verify-side JWK (with key_ops/ext, matching
// the shape produced by WebCrypto exportKey in the official CLI).
func publicJWKFromPrivate(key *ecdsa.PrivateKey) jwk {
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	key.X.FillBytes(xb)
	key.Y.FillBytes(yb)
	return jwk{
		Kty:    "EC",
		Crv:    "P-256",
		X:      b64url.EncodeToString(xb),
		Y:      b64url.EncodeToString(yb),
		KeyOps: []string{"verify"},
		Ext:    boolPtr(true),
	}
}

func boolPtr(v bool) *bool { return &v }

// generateDeviceKeyPair creates a fresh P-256 keypair in WebCrypto-compatible JWK form.
func generateDeviceKeyPair() (*deviceKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := publicJWKFromPrivate(key)
	db := make([]byte, 32)
	key.D.FillBytes(db)
	priv := jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   pub.X,
		Y:   pub.Y,
		D:   b64url.EncodeToString(db),
	}
	return &deviceKeyPair{Private: priv, Public: pub}, nil
}

// dpopHeaders produces the authorization and dpop headers for one request,
// mirroring dist/device-auth.js dpopHeaders() from the official CLI.
func dpopHeaders(token string, priv jwk, pub jwk, method, url string) (map[string]string, error) {
	if !strings.HasPrefix(token, "u1s1d-") {
		return nil, errors.New("u1s1: missing or malformed device token")
	}
	key, err := cachedPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	headerJSON, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": normalizePublicJWK(pub),
	})
	if err != nil {
		return nil, err
	}
	// htu: scheme://host/path without query or fragment.
	htu := url
	if i := strings.IndexAny(htu, "?#"); i >= 0 {
		htu = htu[:i]
	}
	payload := map[string]any{
		"jti": strings.ReplaceAll(newUUID(), "-", ""),
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": nowUnix(),
		"ath": b64url.EncodeToString(hashSHA256([]byte(token))),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	signingInput := b64url.EncodeToString(headerJSON) + "." + b64url.EncodeToString(payloadJSON)
	sig, err := signP1363(key, []byte(signingInput))
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": "DPoP " + token,
		"dpop":          signingInput + "." + b64url.EncodeToString(sig),
	}, nil
}

// normalizePublicJWK ensures the header JWK carries key_ops/ext like WebCrypto exports.
func normalizePublicJWK(k jwk) jwk {
	out := jwk{Kty: k.Kty, Crv: k.Crv, X: k.X, Y: k.Y}
	if len(k.KeyOps) == 0 {
		out.KeyOps = []string{"verify"}
	} else {
		out.KeyOps = k.KeyOps
	}
	if k.Ext != nil {
		out.Ext = k.Ext
	} else {
		out.Ext = boolPtr(true)
	}
	return out
}

func hashSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// keyCache caches parsed private keys per serialized JWK. Beyond skipping the
// per-request JWK decode it amortizes the keypair consistency check in
// parsePrivateJWK, which costs one scalar multiplication.
var keyCache sync.Map

func cachedPrivateKey(priv jwk) (*ecdsa.PrivateKey, error) {
	serialized, err := json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	if v, ok := keyCache.Load(string(serialized)); ok {
		return v.(*ecdsa.PrivateKey), nil
	}
	key, err := parsePrivateJWK(priv)
	if err != nil {
		return nil, err
	}
	keyCache.Store(string(serialized), key)
	return key, nil
}
