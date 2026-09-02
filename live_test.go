package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLiveGatewayRoundTrip exercises the real u1s1 gateway with the credential
// already stored by the u1s1 CLI. It is skipped unless U1S1_LIVE_TEST=1 so the
// normal test run stays offline and spends no credits.
//
//	U1S1_LIVE_TEST=1 go test -run TestLiveGateway -v
func TestLiveGatewayRoundTrip(t *testing.T) {
	if os.Getenv("U1S1_LIVE_TEST") != "1" {
		t.Skip("set U1S1_LIVE_TEST=1 to run the live gateway test")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	path := filepath.Join(home, ".u1s1", "config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no u1s1 CLI credential at %s: %v", path, err)
	}
	sa, err := parseStored(raw)
	if err != nil {
		t.Fatalf("parseStored(%s) error = %v", path, err)
	}

	// 1. /v1/models also hands out the client_attestation token.
	models, err := fetchModels(sa, "", "")
	if err != nil {
		t.Fatalf("fetchModels() error = %v", err)
	}
	if len(models.Data) == 0 {
		t.Fatal("gateway returned an empty model list")
	}
	if models.ClientAttestation == nil || models.ClientAttestation.Token == "" {
		t.Fatal("gateway returned no client_attestation token")
	}
	attestation := models.ClientAttestation.Token
	t.Logf("models=%d attestation_ttl=%ds first_model=%s", len(models.Data), models.ClientAttestation.ExpiresIn, models.Data[0].ID)

	// 2. /v1/me must accept the same DPoP proof scheme.
	me, err := fetchMe(sa, attestation, "")
	if err != nil {
		t.Fatalf("fetchMe() error = %v", err)
	}
	if me.Email == "" {
		t.Fatal("/me returned no account email")
	}

	// 3. Non-streaming chat: the full fingerprint + DPoP + attestation path.
	model := models.Data[0].ID
	body := prepareBody([]byte(`{"messages":[{"role":"user","content":"只回复两个字:收到"}]}`), nil, model, false)
	url := chatEndpoint(sa)
	headers, err := signedHeaders(sa, "POST", url, attestation)
	if err != nil {
		t.Fatalf("signedHeaders() error = %v", err)
	}
	resp, err := doRequest("POST", url, headers, body, "")
	if err != nil {
		t.Fatalf("chat request error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("chat status = %d: %s", resp.StatusCode, gatewayMessage(resp.Body, resp.StatusCode))
	}
	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(resp.Body, &completion); err != nil {
		t.Fatalf("decode completion: %v", err)
	}
	if len(completion.Choices) == 0 || strings.TrimSpace(completion.Choices[0].Message.Content) == "" {
		t.Fatalf("empty completion: %s", truncate(string(resp.Body), 300))
	}
	t.Logf("non-stream reply=%q", completion.Choices[0].Message.Content)

	// 4. Streaming chat through the same code path the executor uses.
	streamBody := prepareBody([]byte(`{"messages":[{"role":"user","content":"只回复两个字:收到"}]}`), nil, model, true)
	streamHeaders, err := signedHeaders(sa, "POST", url, attestation)
	if err != nil {
		t.Fatalf("signedHeaders() error = %v", err)
	}
	streamHeaders["accept"] = "text/event-stream"
	chunks, status, err := collectStream(url, streamHeaders, streamBody, false, "")
	if err != nil {
		t.Fatalf("collectStream() status=%d error = %v", status, err)
	}
	if len(chunks) == 0 {
		t.Fatal("stream produced no chunks")
	}
	t.Logf("stream chunks=%d first=%s", len(chunks), truncate(string(chunks[0].Payload), 160))
}
