package transportauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestSignatureBindsTransportAndIdentity(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"jsonrpc":"2.0","id":1}`)
	request := signedRequest(http.MethodPost, "/mcp/tools?b=2&a=1", body)
	headers, err := SignRequest(key, request, body, now)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }

	tests := []struct {
		name   string
		mutate func(*http.Request) []byte
	}{
		{name: "method", mutate: func(r *http.Request) []byte { r.Method = http.MethodPut; return body }},
		{name: "path", mutate: func(r *http.Request) []byte { r.URL.Path = "/mcp/other"; return body }},
		{name: "query", mutate: func(r *http.Request) []byte { r.URL.RawQuery = "b=2&a=changed"; return body }},
		{name: "content type", mutate: func(r *http.Request) []byte {
			r.Header.Set("Content-Type", "application/json; charset=utf-8")
			return body
		}},
		{name: "body", mutate: func(r *http.Request) []byte { return []byte(`{"jsonrpc":"2.0","id":2}`) }},
		{name: "bridge", mutate: func(r *http.Request) []byte { r.Header.Set(HeaderBridgeID, "bridge-2"); return body }},
		{name: "legacy session", mutate: func(r *http.Request) []byte { r.Header.Set(HeaderSessionID, "legacy-session-2"); return body }},
		{name: "MCP session", mutate: func(r *http.Request) []byte { r.Header.Set(HeaderMCPSessionID, "mcp-session-2"); return body }},
		{name: "protocol version", mutate: func(r *http.Request) []byte {
			r.Header.Set(HeaderProtocolVersion, "2025-06-18")
			return body
		}},
		{name: "client request", mutate: func(r *http.Request) []byte { r.Header.Set(HeaderClientRequest, "request-2"); return body }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := request.Clone(request.Context())
			mutatedBody := test.mutate(mutated)
			if err := verifier.VerifyRequest(mutated, mutatedBody, headers); err == nil {
				t.Fatal("tampered request accepted")
			}
		})
	}

	if err := verifier.VerifyRequest(request, body, headers); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyRequest(request, body, headers); err == nil {
		t.Fatal("replay accepted")
	}
}

func TestRequestSignatureRejectsLegacyExpiryAndBadKey(t *testing.T) {
	key := []byte(strings.Repeat("x", 32))
	now := time.Now().UTC()
	body := []byte("body")
	request := signedRequest(http.MethodPost, "/mcp", body)
	verifier, err := NewVerifier(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }

	legacy, err := signBodyOnlyForTest(key, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyRequest(request, body, legacy); err == nil {
		t.Fatal("legacy body-only signature accepted by request verifier")
	}
	legacyVerifier, _ := NewVerifier(key, time.Minute)
	legacyVerifier.now = func() time.Time { return now }
	if err := legacyVerifier.verifyBodyOnlyForTest(body, legacy); err != nil {
		t.Fatalf("legacy test helper rejected its signature: %v", err)
	}

	expired, err := SignRequest(key, request, body, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyRequest(request, body, expired); err == nil {
		t.Fatal("expired signature accepted")
	}
	if _, err := SignRequest([]byte("short"), request, nil, now); err == nil {
		t.Fatal("short signing key accepted")
	}
	if _, err := NewVerifier([]byte("short"), time.Minute); err == nil {
		t.Fatal("short verifier key accepted")
	}
}

func signedRequest(method, target string, body []byte) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderBridgeID, "bridge-1")
	request.Header.Set(HeaderSessionID, "legacy-session-1")
	request.Header.Set(HeaderMCPSessionID, "mcp-session-1")
	request.Header.Set(HeaderProtocolVersion, "2025-03-26")
	request.Header.Set(HeaderClientRequest, "request-1")
	return request
}
