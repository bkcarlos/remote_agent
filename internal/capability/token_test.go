package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testSignerVerifier(t *testing.T, now time.Time) (*Signer, *Verifier) {
	t.Helper()
	signer, err := NewSignerFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	signer.now = func() time.Time { return now }
	verifier.now = func() time.Time { return now }
	return signer, verifier
}

func testClaims(now time.Time) Claims {
	return Claims{
		TokenID:          "token-1",
		WorkerType:       "file",
		RequestID:        "request-1",
		BridgeID:         "bridge-1",
		SessionID:        "session-1",
		ClientRequestID:  "client-request-1",
		AuthPrincipal:    "principal-1",
		Operation:        "grep",
		Path:             "dir/file.txt",
		PolicyID:         "policy-1",
		WorkerPolicyID:   "worker-policy-1",
		PolicyDecision:   "allow",
		ApprovalRequired: true,
		ArgumentsSHA256:  strings.Repeat("e", 64),
		Targets:          []Target{{Path: "dir/file.txt", BeforeSHA256: strings.Repeat("f", 64), AfterSHA256: strings.Repeat("0", 64)}},
		MaxBytes:         1024,
		StartLine:        2,
		EndLine:          3,
		MaxFiles:         10,
		MaxResults:       5,
		ExpectedHash:     strings.Repeat("a", 64),
		ContentSHA256:    strings.Repeat("b", 64),
		PatternSHA256:    strings.Repeat("c", 64),
		QuerySHA256:      strings.Repeat("d", 64),
		ExpiresAt:        now.Add(30 * time.Second),
		SingleUse:        true,
	}
}

func scopeFromClaims(claims Claims) Scope {
	return Scope{
		WorkerType:       claims.WorkerType,
		RequestID:        claims.RequestID,
		BridgeID:         claims.BridgeID,
		SessionID:        claims.SessionID,
		ClientRequestID:  claims.ClientRequestID,
		AuthPrincipal:    claims.AuthPrincipal,
		Operation:        claims.Operation,
		Path:             claims.Path,
		Targets:          append([]Target(nil), claims.Targets...),
		PolicyID:         claims.PolicyID,
		WorkerPolicyID:   claims.WorkerPolicyID,
		PolicyDecision:   claims.PolicyDecision,
		ApprovalRequired: claims.ApprovalRequired,
		ArgumentsSHA256:  claims.ArgumentsSHA256,
		MaxBytes:         claims.MaxBytes,
		StartLine:        claims.StartLine,
		EndLine:          claims.EndLine,
		MaxEntries:       claims.MaxEntries,
		MaxFiles:         claims.MaxFiles,
		MaxResults:       claims.MaxResults,
		ExpectedHash:     claims.ExpectedHash,
		ContentSHA256:    claims.ContentSHA256,
		PatternSHA256:    claims.PatternSHA256,
		QuerySHA256:      claims.QuerySHA256,
	}
}

func TestCapabilityEd25519LifecycleAndReplay(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signer, verifier := testSignerVerifier(t, now)
	claims := testClaims(now)
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(token, scopeFromClaims(claims)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(token, scopeFromClaims(claims)); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestCapabilityRejectsSignatureScopeExpiryAndWrongKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signer, verifier := testSignerVerifier(t, now)
	claims := testClaims(now)
	claims.SingleUse = false
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifier.Verify(token+"x", scopeFromClaims(claims)); err == nil {
		t.Fatal("tampered signature accepted")
	}
	wrongSigner, _ := NewSignerFromSeed([]byte(strings.Repeat("x", ed25519.SeedSize)))
	wrongVerifier, _ := NewVerifier(wrongSigner.PublicKey())
	wrongVerifier.now = func() time.Time { return now }
	if _, err := wrongVerifier.Verify(token, scopeFromClaims(claims)); err == nil {
		t.Fatal("token accepted by unrelated public key")
	}

	mutations := []struct {
		name   string
		mutate func(*Scope)
	}{
		{"worker type", func(s *Scope) { s.WorkerType += "-other" }},
		{"request", func(s *Scope) { s.RequestID += "-other" }},
		{"bridge", func(s *Scope) { s.BridgeID += "-other" }},
		{"session", func(s *Scope) { s.SessionID += "-other" }},
		{"client request", func(s *Scope) { s.ClientRequestID += "-other" }},
		{"principal", func(s *Scope) { s.AuthPrincipal += "-other" }},
		{"operation", func(s *Scope) { s.Operation += "-other" }},
		{"path", func(s *Scope) { s.Path = "other.txt" }},
		{"policy", func(s *Scope) { s.PolicyID += "-other" }},
		{"worker policy", func(s *Scope) { s.WorkerPolicyID += "-other" }},
		{"policy decision", func(s *Scope) { s.PolicyDecision = "deny" }},
		{"approval requirement", func(s *Scope) { s.ApprovalRequired = false }},
		{"arguments", func(s *Scope) { s.ArgumentsSHA256 = strings.Repeat("1", 64) }},
		{"targets", func(s *Scope) { s.Targets[0].AfterSHA256 = strings.Repeat("1", 64) }},
		{"max bytes", func(s *Scope) { s.MaxBytes++ }},
		{"start line", func(s *Scope) { s.StartLine++ }},
		{"end line", func(s *Scope) { s.EndLine++ }},
		{"max entries", func(s *Scope) { s.MaxEntries++ }},
		{"max files", func(s *Scope) { s.MaxFiles++ }},
		{"max results", func(s *Scope) { s.MaxResults++ }},
		{"expected hash", func(s *Scope) { s.ExpectedHash = strings.Repeat("e", 64) }},
		{"content hash", func(s *Scope) { s.ContentSHA256 = strings.Repeat("e", 64) }},
		{"pattern", func(s *Scope) { s.PatternSHA256 = strings.Repeat("e", 64) }},
		{"query", func(s *Scope) { s.QuerySHA256 = strings.Repeat("e", 64) }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			scope := scopeFromClaims(claims)
			test.mutate(&scope)
			if _, err := verifier.Verify(token, scope); err == nil || !strings.Contains(err.Error(), "scope mismatch") {
				t.Fatalf("mismatched scope accepted: %v", err)
			}
		})
	}

	verifier.now = func() time.Time { return claims.ExpiresAt }
	if _, err := verifier.Verify(token, scopeFromClaims(claims)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestCapabilityClaimsValidationAndNormalizedPath(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signer, _ := testSignerVerifier(t, now)
	claims := testClaims(now)

	invalid := []Claims{
		{},
		func() Claims { c := claims; c.Path = "dir/../file.txt"; return c }(),
		func() Claims { c := claims; c.Path = "../file.txt"; return c }(),
		func() Claims { c := claims; c.MaxBytes = -1; return c }(),
		func() Claims { c := claims; c.EndLine = 0; return c }(),
		func() Claims { c := claims; c.StartLine = 1; c.EndLine = 10001; return c }(),
		func() Claims { c := claims; c.ContentSHA256 = "ABC"; return c }(),
		func() Claims { c := claims; c.ExpiresAt = now; return c }(),
		func() Claims { c := claims; c.ExpiresAt = now.Add(2 * time.Minute); return c }(),
	}
	for i, value := range invalid {
		if _, err := signer.Sign(value); err == nil {
			t.Errorf("invalid claims %d accepted", i)
		}
	}
	if got, err := NormalizePath("dir/../file.txt"); err != nil || got != "file.txt" {
		t.Fatalf("normalize path = %q, %v", got, err)
	}
}

func TestCapabilityPayloadUsesStrictJSON(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signer, verifier := testSignerVerifier(t, now)
	claims := testClaims(now)
	claims.SingleUse = false
	payload, _ := json.Marshal(claims)
	payload = append(payload[:len(payload)-1], []byte(`,"unknown":true}`)...)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signed := tokenVersion + "." + encoded
	token := signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.privateKey, []byte(signed)))
	if _, err := verifier.Verify(token, scopeFromClaims(claims)); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("unknown token field accepted: %v", err)
	}
}

func TestCapabilityKeySizesAreExact(t *testing.T) {
	if _, err := NewSignerFromSeed([]byte("short")); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, err := NewSigner(make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)); err == nil {
		t.Fatal("invalid private key accepted")
	}
	if _, err := NewVerifier(make(ed25519.PublicKey, ed25519.PublicKeySize-1)); err == nil {
		t.Fatal("invalid public key accepted")
	}
}
