package approval

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/replay"
)

func claims(now time.Time) Claims {
	return Claims{ApprovalID: "approval-1", Approver: "reviewer-1", SessionID: "session-1", Operation: "write_file", Path: "a.txt", ContentSHA256: strings.Repeat("a", 64), ExpectedHash: strings.Repeat("b", 64), ExpiresAt: now.Add(time.Minute)}
}
func scope(c Claims) Scope {
	return Scope{SessionID: c.SessionID, Operation: c.Operation, Path: c.Path, ContentSHA256: c.ContentSHA256, ExpectedHash: c.ExpectedHash}
}
func TestApprovalSingleUseAndScope(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	c := claims(now)
	token, err := m.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	wrong := scope(c)
	wrong.Path = "b.txt"
	if _, err := m.Verify(token, wrong); err == nil {
		t.Fatal("wrong scope accepted")
	}
	if _, err := m.Verify(token, scope(c)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(token, scope(c)); err == nil {
		t.Fatal("replay accepted")
	}
}

type unavailableStore struct{}

func (unavailableStore) Consume(string, string, time.Time, time.Time) error {
	return errors.New("storage down")
}

func TestRegisteredChallengeRequiredAndConsumed(t *testing.T) {
	now := time.Now().UTC()
	store := replay.NewMemory()
	m, err := NewWithChallengeStore([]byte(strings.Repeat("c", 32)), store)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	c := claims(now)
	token, _ := m.Sign(c)
	if _, err := m.Verify(token, scope(c)); err == nil {
		t.Fatal("unregistered challenge accepted")
	}
	challenge := c
	challenge.Approver = ""
	if err := m.RegisterChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	if verified, err := m.Verify(token, scope(c)); err != nil {
		t.Fatal(err)
	} else if verified.Approver != c.Approver {
		t.Fatalf("verified approver = %q, want %q", verified.Approver, c.Approver)
	}
	if _, err := m.Verify(token, scope(c)); err == nil {
		t.Fatal("consumed challenge accepted")
	}
}

func TestInspectAuthenticatesWithoutConsuming(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	store := replay.NewMemory()
	manager, err := NewWithChallengeStore([]byte(strings.Repeat("i", 32)), store)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	approved := claims(now)
	challenge := approved
	challenge.Approver = ""
	if err := manager.RegisterChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	token, err := manager.Sign(approved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Inspect(token+"x", scope(approved)); err == nil {
		t.Fatal("Inspect accepted a tampered signature")
	}
	wrong := scope(approved)
	wrong.Path = "other.txt"
	if _, err := manager.Inspect(token, wrong); err == nil {
		t.Fatal("Inspect accepted the wrong scope")
	}
	for i := 0; i < 2; i++ {
		inspected, err := manager.Inspect(token, scope(approved))
		if err != nil {
			t.Fatalf("Inspect %d failed: %v", i+1, err)
		}
		if inspected.ApprovalID != approved.ApprovalID || inspected.Approver != approved.Approver {
			t.Fatalf("Inspect returned incomplete identity: %+v", inspected)
		}
	}
	if _, err := manager.Verify(token, scope(approved)); err != nil {
		t.Fatalf("Inspect consumed the approval: %v", err)
	}
	if _, err := manager.Inspect(token, scope(approved)); err == nil {
		t.Fatal("Inspect accepted a consumed challenge")
	}
}

func TestInspectChecksChallengeBindingWithoutConsuming(t *testing.T) {
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	store := replay.NewMemory()
	manager, err := NewWithChallengeStore([]byte(strings.Repeat("j", 32)), store)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	registered := claims(now)
	registered.Approver = ""
	if err := manager.RegisterChallenge(registered); err != nil {
		t.Fatal(err)
	}
	mismatched := claims(now)
	mismatched.Path = "other.txt"
	mismatched.Targets = nil
	badToken, err := manager.Sign(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Inspect(badToken, scope(mismatched)); err == nil {
		t.Fatal("Inspect accepted a token that did not match the registered challenge")
	}
	if _, err := manager.Verify(badToken, scope(mismatched)); err == nil {
		t.Fatal("Verify accepted a token that did not match the registered challenge")
	}
	valid := claims(now)
	validToken, err := manager.Sign(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(validToken, scope(valid)); err != nil {
		t.Fatalf("failed Inspect consumed the registered challenge: %v", err)
	}
}

func TestApprovalFailsClosedWhenReplayStoreUnavailable(t *testing.T) {
	now := time.Now().UTC()
	m, err := NewWithStore([]byte(strings.Repeat("s", 32)), unavailableStore{})
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	c := claims(now)
	token, _ := m.Sign(c)
	if _, err := m.Verify(token, scope(c)); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("approval did not fail closed: %v", err)
	}
}

func TestBatchApprovalBindsEveryNormalizedTarget(t *testing.T) {
	now := time.Now().UTC()
	store := replay.NewMemory()
	manager, err := NewWithChallengeStore([]byte(strings.Repeat("b", 32)), store)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	claims := Claims{
		ApprovalID: "batch-challenge", Approver: "reviewer-1", SessionID: "session-1", Operation: "multi_edit", ReviewSHA256: strings.Repeat("5", 64),
		Targets: []Target{
			{Path: "dir/../a.txt", BeforeSHA256: strings.Repeat("1", 64), AfterSHA256: strings.Repeat("2", 64)},
			{Path: "b.txt", BeforeSHA256: strings.Repeat("3", 64), AfterSHA256: strings.Repeat("4", 64)},
		},
		ExpiresAt: now.Add(time.Minute),
	}
	if err := manager.RegisterChallenge(claims); err != nil {
		t.Fatal(err)
	}
	token, err := manager.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	wrong := Scope{SessionID: claims.SessionID, Operation: claims.Operation, Targets: []Target{{Path: "a.txt", BeforeSHA256: strings.Repeat("1", 64), AfterSHA256: strings.Repeat("9", 64)}, claims.Targets[1]}, ReviewSHA256: claims.ReviewSHA256}
	if _, err := manager.Verify(token, wrong); err == nil {
		t.Fatal("tampered batch target accepted")
	}
	correct := Scope{SessionID: claims.SessionID, Operation: claims.Operation, Targets: []Target{{Path: "a.txt", BeforeSHA256: strings.Repeat("1", 64), AfterSHA256: strings.Repeat("2", 64)}, claims.Targets[1]}, ReviewSHA256: claims.ReviewSHA256}
	if verified, err := manager.Verify(token, correct); err != nil || len(verified.Targets) != 2 || verified.Targets[0].Path != "a.txt" {
		t.Fatalf("batch verification failed: %+v, %v", verified, err)
	}
	if _, err := manager.Verify(token, correct); err == nil {
		t.Fatal("persistent challenge consumption was not single-use")
	}
}

func TestReviewSHA256IsSignedPersistedAndScopeBound(t *testing.T) {
	now := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)
	store := replay.NewMemory()
	manager, err := NewWithChallengeStore([]byte(strings.Repeat("r", 32)), store)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	approved := claims(now)
	approved.ReviewSHA256 = strings.Repeat("6", 64)
	challenge := approved
	challenge.Approver = ""
	if err := manager.RegisterChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	token, err := manager.Sign(approved)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var tampered Claims
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.ReviewSHA256 = strings.Repeat("8", 64)
	payload, err = json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Inspect(base64.RawURLEncoding.EncodeToString(payload)+"."+parts[1], Scope{SessionID: approved.SessionID, Operation: approved.Operation, Path: approved.Path, ContentSHA256: approved.ContentSHA256, ExpectedHash: approved.ExpectedHash, ReviewSHA256: tampered.ReviewSHA256}); err == nil {
		t.Fatal("token signature did not cover review digest")
	}
	wrong := scope(approved)
	wrong.ReviewSHA256 = strings.Repeat("7", 64)
	if _, err := manager.Inspect(token, wrong); err == nil {
		t.Fatal("Inspect accepted a different review digest")
	}
	mismatchedChallenge := approved
	mismatchedChallenge.ReviewSHA256 = wrong.ReviewSHA256
	mismatchedToken, err := manager.Sign(mismatchedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Inspect(mismatchedToken, wrong); err == nil {
		t.Fatal("Inspect accepted a review digest not persisted in the challenge")
	}
	correct := scope(approved)
	correct.ReviewSHA256 = approved.ReviewSHA256
	if verified, err := manager.Verify(token, correct); err != nil || verified.ReviewSHA256 != approved.ReviewSHA256 {
		t.Fatalf("review-bound verification = %+v, %v", verified, err)
	}
}

func TestReviewSHA256ValidationAndLegacyWriteCompatibility(t *testing.T) {
	now := time.Now().UTC()
	manager, err := New([]byte(strings.Repeat("v", 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	legacy := claims(now)
	if _, err := manager.Sign(legacy); err != nil {
		t.Fatalf("legacy write without review rejected: %v", err)
	}
	invalid := claims(now)
	invalid.ReviewSHA256 = strings.ToUpper(strings.Repeat("a", 64))
	if _, err := manager.Sign(invalid); err == nil {
		t.Fatal("uppercase review digest accepted")
	}
	nonWrite := claims(now)
	nonWrite.Operation = "edit"
	if _, err := manager.Sign(nonWrite); err == nil {
		t.Fatal("edit without review digest accepted")
	}
}

func TestApproverIsCoveredByTokenSignature(t *testing.T) {
	now := time.Now().UTC()
	manager, err := New([]byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	original := claims(now)
	token, err := manager.Sign(original)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var tampered Claims
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Approver = "attacker"
	payload, err = json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedToken := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, err := manager.Verify(tamperedToken, scope(original)); err == nil {
		t.Fatal("tampered approver was not rejected by the token signature")
	}
}

func TestApprovalRejectsTamperExpiryAndIncomplete(t *testing.T) {
	now := time.Now().UTC()
	m, _ := New([]byte(strings.Repeat("x", 32)))
	m.now = func() time.Time { return now }
	c := claims(now)
	token, _ := m.Sign(c)
	if _, err := m.Verify(token+"x", scope(c)); err == nil {
		t.Fatal("tamper accepted")
	}
	c.ApprovalID = "expired"
	c.ExpiresAt = now
	token, _ = m.Sign(c)
	if _, err := m.Verify(token, scope(c)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := m.Sign(Claims{}); err == nil {
		t.Fatal("incomplete claims accepted")
	}
	withoutApprover := claims(now)
	withoutApprover.Approver = ""
	if _, err := m.Sign(withoutApprover); err == nil {
		t.Fatal("approval without approver accepted")
	}
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}
