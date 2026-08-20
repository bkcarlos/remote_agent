package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/replay"
)

func claims(now time.Time) Claims {
	return Claims{ApprovalID: "approval-1", SessionID: "session-1", Operation: "write_file", Path: "a.txt", ContentSHA256: strings.Repeat("a", 64), ExpectedHash: strings.Repeat("b", 64), ExpiresAt: now.Add(time.Minute)}
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
	if err := m.RegisterChallenge(c); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(token, scope(c)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(token, scope(c)); err == nil {
		t.Fatal("consumed challenge accepted")
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
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}
