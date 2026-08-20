package transportauth

import (
	"strings"
	"testing"
	"time"
)

func TestSignVerifyAndReplay(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h, err := Sign(key, []byte("body"), now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	if err := v.Verify([]byte("body"), h); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify([]byte("body"), h); err == nil {
		t.Fatal("replay accepted")
	}
}
func TestRejectTamperExpiryAndBadKey(t *testing.T) {
	key := []byte(strings.Repeat("x", 32))
	now := time.Now().UTC()
	h, _ := Sign(key, []byte("body"), now)
	v, _ := NewVerifier(key, time.Minute)
	v.now = func() time.Time { return now }
	if err := v.Verify([]byte("changed"), h); err == nil {
		t.Fatal("tampered body accepted")
	}
	old, _ := Sign(key, []byte("body"), now.Add(-2*time.Minute))
	if err := v.Verify([]byte("body"), old); err == nil {
		t.Fatal("expired signature accepted")
	}
	if _, err := Sign([]byte("short"), nil, now); err == nil {
		t.Fatal("short signing key accepted")
	}
	if _, err := NewVerifier([]byte("short"), time.Minute); err == nil {
		t.Fatal("short verifier key accepted")
	}
}
