package capability

import (
	"strings"
	"testing"
	"time"
)

func TestCapabilityLifecycle(t *testing.T) {
	m, e := New([]byte(strings.Repeat("k", 32)))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	c := Claims{TokenID: "one", RequestID: "req", SessionID: "s", Operation: "read", Path: "a.txt", ExpiresAt: now.Add(time.Minute), SingleUse: true}
	tok, e := m.Sign(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Verify(tok, "req", "read", "a.txt"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Verify(tok, "req", "read", "a.txt"); e == nil {
		t.Fatal("expected replay rejection")
	}
}
func TestCapabilityRejectsTamperScopeAndExpiry(t *testing.T) {
	m, _ := New([]byte(strings.Repeat("x", 32)))
	now := time.Now()
	m.now = func() time.Time { return now }
	cases := []struct {
		name      string
		claims    Claims
		mutate    func(string) string
		rid, path string
	}{
		{"tamper", Claims{TokenID: "1", RequestID: "r", Operation: "read", Path: "a", ExpiresAt: now.Add(time.Minute)}, func(s string) string { return s + "x" }, "r", "a"},
		{"scope", Claims{TokenID: "2", RequestID: "r", Operation: "read", Path: "a", ExpiresAt: now.Add(time.Minute)}, func(s string) string { return s }, "r", "b"},
		{"expired", Claims{TokenID: "3", RequestID: "r", Operation: "read", Path: "a", ExpiresAt: now}, func(s string) string { return s }, "r", "a"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, _ := m.Sign(tc.claims)
			if _, e := m.Verify(tc.mutate(tok), tc.rid, "read", tc.path); e == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
func TestShortKeyRejected(t *testing.T) {
	if _, e := New([]byte("short")); e == nil {
		t.Fatal("expected error")
	}
}
