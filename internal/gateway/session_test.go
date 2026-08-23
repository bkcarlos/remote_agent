package gateway

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSessionCapacityAndTTLCallbacksRunOutsideStoreLock(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := newSessionStore(time.Minute, 1, func() time.Time { return now })
	var mu sync.Mutex
	var evicted []mcpSession
	store.onEvict = func(sessions []mcpSession) {
		store.mu.Lock()
		store.mu.Unlock()
		mu.Lock()
		evicted = append(evicted, sessions...)
		mu.Unlock()
	}
	first, err := store.create("principal", "version")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.create("principal", "version")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(evicted) != 1 || evicted[0].ID != first.ID {
		t.Fatalf("capacity eviction callback = %+v", evicted)
	}
	mu.Unlock()

	now = now.Add(time.Minute)
	if _, err := store.validateAndTouch(second.ID, second.Principal, second.ProtocolVersion); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("expired session validation error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(evicted) != 2 || evicted[1].ID != second.ID {
		t.Fatalf("TTL eviction callback = %+v", evicted)
	}
}
