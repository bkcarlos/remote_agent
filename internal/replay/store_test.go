package replay

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func exerciseStore(t *testing.T, store Store) {
	t.Helper()
	now := time.Now().UTC()
	if err := store.Consume("scope", "id", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("scope", "id", now.Add(time.Minute), now); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("replay accepted: %v", err)
	}
	if err := store.Consume("other-scope", "id", now.Add(time.Minute), now); err != nil {
		t.Fatalf("namespace collision: %v", err)
	}
	if err := store.Consume("scope", "id", now.Add(2*time.Minute), now.Add(time.Minute+time.Second)); err != nil {
		t.Fatalf("expired entry was not reusable: %v", err)
	}
}
func TestMemory(t *testing.T) { exerciseStore(t, NewMemory()) }

func exerciseChallengePeek(t *testing.T, store ChallengeStore) {
	t.Helper()
	now := time.Now().UTC()
	if err := store.Put("approval", "peek", []byte("payload"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first, err := store.Peek("approval", "peek", now)
	if err != nil || string(first) != "payload" {
		t.Fatalf("first peek = %q, %v", first, err)
	}
	first[0] = 'X'
	second, err := store.Peek("approval", "peek", now)
	if err != nil || string(second) != "payload" {
		t.Fatalf("second peek = %q, %v", second, err)
	}
	taken, err := store.Take("approval", "peek", now)
	if err != nil || string(taken) != "payload" {
		t.Fatalf("take after peek = %q, %v", taken, err)
	}
	if _, err := store.Peek("approval", "peek", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed challenge remained visible: %v", err)
	}
}

func TestChallengePeekDoesNotConsume(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		exerciseChallengePeek(t, NewMemory())
	})
	t.Run("bolt", func(t *testing.T) {
		store, err := OpenBolt(filepath.Join(t.TempDir(), "replay.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		exerciseChallengePeek(t, store)
	})
}

func TestBoltPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "replay.db")
	now := time.Now().UTC()
	first, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Consume("approval", "token", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Consume("approval", "token", now.Add(time.Minute), now); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("replay after restart accepted: %v", err)
	}
}
func TestBoltChallengePersistsAndIsConsumedAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Now().UTC()
	first, _ := OpenBolt(path)
	if err := first.Put("approval", "challenge", []byte("payload"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, _ := OpenBolt(path)
	defer second.Close()
	peeked, err := second.Peek("approval", "challenge", now)
	if err != nil || string(peeked) != "payload" {
		t.Fatalf("peek after restart %q: %v", peeked, err)
	}
	payload, err := second.Take("approval", "challenge", now)
	if err != nil || string(payload) != "payload" {
		t.Fatalf("take %q: %v", payload, err)
	}
	if _, err := second.Take("approval", "challenge", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("challenge replay accepted: %v", err)
	}
}

func TestBoltAtomicConcurrentConsume(t *testing.T) {
	store, err := OpenBolt(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.Consume("request", "same", now.Add(time.Minute), now) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d concurrent replays", accepted.Load())
	}
}
func TestRejectInvalidEntry(t *testing.T) {
	store, _ := OpenBolt(filepath.Join(t.TempDir(), "replay.db"))
	defer store.Close()
	now := time.Now()
	if err := store.Consume("", "", now, now); err == nil {
		t.Fatal("invalid entry accepted")
	}
}
