package workspaceregistry

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mutableClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *mutableClock) Time() time.Time {
	clock.mu.RLock()
	now := clock.now
	clock.mu.RUnlock()
	return now
}

func (clock *mutableClock) Set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

func registryWorkspace(id, root string, now time.Time) WorkspaceConfig {
	return WorkspaceConfig{
		ID:          id,
		Root:        root,
		ReadOnly:    true,
		ExpiresAt:   now.Add(time.Hour),
		DeniedNames: []string{".env"},
	}
}

func TestGetExpiresAndCleansWorkspaceOnce(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	var cleaned atomic.Int32
	registry := NewWithClock(clock.Time, func(workspace AdminView) {
		cleaned.Add(1)
		if workspace.Root != "/srv/expiring" {
			t.Errorf("cleanup root = %q", workspace.Root)
		}
	})
	workspace := registryWorkspace("expiring-0123456789", "/srv/expiring", now)
	generation, err := registry.Register(workspace)
	if err != nil || generation != 1 {
		t.Fatalf("Register generation=%d err=%v", generation, err)
	}

	clock.Set(workspace.ExpiresAt)
	if _, err := registry.Get(workspace.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("first expired Get error = %v", err)
	}
	if _, err := registry.Get(workspace.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second expired Get error = %v", err)
	}
	if cleaned.Load() != 1 {
		t.Fatalf("cleanup called %d times", cleaned.Load())
	}
	if registry.Generation() != 2 {
		t.Fatalf("generation = %d", registry.Generation())
	}
}

func TestConcurrentRevokeRunsCleanupOnce(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	var cleaned atomic.Int32
	var registry *Registry
	registry = NewWithClock(func() time.Time { return now }, func(AdminView) {
		cleaned.Add(1)
		if views := registry.List(); len(views) != 0 {
			t.Errorf("revoked workspace visible to reentrant callback: %+v", views)
		}
	})
	workspace := registryWorkspace("revocable-01234567", "/srv/revocable", now)
	if _, err := registry.Register(workspace); err != nil {
		t.Fatal(err)
	}

	const goroutines = 64
	var successes atomic.Int32
	var group sync.WaitGroup
	start := make(chan struct{})
	for range goroutines {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if _, err := registry.Revoke(workspace.ID); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrNotFound) {
				t.Errorf("Revoke error = %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	if successes.Load() != 1 || cleaned.Load() != 1 {
		t.Fatalf("successes=%d cleanup=%d", successes.Load(), cleaned.Load())
	}
	if registry.Generation() != 2 {
		t.Fatalf("generation = %d", registry.Generation())
	}
}

func TestConcurrentRegisterHasSingleWinner(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	registry := NewWithClock(func() time.Time { return now })
	workspace := registryWorkspace("register-012345678", "/srv/register", now)
	const goroutines = 64
	var successes atomic.Int32
	var group sync.WaitGroup
	start := make(chan struct{})
	for range goroutines {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if _, err := registry.Register(workspace); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrAlreadyExists) {
				t.Errorf("Register error = %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	if successes.Load() != 1 || registry.Generation() != 1 {
		t.Fatalf("successes=%d generation=%d", successes.Load(), registry.Generation())
	}
}

func TestReplaceAllIsAtomicAndCleansChangedRegistrations(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var cleaned []string
	registry := NewWithClock(func() time.Time { return now }, func(workspace AdminView) {
		mu.Lock()
		cleaned = append(cleaned, workspace.ID+"="+workspace.Root)
		mu.Unlock()
	})
	alpha := registryWorkspace("alpha-workspace-01", "/srv/alpha", now)
	beta := registryWorkspace("beta-workspace-001", "/srv/beta-old", now)
	if generation, err := registry.ReplaceAll([]WorkspaceConfig{alpha, beta}); err != nil || generation != 1 {
		t.Fatalf("initial ReplaceAll generation=%d err=%v", generation, err)
	}

	newBeta := beta
	newBeta.Root = "/srv/beta-new"
	gamma := registryWorkspace("gamma-workspace-01", "/srv/gamma", now)
	generation, err := registry.ReplaceAll([]WorkspaceConfig{gamma, newBeta, alpha})
	if err != nil || generation != 2 {
		t.Fatalf("ReplaceAll generation=%d err=%v", generation, err)
	}
	mu.Lock()
	gotCleaned := append([]string(nil), cleaned...)
	mu.Unlock()
	if len(gotCleaned) != 1 || gotCleaned[0] != beta.ID+"="+beta.Root {
		t.Fatalf("replacement cleanup = %v", gotCleaned)
	}

	views := registry.List()
	if len(views) != 3 || views[0].ID != alpha.ID || views[1].ID != beta.ID || views[2].ID != gamma.ID {
		t.Fatalf("replacement snapshot = %+v", views)
	}
	if views[0].Generation != generation || views[1].Generation != generation || views[2].Generation != generation {
		t.Fatalf("snapshot has mixed generations: %+v", views)
	}
	adminBeta, err := registry.GetAdmin(beta.ID)
	if err != nil || adminBeta.Root != newBeta.Root {
		t.Fatalf("new beta = %+v, %v", adminBeta, err)
	}
}

func TestReplaceAllInvalidInputLeavesStateUnchanged(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	registry := NewWithClock(func() time.Time { return now })
	workspace := registryWorkspace("stable-workspace-01", "/srv/stable", now)
	if _, err := registry.Register(workspace); err != nil {
		t.Fatal(err)
	}
	invalid := registryWorkspace("short", "/srv/invalid", now)
	if _, err := registry.ReplaceAll([]WorkspaceConfig{invalid}); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if registry.Generation() != 1 {
		t.Fatalf("failed replacement changed generation to %d", registry.Generation())
	}
	if view, err := registry.Get(workspace.ID); err != nil || view.ID != workspace.ID {
		t.Fatalf("old state lost: %+v, %v", view, err)
	}
}

func TestConcurrentListObservesWholeReplacementSnapshots(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	registry := NewWithClock(func() time.Time { return now })
	setA := []WorkspaceConfig{
		registryWorkspace("set-a-workspace-01", "/srv/a1", now),
		registryWorkspace("set-a-workspace-02", "/srv/a2", now),
	}
	setB := []WorkspaceConfig{
		registryWorkspace("set-b-workspace-01", "/srv/b1", now),
		registryWorkspace("set-b-workspace-02", "/srv/b2", now),
	}
	if _, err := registry.ReplaceAll(setA); err != nil {
		t.Fatal(err)
	}

	var failed atomic.Bool
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for index := 0; index < 500; index++ {
			set := setA
			if index%2 == 0 {
				set = setB
			}
			if _, err := registry.ReplaceAll(set); err != nil {
				failed.Store(true)
				return
			}
		}
	}()
	go func() {
		defer group.Done()
		for index := 0; index < 1000; index++ {
			views := registry.List()
			if len(views) != 2 {
				failed.Store(true)
				return
			}
			bothA := strings.HasPrefix(views[0].ID, "set-a-") && strings.HasPrefix(views[1].ID, "set-a-")
			bothB := strings.HasPrefix(views[0].ID, "set-b-") && strings.HasPrefix(views[1].ID, "set-b-")
			if !bothA && !bothB || views[0].Generation != views[1].Generation {
				failed.Store(true)
				return
			}
		}
	}()
	group.Wait()
	if failed.Load() {
		t.Fatal("observed a partial or mixed-generation replacement")
	}
}

func TestViewsDoNotExposeRootOrMutableRegistryState(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	registry := NewWithClock(func() time.Time { return now })
	workspace := registryWorkspace("private-workspace-1", "/secret/host/root", now)
	if _, err := registry.Register(workspace); err != nil {
		t.Fatal(err)
	}
	workspace.DeniedNames[0] = "mutated-input"

	view, err := registry.Get(workspace.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "/secret/host/root") || strings.Contains(strings.ToLower(string(encoded)), "root") {
		t.Fatalf("non-management view leaked root: %s", encoded)
	}
	if len(view.DeniedNames) != 1 || view.DeniedNames[0] != ".env" {
		t.Fatalf("input slice mutation reached registry: %+v", view)
	}
	view.DeniedNames[0] = "mutated-view"
	second, err := registry.Get(workspace.ID)
	if err != nil || second.DeniedNames[0] != ".env" {
		t.Fatalf("returned slice mutation reached registry: %+v, %v", second, err)
	}
	admin, err := registry.GetAdmin(workspace.ID)
	if err != nil || admin.Root != "/secret/host/root" {
		t.Fatalf("management root unavailable: %+v, %v", admin, err)
	}
}

func TestCleanupCallbackPanicsDoNotRepeatOrBlockLaterCallbacks(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	var called atomic.Int32
	registry := NewWithClock(func() time.Time { return now }, func(AdminView) {
		panic("cleanup failure")
	}, func(AdminView) {
		called.Add(1)
	})
	workspace := registryWorkspace("panic-workspace-001", "/srv/panic", now)
	if _, err := registry.Register(workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Revoke(workspace.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Revoke(workspace.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Revoke error = %v", err)
	}
	if called.Load() != 1 {
		t.Fatalf("later cleanup callback called %d times", called.Load())
	}
}
