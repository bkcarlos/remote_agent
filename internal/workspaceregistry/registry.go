package workspaceregistry

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("workspace not found")
	ErrExpired       = errors.New("workspace expired")
	ErrAlreadyExists = errors.New("workspace already registered")
)

// View is safe to return to non-management callers. It intentionally contains
// no filesystem root.
type View struct {
	ID          string
	ReadOnly    bool
	ExpiresAt   time.Time
	DeniedNames []string
	Generation  uint64
}

// AdminView is an explicitly privileged view that includes the filesystem root.
type AdminView struct {
	View
	Root string
}

// CleanupCallback is called after a workspace leaves the registry. The callback
// runs outside the registry lock and may safely call back into the registry.
type CleanupCallback func(AdminView)

// Registry is a concurrent, in-memory workspace lifecycle registry.
type Registry struct {
	mu         sync.RWMutex
	workspaces map[string]WorkspaceConfig
	generation uint64
	callbacks  []CleanupCallback
	now        func() time.Time
}

// New constructs a registry using the system clock. Non-nil callbacks are
// registered in argument order.
func New(callbacks ...CleanupCallback) *Registry {
	return NewWithClock(time.Now, callbacks...)
}

// NewWithClock allows deterministic lifecycle control while retaining all
// normal validation. A nil clock falls back to the system clock.
func NewWithClock(clock func() time.Time, callbacks ...CleanupCallback) *Registry {
	if clock == nil {
		clock = time.Now
	}
	registry := &Registry{
		workspaces: make(map[string]WorkspaceConfig),
		now:        clock,
	}
	for _, callback := range callbacks {
		if callback != nil {
			registry.callbacks = append(registry.callbacks, callback)
		}
	}
	return registry
}

// OnCleanup registers a callback for future removals. Registration is
// linearizable with lifecycle operations: a concurrent removal either sees the
// callback in its snapshot or completes before the callback is registered.
func (registry *Registry) OnCleanup(callback CleanupCallback) error {
	if callback == nil {
		return errors.New("cleanup callback must not be nil")
	}
	registry.mu.Lock()
	registry.callbacks = append(registry.callbacks, callback)
	registry.mu.Unlock()
	return nil
}

// Register adds one workspace and advances the registry generation once.
func (registry *Registry) Register(workspace WorkspaceConfig) (uint64, error) {
	now := registry.now()
	if err := validateWorkspace(workspace, now); err != nil {
		return registry.Generation(), err
	}
	workspace = cloneWorkspace(workspace)

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.workspaces[workspace.ID]; exists {
		return registry.generation, ErrAlreadyExists
	}
	registry.generation++
	registry.workspaces[workspace.ID] = workspace
	return registry.generation, nil
}

// ReplaceAll atomically installs the supplied complete set. Invalid input does
// not change registry state. Removed and materially changed old registrations
// each produce one cleanup callback event; unchanged registrations continue
// without cleanup. An empty slice atomically clears the registry.
func (registry *Registry) ReplaceAll(workspaces []WorkspaceConfig) (uint64, error) {
	now := registry.now()
	next := make(map[string]WorkspaceConfig, len(workspaces))
	for _, workspace := range workspaces {
		if err := validateWorkspace(workspace, now); err != nil {
			return registry.Generation(), err
		}
		if _, exists := next[workspace.ID]; exists {
			return registry.Generation(), errors.New("duplicate workspace ID")
		}
		next[workspace.ID] = cloneWorkspace(workspace)
	}

	registry.mu.Lock()
	registry.generation++
	generation := registry.generation
	removed := make([]AdminView, 0)
	for id, old := range registry.workspaces {
		replacement, exists := next[id]
		if !exists || !sameWorkspace(old, replacement) {
			removed = append(removed, adminViewOf(old, generation))
		}
	}
	registry.workspaces = next
	callbacks := append([]CleanupCallback(nil), registry.callbacks...)
	registry.mu.Unlock()

	sortAdminViews(removed)
	runCleanup(callbacks, removed)
	return generation, nil
}

// Get returns a non-management view. If the selected workspace has expired, it
// is atomically removed, cleanup is triggered once, and ErrExpired is returned.
func (registry *Registry) Get(id string) (View, error) {
	workspace, generation, callbacks, expired, err := registry.get(id)
	if err != nil {
		return View{}, err
	}
	if expired {
		runCleanup(callbacks, []AdminView{adminViewOf(workspace, generation)})
		return View{}, ErrExpired
	}
	return viewOf(workspace, generation), nil
}

// GetAdmin is the explicit management equivalent of Get and includes Root.
func (registry *Registry) GetAdmin(id string) (AdminView, error) {
	workspace, generation, callbacks, expired, err := registry.get(id)
	if err != nil {
		return AdminView{}, err
	}
	if expired {
		runCleanup(callbacks, []AdminView{adminViewOf(workspace, generation)})
		return AdminView{}, ErrExpired
	}
	return adminViewOf(workspace, generation), nil
}

func (registry *Registry) get(id string) (WorkspaceConfig, uint64, []CleanupCallback, bool, error) {
	registry.mu.Lock()
	workspace, exists := registry.workspaces[id]
	if !exists {
		generation := registry.generation
		registry.mu.Unlock()
		return WorkspaceConfig{}, generation, nil, false, ErrNotFound
	}
	if !workspace.ExpiresAt.After(registry.now()) {
		delete(registry.workspaces, id)
		registry.generation++
		generation := registry.generation
		callbacks := append([]CleanupCallback(nil), registry.callbacks...)
		registry.mu.Unlock()
		return workspace, generation, callbacks, true, nil
	}
	generation := registry.generation
	registry.mu.Unlock()
	return workspace, generation, nil, false, nil
}

// Revoke atomically removes a workspace. Concurrent or repeated revocations
// observe ErrNotFound after the first removal, so cleanup runs exactly once.
func (registry *Registry) Revoke(id string) (uint64, error) {
	registry.mu.Lock()
	workspace, exists := registry.workspaces[id]
	if !exists {
		generation := registry.generation
		registry.mu.Unlock()
		return generation, ErrNotFound
	}
	delete(registry.workspaces, id)
	registry.generation++
	generation := registry.generation
	callbacks := append([]CleanupCallback(nil), registry.callbacks...)
	registry.mu.Unlock()

	runCleanup(callbacks, []AdminView{adminViewOf(workspace, generation)})
	return generation, nil
}

// List returns a stable ID-sorted non-management snapshot. Any expired entries
// encountered while taking the snapshot are removed and cleaned up once.
func (registry *Registry) List() []View {
	workspaces, generation, callbacks, expired := registry.snapshot()
	views := make([]View, 0, len(workspaces))
	for _, workspace := range workspaces {
		views = append(views, viewOf(workspace, generation))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	runCleanup(callbacks, expired)
	return views
}

// ListAdmin returns the corresponding management snapshot including roots.
func (registry *Registry) ListAdmin() []AdminView {
	workspaces, generation, callbacks, expired := registry.snapshot()
	views := make([]AdminView, 0, len(workspaces))
	for _, workspace := range workspaces {
		views = append(views, adminViewOf(workspace, generation))
	}
	sortAdminViews(views)
	runCleanup(callbacks, expired)
	return views
}

func (registry *Registry) snapshot() ([]WorkspaceConfig, uint64, []CleanupCallback, []AdminView) {
	now := registry.now()
	registry.mu.Lock()
	expiredWorkspaces := make([]WorkspaceConfig, 0)
	for id, workspace := range registry.workspaces {
		if !workspace.ExpiresAt.After(now) {
			delete(registry.workspaces, id)
			expiredWorkspaces = append(expiredWorkspaces, workspace)
		}
	}
	if len(expiredWorkspaces) > 0 {
		registry.generation++
	}
	generation := registry.generation
	workspaces := make([]WorkspaceConfig, 0, len(registry.workspaces))
	for _, workspace := range registry.workspaces {
		workspaces = append(workspaces, cloneWorkspace(workspace))
	}
	callbacks := append([]CleanupCallback(nil), registry.callbacks...)
	registry.mu.Unlock()

	expired := make([]AdminView, 0, len(expiredWorkspaces))
	for _, workspace := range expiredWorkspaces {
		expired = append(expired, adminViewOf(workspace, generation))
	}
	sortAdminViews(expired)
	return workspaces, generation, callbacks, expired
}

// Generation returns the current monotonic mutation version.
func (registry *Registry) Generation() uint64 {
	registry.mu.RLock()
	generation := registry.generation
	registry.mu.RUnlock()
	return generation
}

func cloneWorkspace(workspace WorkspaceConfig) WorkspaceConfig {
	workspace.DeniedNames = append([]string(nil), workspace.DeniedNames...)
	return workspace
}

func sameWorkspace(left, right WorkspaceConfig) bool {
	if left.ID != right.ID || left.Root != right.Root || left.ReadOnly != right.ReadOnly || !left.ExpiresAt.Equal(right.ExpiresAt) || len(left.DeniedNames) != len(right.DeniedNames) {
		return false
	}
	for index := range left.DeniedNames {
		if left.DeniedNames[index] != right.DeniedNames[index] {
			return false
		}
	}
	return true
}

func viewOf(workspace WorkspaceConfig, generation uint64) View {
	return View{
		ID:          workspace.ID,
		ReadOnly:    workspace.ReadOnly,
		ExpiresAt:   workspace.ExpiresAt,
		DeniedNames: append([]string(nil), workspace.DeniedNames...),
		Generation:  generation,
	}
}

func adminViewOf(workspace WorkspaceConfig, generation uint64) AdminView {
	return AdminView{View: viewOf(workspace, generation), Root: workspace.Root}
}

func sortAdminViews(views []AdminView) {
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
}

func runCleanup(callbacks []CleanupCallback, workspaces []AdminView) {
	for _, workspace := range workspaces {
		for _, callback := range callbacks {
			invokeCleanup(callback, workspace)
		}
	}
}

func invokeCleanup(callback CleanupCallback, workspace AdminView) {
	defer func() {
		_ = recover()
	}()
	callback(workspace)
}
