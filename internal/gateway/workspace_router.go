package gateway

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/bkcarlos/remote_agent/internal/workspaceregistry"
)

// WorkspaceBinding is a fully constructed production handler paired with the
// trusted management registration from which it was built.
type WorkspaceBinding struct {
	Workspace workspaceregistry.WorkspaceConfig
	Handler   *Server
}

// WorkspaceRouter routes only canonical opaque workspace endpoints. It never
// provides a default /mcp route and never exposes management roots.
type WorkspaceRouter struct {
	mu       sync.Mutex
	registry *workspaceregistry.Registry
	handlers map[string]*Server
	expires  map[string]time.Time
	now      func() time.Time
	after    func(time.Duration) <-chan time.Time
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	closed   bool
}

func NewWorkspaceRouter() *WorkspaceRouter {
	return NewWorkspaceRouterWithClock(time.Now)
}

func NewWorkspaceRouterWithClock(now func() time.Time) *WorkspaceRouter {
	return newWorkspaceRouter(now, time.After)
}

func newWorkspaceRouter(now func() time.Time, after func(time.Duration) <-chan time.Time) *WorkspaceRouter {
	if now == nil {
		now = time.Now
	}
	if after == nil {
		after = time.After
	}
	router := &WorkspaceRouter{
		registry: workspaceregistry.NewWithClock(now), handlers: make(map[string]*Server),
		expires: make(map[string]time.Time), now: now, after: after,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go router.expireLoop()
	return router
}

func (router *WorkspaceRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	route, err := workspaceregistry.ParsePath(r.URL.EscapedPath())
	if err != nil || route.Default {
		http.NotFound(w, r)
		return
	}

	router.mu.Lock()
	if router.closed {
		router.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	_, registryErr := router.registry.Get(route.WorkspaceID)
	handler := router.handlers[route.WorkspaceID]
	if registryErr != nil || handler == nil {
		if handler != nil {
			delete(router.handlers, route.WorkspaceID)
			delete(router.expires, route.WorkspaceID)
			handler.Revoke()
		}
		router.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	router.mu.Unlock()

	// Revoke may linearize after the lookup and before this call. Server.admit
	// closes that race by rejecting the request or tracking it for cancellation.
	handler.ServeHTTP(w, r)
}

// ReplaceAll atomically installs a complete set of already-built handlers. The
// caller can therefore build every workspace first and leave the current set
// untouched on any construction failure.
func (router *WorkspaceRouter) ReplaceAll(bindings []WorkspaceBinding) error {
	nextHandlers := make(map[string]*Server, len(bindings))
	nextExpiries := make(map[string]time.Time, len(bindings))
	nextWorkspaces := make([]workspaceregistry.WorkspaceConfig, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Handler == nil {
			return errors.New("workspace handler must not be nil")
		}
		if _, duplicate := nextHandlers[binding.Workspace.ID]; duplicate {
			return errors.New("duplicate workspace handler")
		}
		nextHandlers[binding.Workspace.ID] = binding.Handler
		nextExpiries[binding.Workspace.ID] = binding.Workspace.ExpiresAt
		nextWorkspaces = append(nextWorkspaces, binding.Workspace)
	}

	router.mu.Lock()
	if router.closed {
		router.mu.Unlock()
		return errors.New("workspace router is closed")
	}
	if _, err := router.registry.ReplaceAll(nextWorkspaces); err != nil {
		router.mu.Unlock()
		return err
	}
	oldHandlers := router.handlers
	router.handlers = nextHandlers
	router.expires = nextExpiries
	for id, handler := range oldHandlers {
		if nextHandlers[id] != handler {
			handler.Revoke()
		}
	}
	router.mu.Unlock()
	router.signalWake()
	return nil
}

// Revoke atomically removes one workspace and closes its server before another
// request can be routed to the removed registration.
func (router *WorkspaceRouter) Revoke(id string) error {
	router.mu.Lock()
	if router.closed {
		router.mu.Unlock()
		return workspaceregistry.ErrNotFound
	}
	_, err := router.registry.Revoke(id)
	if err != nil {
		router.mu.Unlock()
		return err
	}
	handler := router.handlers[id]
	delete(router.handlers, id)
	delete(router.expires, id)
	if handler != nil {
		handler.Revoke()
	}
	router.mu.Unlock()
	router.signalWake()
	return nil
}

// Close revokes every currently installed workspace handler and waits for the
// expiry scheduler to stop.
func (router *WorkspaceRouter) Close() error {
	router.mu.Lock()
	if router.closed {
		done := router.done
		router.mu.Unlock()
		<-done
		return nil
	}
	router.closed = true
	handlers := router.handlers
	router.handlers = make(map[string]*Server)
	router.expires = make(map[string]time.Time)
	_, err := router.registry.ReplaceAll(nil)
	for _, handler := range handlers {
		handler.Revoke()
	}
	router.mu.Unlock()
	close(router.stop)
	<-router.done
	return err
}

func (router *WorkspaceRouter) signalWake() {
	select {
	case router.wake <- struct{}{}:
	default:
	}
}

func (router *WorkspaceRouter) expireLoop() {
	defer close(router.done)
	for {
		router.mu.Lock()
		if router.closed {
			router.mu.Unlock()
			return
		}
		now := router.now().UTC()
		var next time.Time
		for id, expiresAt := range router.expires {
			if !expiresAt.After(now) {
				handler := router.handlers[id]
				delete(router.handlers, id)
				delete(router.expires, id)
				_, _ = router.registry.Revoke(id)
				if handler != nil {
					handler.Revoke()
				}
				continue
			}
			if next.IsZero() || expiresAt.Before(next) {
				next = expiresAt
			}
		}
		router.mu.Unlock()

		if next.IsZero() {
			select {
			case <-router.wake:
				continue
			case <-router.stop:
				return
			}
		}
		wait := next.Sub(router.now().UTC())
		if wait < 0 {
			wait = 0
		}
		select {
		case <-router.after(wait):
		case <-router.wake:
		case <-router.stop:
			return
		}
	}
}
