package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/workspaceregistry"
)

func routedWorkspace(id string, now time.Time) workspaceregistry.WorkspaceConfig {
	return workspaceregistry.WorkspaceConfig{
		ID:        id,
		Root:      "/management-only/root/" + id,
		ReadOnly:  true,
		ExpiresAt: now.Add(time.Hour),
	}
}

func testWorkspaceRouter(t *testing.T, now func() time.Time) *WorkspaceRouter {
	t.Helper()
	router := NewWorkspaceRouterWithClock(now)
	t.Cleanup(func() { _ = router.Close() })
	return router
}

func routeRequest(handler http.Handler, path, body, session string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+standardTestToken)
	request.Header.Set("Content-Type", "application/json")
	if session != "" {
		request.Header.Set(protocol.HeaderSessionID, session)
		request.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestWorkspaceRouterHasNoDefaultAndDoesNotLeakRoot(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	workspace := routedWorkspace("opaque-workspace-0001", now)
	server, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	router := testWorkspaceRouter(t, func() time.Time { return now })
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: workspace, Handler: server}}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/mcp", "/mcp/unknown-workspace-0001", "/mcp/opaque-workspace-0001/extra"} {
		response := routeRequest(router, path, `{}`, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, response.Code)
		}
		if strings.Contains(response.Body.String(), workspace.Root) {
			t.Fatalf("404 leaked management root: %q", response.Body.String())
		}
	}

	endpoint, err := workspaceregistry.WorkspacePath(workspace.ID)
	if err != nil {
		t.Fatal(err)
	}
	response := routeRequest(router, endpoint, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"router-test","version":"1"}}}`, "")
	if response.Code != http.StatusOK || response.Header().Get(protocol.HeaderSessionID) == "" {
		t.Fatalf("registered endpoint status=%d body=%s", response.Code, response.Body.String())
	}
}

type controlledRouterClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *controlledRouterClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *controlledRouterClock) Set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

func TestWorkspaceRouterBackgroundExpiryRevokesWithoutRequest(t *testing.T) {
	start := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := &controlledRouterClock{now: start}
	tick := make(chan time.Time, 1)
	waits := make(chan time.Duration, 1)
	router := newWorkspaceRouter(clock.Now, func(wait time.Duration) <-chan time.Time {
		waits <- wait
		return tick
	})
	t.Cleanup(func() { _ = router.Close() })
	workspace := routedWorkspace("background-expiry-01", start)
	workspace.ExpiresAt = start.Add(time.Minute)
	server, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: workspace, Handler: server}}); err != nil {
		t.Fatal(err)
	}
	select {
	case wait := <-waits:
		if wait != time.Minute {
			t.Fatalf("expiry wait = %s", wait)
		}
	case <-time.After(time.Second):
		t.Fatal("expiry scheduler did not arm")
	}
	clock.Set(workspace.ExpiresAt)
	tick <- workspace.ExpiresAt
	deadline := time.After(time.Second)
	for {
		server.lifecycleMu.Lock()
		revoked := server.revoked
		server.lifecycleMu.Unlock()
		if revoked {
			break
		}
		select {
		case <-deadline:
			t.Fatal("background expiry did not revoke the workspace server")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestWorkspaceRouterExpiryRevokesServerAndSessions(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	workspace := routedWorkspace("expiring-workspace-01", now)
	workspace.ExpiresAt = now.Add(time.Minute)
	server, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	router := testWorkspaceRouter(t, func() time.Time { return now })
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: workspace, Handler: server}}); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := workspaceregistry.WorkspacePath(workspace.ID)
	initialized := routeRequest(router, endpoint, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"expiry-test","version":"1"}}}`, "")
	if initialized.Code != http.StatusOK || len(server.sessions.sessions) != 1 {
		t.Fatalf("initialize status=%d sessions=%d", initialized.Code, len(server.sessions.sessions))
	}

	now = workspace.ExpiresAt
	expired := routeRequest(router, endpoint, `{}`, "")
	if expired.Code != http.StatusNotFound || len(server.sessions.sessions) != 0 {
		t.Fatalf("expired status=%d sessions=%d", expired.Code, len(server.sessions.sessions))
	}
	direct := routeRequest(server, DefaultEndpoint, `{}`, "")
	if direct.Code != http.StatusNotFound {
		t.Fatalf("expired server accepted a direct request: %d", direct.Code)
	}
}

type cancellationExecutor struct {
	once     sync.Once
	started  chan struct{}
	canceled chan struct{}
}

func (executor *cancellationExecutor) Execute(ctx context.Context, request fileworker.Request) (fileworker.Response, error) {
	executor.once.Do(func() { close(executor.started) })
	<-ctx.Done()
	close(executor.canceled)
	return fileworker.Response{TokenID: request.TokenID, WorkerID: "blocking-worker"}, ctx.Err()
}

func TestWorkspaceRouterRevokeCancelsActiveRequestAndClearsSession(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	workspace := routedWorkspace("revoked-workspace-001", now)
	executor := &cancellationExecutor{started: make(chan struct{}), canceled: make(chan struct{})}
	server, err := New(Config{AuthToken: standardTestToken}, executor, policy.New(policy.Config{}), audit.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	router := testWorkspaceRouter(t, func() time.Time { return now })
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: workspace, Handler: server}}); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := workspaceregistry.WorkspacePath(workspace.ID)
	initialized := routeRequest(router, endpoint, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"revoke-test","version":"1"}}}`, "")
	session := initialized.Header().Get(protocol.HeaderSessionID)
	if initialized.Code != http.StatusOK || session == "" {
		t.Fatalf("initialize status=%d body=%s", initialized.Code, initialized.Body.String())
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- routeRequest(router, endpoint, call(2, "read_file", `{"path":"a.txt"}`), session)
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("workspace request did not reach executor")
	}
	if err := router.Revoke(workspace.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-executor.canceled:
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel active executor")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled request did not return")
	}
	if len(server.sessions.sessions) != 0 {
		t.Fatalf("revocation retained %d sessions", len(server.sessions.sessions))
	}
	if response := routeRequest(router, endpoint, `{}`, ""); response.Code != http.StatusNotFound {
		t.Fatalf("post-revoke route status = %d", response.Code)
	}
}

func TestWorkspaceRouterReplaceAllRejectsOldRoutes(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	oldWorkspace := routedWorkspace("old-workspace-00001", now)
	newWorkspace := routedWorkspace("new-workspace-00001", now)
	oldServer, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	newServer, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	router := testWorkspaceRouter(t, func() time.Time { return now })
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: oldWorkspace, Handler: oldServer}}); err != nil {
		t.Fatal(err)
	}
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: newWorkspace, Handler: newServer}}); err != nil {
		t.Fatal(err)
	}

	oldEndpoint, _ := workspaceregistry.WorkspacePath(oldWorkspace.ID)
	newEndpoint, _ := workspaceregistry.WorkspacePath(newWorkspace.ID)
	if response := routeRequest(router, oldEndpoint, `{}`, ""); response.Code != http.StatusNotFound {
		t.Fatalf("old route status = %d", response.Code)
	}
	if response := routeRequest(oldServer, DefaultEndpoint, `{}`, ""); response.Code != http.StatusNotFound {
		t.Fatalf("old server was not revoked: %d", response.Code)
	}
	if response := routeRequest(router, newEndpoint, `{}`, ""); response.Code == http.StatusNotFound {
		t.Fatalf("new route was not installed: status=%d", response.Code)
	}
}

func TestWorkspaceRouterConcurrentRequestsLinearizeWithRevoke(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	workspace := routedWorkspace("concurrent-workspace-1", now)
	server, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	router := testWorkspaceRouter(t, func() time.Time { return now })
	if err := router.ReplaceAll([]WorkspaceBinding{{Workspace: workspace, Handler: server}}); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := workspaceregistry.WorkspacePath(workspace.ID)
	const goroutines = 64
	start := make(chan struct{})
	statuses := make(chan int, goroutines)
	var group sync.WaitGroup
	for range goroutines {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			statuses <- routeRequest(router, endpoint, `{}`, "").Code
		}()
	}
	close(start)
	if err := router.Revoke(workspace.ID); err != nil {
		t.Fatal(err)
	}
	group.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK && status != http.StatusNotFound {
			t.Fatalf("concurrent request status = %d", status)
		}
	}
	for index := 0; index < 10; index++ {
		if status := routeRequest(router, endpoint, `{}`, "").Code; status != http.StatusNotFound {
			t.Fatalf("post-revoke request %d status = %d", index, status)
		}
	}
}

func TestServerRevokeIsConcurrentAndIdempotent(t *testing.T) {
	server, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	const goroutines = 32
	var group sync.WaitGroup
	for range goroutines {
		group.Add(1)
		go func() {
			defer group.Done()
			server.Revoke()
		}()
	}
	group.Wait()
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodPost, DefaultEndpoint, bytes.NewReader(nil)))
	if response.Code != http.StatusNotFound {
		t.Fatalf("revoked status = %d", response.Code)
	}
}
