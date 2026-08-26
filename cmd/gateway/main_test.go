package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/gateway"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/workspace"
	"github.com/bkcarlos/remote_agent/internal/workspaceregistry"
)

func TestRandomWorkspaceIdentityIsOpaqueAndUnique(t *testing.T) {
	first, err := randomID("workspace-", 16)
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomID("workspace-", 16)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != len("workspace-")+32 || len(second) != len("workspace-")+32 {
		t.Fatalf("workspace identities are not unique 128-bit opaque values: %q %q", first, second)
	}
}

func TestGatewayHandlerOnlyMountsMCPPath(t *testing.T) {
	handler := gatewayHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	for _, test := range []struct {
		path string
		want int
	}{{path: "/mcp", want: http.StatusAccepted}, {path: "/", want: http.StatusNotFound}, {path: "/other", want: http.StatusNotFound}} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, test.path, nil))
		if recorder.Code != test.want {
			t.Fatalf("%s status = %d, want %d", test.path, recorder.Code, test.want)
		}
	}
}

func TestPrivateListen(t *testing.T) {
	for _, a := range []string{"127.0.0.1:1", "10.0.0.1:2", "192.168.1.1:3", "[::1]:4"} {
		if !privateListen(a) {
			t.Errorf("should be private: %s", a)
		}
	}
	for _, a := range []string{"0.0.0.0:1", "8.8.8.8:2", ":8080", "bad"} {
		if privateListen(a) {
			t.Errorf("should be rejected: %s", a)
		}
	}
}

func TestGatewayWriteTimeoutCoversWorkerAndSynchronousExecLimits(t *testing.T) {
	config := execworker.AdministratorConfig{Profiles: []execworker.TaskProfile{{Limits: execworker.Limits{TimeoutMillis: 180000}}}}
	if got, want := gatewayWriteTimeout(30*time.Second, config), 185*time.Second; got != want {
		t.Fatalf("gateway write timeout = %v, want %v", got, want)
	}
	if got, want := gatewayWriteTimeout(240*time.Second, config), 245*time.Second; got != want {
		t.Fatalf("worker-dominated write timeout = %v, want %v", got, want)
	}
}

func TestWorkspacePolicyReadOnlyAndDeniedNamesOnlyRestrict(t *testing.T) {
	global := policy.Config{AllowWrite: true, AllowNetwork: true, DeniedNames: []string{"global-secret"}}
	readOnly := workspaceregistry.WorkspaceConfig{
		ID: "readonly-workspace-01", ReadOnly: true, DeniedNames: []string{"workspace-secret"},
	}
	effective := workspacePolicyConfig(global, readOnly)
	engine := policy.New(effective)
	if engine.Evaluate("write_file", "ordinary.txt").Allowed || engine.Evaluate("download", "ordinary.txt").Allowed {
		t.Fatal("read-only workspace inherited a workspace write or download permission")
	}
	if !engine.Evaluate("web_fetch", "ordinary.txt").Allowed {
		t.Fatal("read-only workspace unexpectedly disabled read-only Network access")
	}
	for _, path := range []string{"global-secret", "workspace-secret"} {
		if engine.Evaluate("read_file", path).Allowed {
			t.Fatalf("denied_names union did not deny %q", path)
		}
	}
	if !global.AllowWrite || len(global.DeniedNames) != 1 {
		t.Fatalf("workspace restriction mutated global policy: %+v", global)
	}

	writable := readOnly
	writable.ReadOnly = false
	if !policy.New(workspacePolicyConfig(global, writable)).Evaluate("write_file", "ordinary.txt").Allowed {
		t.Fatal("writable workspace did not retain global write permission")
	}
}

func TestReadOnlyWorkspaceFiltersReadWriteExecProfiles(t *testing.T) {
	limits := execworker.Limits{TimeoutMillis: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, PIDs: 1, OutputBytes: 1024}
	config := execworker.AdministratorConfig{Version: execworker.AdminConfigVersion, Profiles: []execworker.TaskProfile{
		{Name: "none", Executable: "/usr/bin/true", WorkspaceMode: execworker.WorkspaceNone, Limits: limits},
		{Name: "read", Executable: "/usr/bin/true", WorkspaceMode: execworker.WorkspaceReadOnly, Limits: limits},
		{Name: "write", Executable: "/usr/bin/true", WorkspaceMode: execworker.WorkspaceReadWrite, Limits: limits},
	}}
	filtered, available := execAdministratorForWorkspace(config, true)
	if !available || len(filtered.Profiles) != 2 {
		t.Fatalf("read-only filtered profiles = %+v", filtered.Profiles)
	}
	for _, profile := range filtered.Profiles {
		if profile.WorkspaceMode == execworker.WorkspaceReadWrite {
			t.Fatal("read-only workspace retained a read-write Exec profile")
		}
	}
	unfiltered, available := execAdministratorForWorkspace(config, false)
	if !available || len(unfiltered.Profiles) != len(config.Profiles) {
		t.Fatalf("writable workspace profiles = %+v", unfiltered.Profiles)
	}
}

func TestReloadWorkspaceConfigFailureRetainsOldRoutes(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	oldWorkspace := workspaceregistry.WorkspaceConfig{
		ID: "old-reload-workspace", Root: t.TempDir(), ReadOnly: true,
		ExpiresAt: now.Add(time.Hour), DeniedNames: []string{},
	}
	oldServer := testGatewayServer(t, oldWorkspace.Root)
	router := gateway.NewWorkspaceRouterWithClock(func() time.Time { return now })
	t.Cleanup(func() { _ = router.Close() })
	if err := router.ReplaceAll([]gateway.WorkspaceBinding{{Workspace: oldWorkspace, Handler: oldServer}}); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "workspaces.json")
	if err := os.WriteFile(configPath, []byte(`{"version":"v1","workspaces":[{"id":"short"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reloadWorkspaceConfig(configPath, router, func(workspace workspaceregistry.WorkspaceConfig) (*gateway.Server, error) {
		return testGatewayServer(t, workspace.Root), nil
	}, func() time.Time { return now }); err == nil {
		t.Fatal("invalid reload unexpectedly succeeded")
	}
	oldEndpoint, _ := workspaceregistry.WorkspacePath(oldWorkspace.ID)
	if status := routedStatus(router, oldEndpoint); status == http.StatusNotFound {
		t.Fatal("failed reload removed the old route")
	}

	newWorkspace := workspaceregistry.WorkspaceConfig{
		ID: "new-reload-workspace", Root: t.TempDir(), ReadOnly: true,
		ExpiresAt: now.Add(2 * time.Hour), DeniedNames: []string{"local-secret"},
	}
	config, err := json.Marshal(workspaceregistry.Config{Version: workspaceregistry.CurrentVersion, Workspaces: []workspaceregistry.WorkspaceConfig{newWorkspace}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reloadWorkspaceConfig(configPath, router, func(workspaceregistry.WorkspaceConfig) (*gateway.Server, error) {
		return nil, errors.New("injected workspace construction failure")
	}, func() time.Time { return now }); err == nil {
		t.Fatal("handler construction failure unexpectedly reloaded")
	}
	if status := routedStatus(router, oldEndpoint); status == http.StatusNotFound {
		t.Fatal("handler construction failure removed the old route")
	}
	if _, err := reloadWorkspaceConfig(configPath, router, func(workspace workspaceregistry.WorkspaceConfig) (*gateway.Server, error) {
		return testGatewayServer(t, workspace.Root), nil
	}, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	if status := routedStatus(router, oldEndpoint); status != http.StatusNotFound {
		t.Fatalf("old route status after reload = %d", status)
	}
	newEndpoint, _ := workspaceregistry.WorkspacePath(newWorkspace.ID)
	if status := routedStatus(router, newEndpoint); status == http.StatusNotFound {
		t.Fatal("successful reload did not install the new route")
	}
}

func testGatewayServer(t *testing.T, root string) *gateway.Server {
	t.Helper()
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.New(
		gateway.Config{AuthToken: "tttttttttttttttttttttttttttttttt"},
		files,
		policy.New(policy.Config{}),
		audit.New(io.Discard),
	)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func routedStatus(handler http.Handler, endpoint string) int {
	request := httptest.NewRequest(http.MethodPost, endpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}
