package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/remoteworker"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

type fakeNetworkExecutor struct {
	mu       sync.Mutex
	requests []networkworker.Request
	scopes   []WorkerExecutionScope
}

func (executor *fakeNetworkExecutor) Execute(ctx context.Context, request networkworker.Request) (networkworker.Response, error) {
	executor.mu.Lock()
	executor.requests = append(executor.requests, request)
	if scope, ok := WorkerExecutionScopeFromContext(ctx); ok {
		executor.scopes = append(executor.scopes, scope)
	}
	executor.mu.Unlock()
	response := networkworker.Response{TokenID: request.TokenID, WorkerID: "network-test", Status: 200, Untrusted: true}
	if request.Operation == networkworker.OperationDownload {
		body := []byte("downloaded bytes")
		response.Base64, response.Bytes, response.SHA256 = base64.StdEncoding.EncodeToString(body), int64(len(body)), digest(body)
	}
	return response, nil
}

type fakeRemoteExecutor struct{}

func (fakeRemoteExecutor) Execute(context.Context, remoteworker.Request) (remoteworker.Response, error) {
	return remoteworker.Response{JobID: "remote-job"}, nil
}

type captureFileExecutor struct {
	mu         sync.Mutex
	operations []string
	binary     []byte
	written    []byte
}

func (executor *captureFileExecutor) Execute(_ context.Context, request fileworker.Request) (fileworker.Response, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.operations = append(executor.operations, request.Operation)
	response := fileworker.Response{TokenID: request.TokenID, WorkerID: "file-test"}
	switch request.Operation {
	case "read_binary":
		response.Base64 = base64.StdEncoding.EncodeToString(executor.binary)
		response.Bytes, response.Checksum = len(executor.binary), digest(executor.binary)
		return response, nil
	case "checksum":
		return response, workspace.ErrNotFound
	case "write_file":
		executor.written = append([]byte(nil), request.Data...)
		response.Checksum = digest(request.Data)
		return response, nil
	default:
		return response, errors.New("unexpected file operation")
	}
}

type cancelAwareExecExecutor struct {
	mu        sync.Mutex
	activeCtx context.Context
	started   chan struct{}
	revoked   bool
}

func (executor *cancelAwareExecExecutor) Do(ctx context.Context, job execworker.Job) (execworker.Response, error) {
	if job.Operation == execworker.OperationSessionRevoke {
		executor.mu.Lock()
		activeCtx := executor.activeCtx
		executor.mu.Unlock()
		if activeCtx != nil {
			select {
			case <-activeCtx.Done():
			default:
				return execworker.Response{CapabilityID: job.CapabilityID}, errors.New("active call was not cancelled before revoke")
			}
		}
		executor.mu.Lock()
		executor.revoked = true
		executor.mu.Unlock()
		return execworker.Response{CapabilityID: job.CapabilityID}, nil
	}
	executor.mu.Lock()
	executor.activeCtx = ctx
	started := executor.started
	executor.mu.Unlock()
	close(started)
	<-ctx.Done()
	return execworker.Response{CapabilityID: job.CapabilityID}, ctx.Err()
}

type fakeExecExecutor struct {
	mu             sync.Mutex
	jobs           []execworker.Job
	revokeFailures int
}

func (executor *fakeExecExecutor) Do(_ context.Context, job execworker.Job) (execworker.Response, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.jobs = append(executor.jobs, job)
	if job.Operation == execworker.OperationSessionRevoke && executor.revokeFailures > 0 {
		executor.revokeFailures--
		return execworker.Response{CapabilityID: job.CapabilityID}, errors.New("supervisor unavailable at /host/private/socket")
	}
	return execworker.Response{CapabilityID: job.CapabilityID, ProcessID: "process-opaque-1"}, nil
}

func networkTestProfile() networkworker.Profile {
	return networkworker.Profile{
		ID: "net-profile",
		Policy: networkworker.Policy{
			AllowedDomains: []string{"secret.example"}, AllowedPorts: []uint16{443},
			AllowedSchemes: []string{"https"}, AllowedRequestHeaders: []string{"accept"},
		},
		Limits: networkworker.ResourceLimits{
			MaxRequestBodyBytes: 1 << 20, MaxResponseBodyBytes: 1 << 20,
			MaxRequestHeaderBytes: 8192, MaxResponseHeaderBytes: 8192,
			MaxRedirects: 2, TimeoutMillis: 5000,
		},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

type failingAuditWriter struct{}

func (failingAuditWriter) Write([]byte) (int, error) { return 0, errors.New("audit unavailable") }

func TestServerTokenHidesAndFailClosesApprovalExternalTools(t *testing.T) {
	network := &fakeNetworkExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeServerToken, WorkspaceID: "workspace-test",
		NetworkExecutor: network, NetworkProfiles: map[string]networkworker.Profile{"net-profile": networkTestProfile()},
		RemoteExecutor: fakeRemoteExecutor{},
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowWrite: true, AllowNetwork: true, AllowRemote: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	listed, _ := json.Marshal(server.tools())
	for _, hidden := range []string{"download", "upload", "ssh_exec", "sftp_write", "sftp_mkdir", "sftp_rename"} {
		if strings.Contains(string(listed), `"name":"`+hidden+`"`) {
			t.Fatalf("server_token exposed approval-gated external tool %q: %s", hidden, listed)
		}
	}
	if !strings.Contains(string(listed), `"name":"web_fetch"`) || !strings.Contains(string(listed), `"name":"sftp_list"`) {
		t.Fatalf("server_token hid non-approval external tools: %s", listed)
	}
	_, _, response := request(t, server, call(1, "download", `{"profile":"net-profile","url":"https://secret.example/file","path":"file.bin"}`), strings.Repeat("t", 32), "")
	if !strings.Contains(mustJSON(response.Result), externalServerApprovalError) {
		t.Fatalf("direct approval-gated external call did not fail closed: %+v", response)
	}
	network.mu.Lock()
	calls := len(network.requests)
	network.mu.Unlock()
	if calls != 0 {
		t.Fatal("fail-closed server approval path reached Network Worker")
	}
}

func TestExternalAuditPrewriteFailureDeniesBeforeWorkerSideEffects(t *testing.T) {
	network := &fakeNetworkExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		NetworkExecutor: network, NetworkProfiles: map[string]networkworker.Profile{"net-profile": networkTestProfile()},
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowNetwork: true}), audit.New(failingAuditWriter{}))
	if err != nil {
		t.Fatal(err)
	}
	_, _, response := request(t, server, call(1, "web_fetch", `{"profile":"net-profile","url":"https://secret.example/","method":"GET"}`), strings.Repeat("t", 32), "")
	if !strings.Contains(mustJSON(response.Result), "audit unavailable") {
		t.Fatalf("audit failure response = %+v", response)
	}
	network.mu.Lock()
	calls := len(network.requests)
	network.mu.Unlock()
	if calls != 0 {
		t.Fatal("Network Worker ran before durable audit prewrite")
	}
}

func TestGatewayRejectsTypedNilExecutors(t *testing.T) {
	var files *captureFileExecutor
	if _, err := New(Config{AuthToken: strings.Repeat("t", 32)}, files, policy.New(policy.Config{}), audit.New(&bytes.Buffer{})); err == nil {
		t.Fatal("typed-nil File executor was accepted")
	}
	validFiles := &captureFileExecutor{}
	var network *fakeNetworkExecutor
	if _, err := New(Config{AuthToken: strings.Repeat("t", 32), NetworkExecutor: network}, validFiles, policy.New(policy.Config{}), audit.New(&bytes.Buffer{})); err == nil {
		t.Fatal("typed-nil Network executor was accepted")
	}
	var remote *fakeRemoteExecutor
	if _, err := New(Config{AuthToken: strings.Repeat("t", 32), RemoteExecutor: remote}, validFiles, policy.New(policy.Config{}), audit.New(&bytes.Buffer{})); err == nil {
		t.Fatal("typed-nil Remote executor was accepted")
	}
	var exec *fakeExecExecutor
	if _, err := New(Config{AuthToken: strings.Repeat("t", 32), ExecExecutor: exec}, validFiles, policy.New(policy.Config{}), audit.New(&bytes.Buffer{})); err == nil {
		t.Fatal("typed-nil Exec executor was accepted")
	}
}

func TestDynamicToolsAndMCPAnnotations(t *testing.T) {
	files := &captureFileExecutor{}
	network := &fakeNetworkExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		NetworkExecutor: network, NetworkProfiles: map[string]networkworker.Profile{"net-profile": networkTestProfile()},
		RemoteExecutor: fakeRemoteExecutor{},
	}, files, policy.New(policy.Config{AllowNetwork: true, AllowRemote: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(server.tools())
	for _, value := range []string{`"web_fetch"`, `"ssh_exec"`, `"annotations"`, `"readOnlyHint"`, `"destructiveHint"`, `"idempotentHint"`, `"openWorldHint"`, `"approval_mode":"client_managed"`} {
		if !strings.Contains(string(encoded), value) {
			t.Fatalf("dynamic tool metadata %s missing from %s", value, encoded)
		}
	}
	if strings.Contains(string(encoded), `"exec_run"`) {
		t.Fatal("unconfigured Exec tools were exposed")
	}
}

func TestClientManagedWriteDoesNotRequireOrVerifyApprovalToken(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	server, err := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged}, files, policy.New(policy.Config{AllowWrite: true}), audit.New(&log))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	_, _, preview := request(t, server, call(1, "write_file", `{"path":"a.txt","content":"after"}`), token, "")
	if preview.Error != nil || !strings.Contains(mustJSON(preview.Result), `"approval_mode":"client_managed"`) || strings.Contains(mustJSON(preview.Result), `"approval_required":true`) {
		t.Fatalf("client-managed preview = %+v", preview)
	}
	_, _, applied := request(t, server, call(2, "write_file", `{"path":"a.txt","content":"after","expected_hash":"`+digest([]byte("before"))+`","apply":true}`), token, "")
	if applied.Error != nil || strings.Contains(mustJSON(applied.Result), "approval_token") {
		t.Fatalf("client-managed apply = %+v", applied)
	}
	written, _ := os.ReadFile(filepath.Join(root, "a.txt"))
	if string(written) != "after" {
		t.Fatalf("written content = %q", written)
	}
	if !strings.Contains(log.String(), `"approval_mode":"client_managed"`) || !strings.Contains(log.String(), `"approval_verified":false`) || !strings.Contains(log.String(), `"approval_source":"mcp_client_policy"`) {
		t.Fatalf("client-managed audit semantics missing: %s", log.String())
	}
}

func TestExternalAuditSummaryRedactsSensitiveArgumentValues(t *testing.T) {
	cases := map[string]string{
		"web_fetch":     `{"profile":"profile-secret","url":"https://host-secret.example/path","method":"GET","headers":{"Accept":"header-secret"}}`,
		"ssh_exec":      `{"profile":"remote-secret","argv":["/host/private/program","argv-secret"]}`,
		"sftp_rename":   `{"profile":"remote-secret","remote_path":"/remote/source-secret","destination_path":"/remote/destination-secret"}`,
		"process_start": `{"profile":"exec-secret","argv":["argv-secret"],"env":{"TOKEN":"env-secret"}}`,
		"mem_scan":      `{"profile":"exec-secret","process_id":"process-secret","pattern":"memory-secret","mode":"base64"}`,
	}
	for tool, raw := range cases {
		summary, err := summarizeToolParameters(tool, json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s summary: %v", tool, err)
		}
		encoded, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"profile-secret", "host-secret", "header-secret", "remote-secret", "source-secret", "destination-secret", "argv-secret", "env-secret", "exec-secret", "process-secret", "memory-secret", "/host/private"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("%s audit summary leaked %q: %s", tool, secret, encoded)
			}
		}
	}
}

func TestGatewayRejectsCaseInsensitiveDuplicateHTTPHeaders(t *testing.T) {
	network := &fakeNetworkExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		NetworkExecutor: network, NetworkProfiles: map[string]networkworker.Profile{"net-profile": networkTestProfile()},
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowNetwork: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	_, _, response := request(t, server, call(1, "web_fetch", `{"profile":"net-profile","url":"https://secret.example/","method":"GET","headers":{"Accept":"one","accept":"two"}}`), strings.Repeat("t", 32), "")
	if response.Error == nil || !strings.Contains(response.Error.Message, "unique after canonicalization") {
		t.Fatalf("case-insensitive duplicate headers response = %+v", response)
	}
	network.mu.Lock()
	calls := len(network.requests)
	network.mu.Unlock()
	if calls != 0 {
		t.Fatal("duplicate headers reached Network Worker")
	}
}

func TestGatewayRejectsWorkspaceTransferBeyondNetworkProfileLimit(t *testing.T) {
	profile := networkTestProfile()
	profile.Limits.MaxRequestBodyBytes = 4
	network := &fakeNetworkExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		NetworkExecutor: network, NetworkProfiles: map[string]networkworker.Profile{profile.ID: profile},
	}, &captureFileExecutor{binary: []byte("too-large")}, policy.New(policy.Config{AllowNetwork: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	_, _, response := request(t, server, call(1, "upload", `{"profile":"net-profile","url":"https://secret.example/upload","path":"payload.bin","method":"PUT"}`), strings.Repeat("t", 32), "")
	if !strings.Contains(mustJSON(response.Result), "workspace transfer failed") {
		t.Fatalf("oversized workspace transfer response = %+v", response)
	}
	network.mu.Lock()
	calls := len(network.requests)
	network.mu.Unlock()
	if calls != 0 {
		t.Fatal("oversized workspace transfer reached Network Worker")
	}
}

func TestNetworkTransferIsSplitAndAuditDoesNotLeakTargetOrHeaders(t *testing.T) {
	files := &captureFileExecutor{binary: []byte("upload bytes")}
	network := &fakeNetworkExecutor{}
	var log bytes.Buffer
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		NetworkExecutor: network, NetworkProfiles: map[string]networkworker.Profile{"net-profile": networkTestProfile()},
	}, files, policy.New(policy.Config{AllowWrite: true, AllowNetwork: true}), audit.New(&log))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	_, _, upload := request(t, server, call(1, "upload", `{"profile":"net-profile","url":"https://secret.example/upload","path":"payload.bin","method":"PUT","headers":{"Accept":"credential-value"}}`), token, "")
	if upload.Error != nil {
		t.Fatalf("upload = %+v", upload)
	}
	_, _, download := request(t, server, call(2, "download", `{"profile":"net-profile","url":"https://secret.example/download","path":"download.bin"}`), token, "")
	if download.Error != nil {
		t.Fatalf("download = %+v", download)
	}
	network.mu.Lock()
	requests := append([]networkworker.Request(nil), network.requests...)
	scopes := append([]WorkerExecutionScope(nil), network.scopes...)
	network.mu.Unlock()
	if len(requests) != 2 || string(requests[0].Body) != "upload bytes" || len(requests[1].Body) != 0 {
		t.Fatalf("network requests crossed data boundary: %+v", requests)
	}
	for _, request := range requests {
		if request.RequestID == "" || request.Principal == "" || request.WorkspaceID != "workspace-test" || request.BridgeID == "" || request.SessionID == "" || request.ClientRequestID == "" {
			t.Fatalf("network wire request scope is incomplete: %+v", request)
		}
	}
	if len(scopes) != 2 || scopes[0].RequestID == "" || scopes[0].Principal == "" || scopes[0].WorkspaceID != "workspace-test" || scopes[0].BridgeID == "" || scopes[0].SessionID == "" || scopes[0].ClientRequestID == "" || scopes[0].PolicyID == "" || scopes[0].AuditID == "" || scopes[0].TokenID != requests[0].TokenID || scopes[0].Worker != "network" {
		t.Fatalf("network execution scope was not propagated: %+v", scopes)
	}
	files.mu.Lock()
	operations, written := append([]string(nil), files.operations...), append([]byte(nil), files.written...)
	files.mu.Unlock()
	if !strings.Contains(strings.Join(operations, ","), "read_binary") || !strings.Contains(strings.Join(operations, ","), "write_file") || string(written) != "downloaded bytes" {
		t.Fatalf("file/network split missing: operations=%v written=%q", operations, written)
	}
	if strings.Contains(log.String(), "secret.example") || strings.Contains(log.String(), "credential-value") || strings.Contains(log.String(), "upload bytes") || strings.Contains(log.String(), "net-profile") {
		t.Fatalf("sensitive network parameters leaked to audit: %s", log.String())
	}
	if lines := strings.Count(strings.TrimSpace(log.String()), "\n") + 1; lines != 4 {
		t.Fatalf("upload and complete download should use one two-record transaction each; audit records=%d log=%s", lines, log.String())
	}
}

func execTestProfile() execworker.TaskProfile {
	return execworker.TaskProfile{
		Name: "fixed-task", Executable: "/usr/bin/env", WorkspaceMode: execworker.WorkspaceNone,
		AllowedArgvPrefixes: [][]string{{"ok"}},
		Limits:              execworker.Limits{TimeoutMillis: 5000, CPUSeconds: 5, MemoryBytes: 64 << 20, PIDs: 16, OutputBytes: 1 << 20},
	}
}

func TestReadOnlyWorkspaceRejectsReadWriteExecProfileAtGatewayBoundary(t *testing.T) {
	seed := bytes.Repeat([]byte{6}, ed25519.SeedSize)
	signer, err := execworker.NewCapabilitySignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	profile := execTestProfile()
	profile.WorkspaceMode = execworker.WorkspaceReadWrite
	if _, err := New(Config{
		AuthToken: strings.Repeat("t", 32), WorkspaceID: "workspace-test", WorkspaceReadOnly: true,
		ExecExecutor: &fakeExecExecutor{}, ExecProfiles: map[string]execworker.TaskProfile{profile.Name: profile}, ExecSigner: signer,
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowExec: true}), audit.New(&bytes.Buffer{})); err == nil {
		t.Fatal("read-only workspace accepted a read-write Exec profile")
	}
}

func TestReadOnlyWorkspaceCallDefenseRejectsInjectedReadWriteExecProfile(t *testing.T) {
	seed := bytes.Repeat([]byte{5}, ed25519.SeedSize)
	signer, err := execworker.NewCapabilitySignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	safeProfile := execTestProfile()
	executor := &fakeExecExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged,
		WorkspaceID: "workspace-test", WorkspaceReadOnly: true,
		ExecExecutor: executor, ExecProfiles: map[string]execworker.TaskProfile{safeProfile.Name: safeProfile}, ExecSigner: signer,
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowExec: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	injected := safeProfile
	injected.Name = "injected-rw"
	injected.WorkspaceMode = execworker.WorkspaceReadWrite
	server.execProfiles[injected.Name] = injected
	_, _, response := request(t, server, call(1, "exec_run", `{"profile":"injected-rw"}`), strings.Repeat("t", 32), "")
	if !strings.Contains(mustJSON(response.Result), "exec profile is unavailable") {
		t.Fatalf("read-only call defense response = %+v", response)
	}
	executor.mu.Lock()
	jobs := len(executor.jobs)
	executor.mu.Unlock()
	if jobs != 0 {
		t.Fatal("read-only call defense reached Exec Worker")
	}
}

func TestExecJobsBindSessionAndDeleteRevokesSession(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	signer, err := execworker.NewCapabilitySignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	profile := execTestProfile()
	executor := &fakeExecExecutor{}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		ExecExecutor: executor, ExecProfiles: map[string]execworker.TaskProfile{profile.Name: profile}, ExecSigner: signer,
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowExec: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	_, firstHeader, initialized := rawRequest(server, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, token, "")
	if initialized.Error != nil {
		t.Fatal(initialized.Error)
	}
	firstSession := firstHeader.Get(protocol.HeaderSessionID)
	_, secondHeader, _ := rawRequest(server, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, token, "")
	secondSession := secondHeader.Get(protocol.HeaderSessionID)
	rawRequest(server, call(3, "process_status", `{"profile":"fixed-task","process_id":"process-opaque-1"}`), token, firstSession)
	rawRequest(server, call(4, "process_status", `{"profile":"fixed-task","process_id":"process-opaque-1"}`), token, secondSession)

	deleteRequest := httptest.NewRequest(http.MethodDelete, DefaultEndpoint, nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+token)
	deleteRequest.Header.Set(protocol.HeaderSessionID, firstSession)
	deleteRequest.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	deleteResponse := httptest.NewRecorder()
	server.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", deleteResponse.Code)
	}
	executor.mu.Lock()
	jobs := append([]execworker.Job(nil), executor.jobs...)
	executor.mu.Unlock()
	if len(jobs) < 3 || jobs[0].SessionID == jobs[1].SessionID {
		t.Fatalf("Exec jobs were not bound to distinct MCP sessions: %+v", jobs)
	}
	last := jobs[len(jobs)-1]
	if last.Operation != execworker.OperationSessionRevoke || last.SessionID != firstSession {
		t.Fatalf("session DELETE did not revoke Exec children first: %+v", last)
	}
}

func TestSessionDeleteCancelsActiveCallBeforeExecRevoke(t *testing.T) {
	seed := bytes.Repeat([]byte{8}, ed25519.SeedSize)
	signer, err := execworker.NewCapabilitySignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	profile := execTestProfile()
	executor := &cancelAwareExecExecutor{started: make(chan struct{})}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		ExecExecutor: executor, ExecProfiles: map[string]execworker.TaskProfile{profile.Name: profile}, ExecSigner: signer,
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowExec: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	_, header, initialized := rawRequest(server, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, token, "")
	if initialized.Error != nil {
		t.Fatal(initialized.Error)
	}
	sessionID := header.Get(protocol.HeaderSessionID)
	callDone := make(chan struct{})
	go func() {
		rawRequest(server, call(2, "process_start", `{"profile":"fixed-task"}`), token, sessionID)
		close(callDone)
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("active Exec call did not start")
	}
	request := httptest.NewRequest(http.MethodDelete, DefaultEndpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set(protocol.HeaderSessionID, sessionID)
	request.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d body=%s", response.Code, response.Body.String())
	}
	select {
	case <-callDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled active call did not return")
	}
	executor.mu.Lock()
	revoked := executor.revoked
	executor.mu.Unlock()
	if !revoked {
		t.Fatal("DELETE did not issue Exec session revoke")
	}
}

func TestSessionDeleteFailureKeepsRevokingSessionForRetry(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	signer, err := execworker.NewCapabilitySignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	profile := execTestProfile()
	executor := &fakeExecExecutor{revokeFailures: 1}
	server, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalMode: ApprovalModeClientManaged, WorkspaceID: "workspace-test",
		ExecExecutor: executor, ExecProfiles: map[string]execworker.TaskProfile{profile.Name: profile}, ExecSigner: signer,
	}, &captureFileExecutor{}, policy.New(policy.Config{AllowExec: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	_, header, initialized := rawRequest(server, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, token, "")
	if initialized.Error != nil {
		t.Fatal(initialized.Error)
	}
	sessionID := header.Get(protocol.HeaderSessionID)
	deleteSession := func() int {
		request := httptest.NewRequest(http.MethodDelete, DefaultEndpoint, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set(protocol.HeaderSessionID, sessionID)
		request.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response.Code
	}
	if status := deleteSession(); status != http.StatusServiceUnavailable {
		t.Fatalf("first DELETE status = %d", status)
	}
	server.sessions.mu.Lock()
	retained, ok := server.sessions.sessions[sessionID]
	server.sessions.mu.Unlock()
	if !ok || !retained.Revoking {
		t.Fatal("failed revocation did not retain a revoking session")
	}
	if status, _, _ := rawRequest(server, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, token, sessionID); status != http.StatusNotFound {
		t.Fatalf("revoking session admitted a new call: %d", status)
	}
	if status := deleteSession(); status != http.StatusNoContent {
		t.Fatalf("retry DELETE status = %d", status)
	}
	server.sessions.mu.Lock()
	_, ok = server.sessions.sessions[sessionID]
	server.sessions.mu.Unlock()
	if ok {
		t.Fatal("successful retry retained the session")
	}
}
