package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/textproto"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/remoteworker"
	"github.com/bkcarlos/remote_agent/internal/requestmeta"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

var (
	opaqueArgumentID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
	headerName       = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]{1,128}$`)
	envName          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

const externalServerApprovalError = "external high-risk tools require client_managed until server approval flow is implemented"

func externalApprovalBlocked(mode string, spec toolSpec) bool {
	return mode == ApprovalModeServerToken && spec.Worker != "file" && spec.Approval
}

func serverApprovalRequired(mode string, spec toolSpec) bool {
	return mode == ApprovalModeServerToken && spec.Worker == "file" && spec.Approval
}

func externalWorkerError(worker string, err error) string {
	if errors.Is(err, context.Canceled) {
		return "request cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	switch worker {
	case "network":
		return "network worker operation failed"
	case "remote":
		return "remote worker operation failed"
	case "exec":
		return "exec worker operation failed"
	case "file":
		return "workspace transfer failed"
	default:
		return "external worker operation failed"
	}
}

func approvalSource(mode string) string {
	if mode == ApprovalModeClientManaged {
		return "mcp_client_policy"
	}
	return "server_token"
}

func summarizeToolParameters(tool string, raw json.RawMessage) (audit.ParameterSummary, error) {
	var values map[string]any
	if err := protocol.DecodeStrict(raw, &values); err != nil {
		return audit.ParameterSummary{}, err
	}
	safe := map[string]any{"operation": tool}
	addStringLength := func(key string) {
		if value, ok := values[key].(string); ok {
			safe[key+"_bytes"] = len(value)
		}
	}
	addStringArrayStats := func(key string) {
		items, ok := values[key].([]any)
		if !ok {
			return
		}
		total := 0
		for _, item := range items {
			if value, ok := item.(string); ok {
				total += len(value)
			}
		}
		safe[key+"_count"] = len(items)
		safe[key+"_total_bytes"] = total
	}
	addStringMapStats := func(key string, includeNames bool) {
		items, ok := values[key].(map[string]any)
		if !ok {
			return
		}
		total := 0
		for name, item := range items {
			if includeNames {
				total += len(name)
			}
			if value, ok := item.(string); ok {
				total += len(value)
			}
		}
		safe[key+"_count"] = len(items)
		safe[key+"_total_bytes"] = total
	}

	switch tool {
	case "web_fetch", "download", "upload":
		safe["profile_present"] = values["profile"] != nil
		addStringLength("url")
		addStringLength("path")
		addStringMapStats("headers", true)
	case "ssh_exec", "sftp_list", "sftp_read", "sftp_write", "sftp_mkdir", "sftp_rename":
		safe["profile_present"] = values["profile"] != nil
		addStringLength("remote_path")
		addStringLength("destination_path")
		addStringLength("path")
		addStringArrayStats("argv")
	case "exec_run", "process_start", "process_status", "process_stop", "debug_status", "debug_signal", "mem_scan":
		safe["profile_present"] = values["profile"] != nil
		addStringArrayStats("argv")
		addStringMapStats("env", true)
		addStringLength("process_id")
		addStringLength("pattern")
		if _, ok := values["signal"]; ok {
			safe["signal_present"] = true
		}
		if include, ok := values["include_context"].(bool); ok {
			safe["include_context"] = include
		}
	default:
		addStringLength("path")
		addStringLength("pattern")
		addStringLength("query")
		if paths, ok := values["paths"].([]any); ok {
			safe["path_count"] = len(paths)
		}
		if apply, ok := values["apply"].(bool); ok {
			safe["apply"] = apply
		}
	}
	summary, err := audit.SummarizeParameters(safe)
	if err == nil {
		summary.Bytes = int64(len(raw))
	}
	return summary, err
}

func (s *Server) validateExternalArguments(spec toolSpec, arguments *toolArguments) error {
	if arguments == nil || !opaqueArgumentID.MatchString(arguments.Profile) {
		return errors.New("profile must be a valid opaque identifier")
	}
	if len(arguments.ApprovalToken) > 32768 || len(arguments.ExpectedHash) > 64 {
		return errors.New("tool argument exceeds its length limit")
	}
	if arguments.ExpectedHash != "" && !validSHA256(arguments.ExpectedHash) {
		return errors.New("expected_hash must be a lowercase SHA-256 value")
	}
	if arguments.Path != "" {
		normalized, err := capability.NormalizePath(arguments.Path)
		if err != nil {
			return errors.New("path is invalid")
		}
		arguments.Path = normalized
	}
	switch spec.Worker {
	case "network":
		if len(arguments.URL) > 8192 {
			return errors.New("URL exceeds its length limit")
		}
		normalized, err := networkworker.NormalizeURL(arguments.URL)
		if err != nil {
			return errors.New("URL is invalid")
		}
		arguments.URL = normalized
		if spec.Name == "download" {
			arguments.Method = http.MethodGet
		}
		if len(arguments.Headers) > 32 {
			return errors.New("header count exceeds limit")
		}
		normalizedHeaders := make(networkworker.Headers, len(arguments.Headers))
		for name, values := range arguments.Headers {
			if !headerName.MatchString(name) || len(values) != 1 || len(values[0]) > 8192 || strings.IndexFunc(values[0], func(r rune) bool { return r == '\r' || r == '\n' || r == 0 }) >= 0 {
				return errors.New("HTTP header is invalid")
			}
			canonical := textproto.CanonicalMIMEHeaderKey(name)
			if _, duplicate := normalizedHeaders[canonical]; duplicate {
				return errors.New("HTTP headers must be unique after canonicalization")
			}
			normalizedHeaders[canonical] = append([]string(nil), values...)
		}
		arguments.Headers = normalizedHeaders
		switch spec.Name {
		case "web_fetch":
			if arguments.Path != "" || (arguments.Method != http.MethodGet && arguments.Method != http.MethodHead) {
				return errors.New("web_fetch arguments are invalid")
			}
		case "download":
			if arguments.Path == "" || len(arguments.Headers) != 0 {
				return errors.New("download arguments are invalid")
			}
		case "upload":
			if arguments.Path == "" || (arguments.Method != http.MethodPost && arguments.Method != http.MethodPut) {
				return errors.New("upload arguments are invalid")
			}
		}
	case "remote":
		if arguments.RemotePath != "" && !validRemotePath(arguments.RemotePath) {
			return errors.New("remote_path must be a clean absolute POSIX path")
		}
		if arguments.DestinationPath != "" && !validRemotePath(arguments.DestinationPath) {
			return errors.New("destination_path must be a clean absolute POSIX path")
		}
		if err := validateArgv(arguments.Argv, spec.Name == "ssh_exec"); err != nil {
			return err
		}
		switch spec.Name {
		case "ssh_exec":
			if arguments.RemotePath != "" || arguments.DestinationPath != "" || arguments.Path != "" {
				return errors.New("ssh_exec arguments are invalid")
			}
		case "sftp_list", "sftp_read", "sftp_mkdir":
			if arguments.RemotePath == "" || arguments.DestinationPath != "" || arguments.Path != "" || len(arguments.Argv) != 0 {
				return errors.New("SFTP arguments are invalid")
			}
		case "sftp_write":
			if arguments.RemotePath == "" || arguments.Path == "" || arguments.DestinationPath != "" || len(arguments.Argv) != 0 {
				return errors.New("sftp_write arguments are invalid")
			}
		case "sftp_rename":
			if arguments.RemotePath == "" || arguments.DestinationPath == "" || arguments.Path != "" || len(arguments.Argv) != 0 {
				return errors.New("sftp_rename arguments are invalid")
			}
		}
	case "exec":
		if err := validateArgv(arguments.Argv, false); err != nil {
			return err
		}
		if len(arguments.Env) > 32 {
			return errors.New("environment variable count exceeds limit")
		}
		for name, value := range arguments.Env {
			if !envName.MatchString(name) || len(value) > 8192 || strings.IndexByte(value, 0) >= 0 {
				return errors.New("environment is invalid")
			}
		}
		if arguments.ProcessID != "" && !opaqueArgumentID.MatchString(arguments.ProcessID) {
			return errors.New("process_id is invalid")
		}
		if arguments.Memory != nil && (len(arguments.Memory.Pattern) == 0 || len(arguments.Memory.Pattern) > 4096) {
			return errors.New("memory pattern is invalid")
		}
		hasLaunch := len(arguments.Argv) != 0 || len(arguments.Env) != 0
		switch spec.Name {
		case "exec_run", "process_start":
			if arguments.ProcessID != "" || arguments.Signal != "" || arguments.Memory != nil {
				return errors.New("launch arguments are invalid")
			}
		case "process_status", "process_stop", "debug_status":
			if arguments.ProcessID == "" || hasLaunch || arguments.Signal != "" || arguments.Memory != nil {
				return errors.New("process arguments are invalid")
			}
		case "debug_signal":
			if arguments.ProcessID == "" || hasLaunch || arguments.Signal == "" || arguments.Memory != nil {
				return errors.New("debug signal arguments are invalid")
			}
		case "mem_scan":
			if arguments.ProcessID == "" || hasLaunch || arguments.Signal != "" || arguments.Memory == nil {
				return errors.New("memory scan arguments are invalid")
			}
		}
	default:
		return errors.New("worker is not supported")
	}
	return nil
}

func validRemotePath(value string) bool {
	return len(value) <= 4096 && strings.IndexByte(value, 0) < 0 && path.IsAbs(value) && path.Clean(value) == value
}

func validateArgv(argv []string, required bool) error {
	if (required && len(argv) == 0) || len(argv) > 64 {
		return errors.New("argv count is invalid")
	}
	for _, argument := range argv {
		if len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 {
			return errors.New("argv is invalid")
		}
	}
	return nil
}

func riskLevel(value string) int {
	if len(value) == 2 && value[0] == 'L' && value[1] >= '0' && value[1] <= '4' {
		return int(value[1] - '0')
	}
	return 4
}

func (s *Server) beginExternalAudit(event audit.Event, spec toolSpec) (*audit.Transaction, error) {
	if riskLevel(spec.Risk) < 2 {
		return nil, nil
	}
	return s.audit.Prewrite(event)
}

func (s *Server) finishExternalAudit(transaction *audit.Transaction, event audit.Event, status string) error {
	if transaction == nil {
		event.Status = status
		return s.audit.Record(event)
	}
	return transaction.Complete(status, func(done *audit.Event) {
		startedAt := done.StartedAt
		*done = event
		done.StartedAt = startedAt
		done.Status = status
		done.Stage = "completed"
	})
}

func (s *Server) externalFailure(id json.RawMessage, transaction *audit.Transaction, event audit.Event, status, message string) protocol.Response {
	if err := s.finishExternalAudit(transaction, event, status); err != nil {
		return toolError(id, "audit unavailable; external operation result cannot be confirmed", event.PolicyID)
	}
	return toolError(id, message, event.PolicyID)
}

func (s *Server) callExternal(ctx context.Context, id json.RawMessage, spec toolSpec, arguments toolArguments, event audit.Event) protocol.Response {
	transaction, err := s.beginExternalAudit(event, spec)
	if err != nil {
		return toolError(id, "audit unavailable; external operation denied", event.PolicyID)
	}
	switch spec.Worker {
	case "network":
		return s.callNetwork(ctx, id, spec, arguments, event, transaction)
	case "remote":
		return s.callRemote(ctx, id, spec, arguments, event, transaction)
	case "exec":
		return s.callExec(ctx, id, spec, arguments, event, transaction)
	default:
		return s.externalFailure(id, transaction, event, "denied", "worker is unavailable")
	}
}

func (s *Server) callNetwork(ctx context.Context, id json.RawMessage, spec toolSpec, arguments toolArguments, event audit.Event, transaction *audit.Transaction) protocol.Response {
	profile, ok := s.networkProfiles[arguments.Profile]
	if !ok || !s.cfg.Now().UTC().Before(profile.ExpiresAt) {
		return s.externalFailure(id, transaction, event, "denied", "network profile is unavailable")
	}
	meta, _ := requestmeta.FromContext(ctx)
	limits := profile.Limits
	if spec.Name == "upload" {
		limits.MaxRequestBodyBytes = min64(limits.MaxRequestBodyBytes, fileworker.MaxBinaryBytes)
	}
	if spec.Name == "download" {
		limits.MaxResponseBodyBytes = min64(limits.MaxResponseBodyBytes, min64(fileworker.MaxBinaryBytes, s.policy.MaxWriteBytes()))
	}
	request := networkworker.Request{
		TokenID: newID("net-cap-"), RequestID: meta.RequestID, Principal: meta.AuthPrincipal,
		WorkspaceID: s.cfg.WorkspaceID, BridgeID: meta.BridgeID, SessionID: meta.SessionID,
		ClientRequestID: meta.ClientRequestID, Operation: spec.Name, URL: arguments.URL,
		Method: arguments.Method, Headers: arguments.Headers, PolicyID: event.PolicyID,
		ProfileID: profile.ID, Policy: profile.Policy, Limits: limits,
	}
	if spec.Name == "upload" {
		body, fileResult, err := s.readBinary(ctx, arguments.Path, limits.MaxRequestBodyBytes)
		event.TokenID, event.WorkerID = fileResult.TokenID, fileResult.WorkerID
		if err != nil {
			return s.externalFailure(id, transaction, event, statusForError(err), externalWorkerError("file", err))
		}
		request.Body = body
		event.InputBytes = int64(len(body))
	}
	scope, _ := WorkerExecutionScopeFromContext(ctx)
	scope.TokenID = request.TokenID
	ctx = withWorkerExecutionScope(ctx, scope)
	response, err := s.network.Execute(ctx, request)
	event.TokenID, event.WorkerID = response.TokenID, response.WorkerID
	if err != nil {
		return s.externalFailure(id, transaction, event, statusForError(err), externalWorkerError("network", err))
	}
	if spec.Name == "download" {
		return s.finishDownload(ctx, id, arguments, event, response, limits.MaxResponseBodyBytes, transaction)
	}
	event.OutputBytes = response.Bytes
	if err := s.finishExternalAudit(transaction, event, "success"); err != nil {
		return toolError(id, "audit unavailable; external operation result cannot be confirmed", event.PolicyID)
	}
	result := map[string]any{"status": response.Status, "headers": response.Headers, "mime_type": response.MIMEType, "bytes": response.Bytes, "sha256": response.SHA256, "untrusted": true, "token_id": response.TokenID, "worker_id": response.WorkerID}
	if spec.Name == "web_fetch" {
		result["text"] = response.Text
		if response.Base64 != "" {
			result["binary_omitted"] = true
		}
	}
	return toolSuccess(id, result)
}

func (s *Server) finishDownload(ctx context.Context, id json.RawMessage, arguments toolArguments, event audit.Event, response networkworker.Response, transferLimit int64, transaction *audit.Transaction) protocol.Response {
	body, err := base64.StdEncoding.DecodeString(response.Base64)
	if err != nil || base64.StdEncoding.EncodeToString(body) != response.Base64 || int64(len(body)) != response.Bytes || response.Bytes > transferLimit || digest(body) != response.SHA256 {
		return s.externalFailure(id, transaction, event, "error", "network worker returned invalid download bytes")
	}
	checksumRequest := fileworker.Request{Operation: "checksum", Path: arguments.Path, TokenID: newID("cap-")}
	current, checksumErr := s.fs.Execute(ctx, checksumRequest)
	before := current.Checksum
	if checksumErr != nil {
		if !errors.Is(checksumErr, workspace.ErrNotFound) {
			return s.externalFailure(id, transaction, event, statusForError(checksumErr), externalWorkerError("file", checksumErr))
		}
		before = ""
	}
	if before != "" && arguments.ExpectedHash == "" {
		return s.externalFailure(id, transaction, event, "denied", "expected_hash is required when replacing an existing file")
	}
	if arguments.ExpectedHash != before {
		return s.externalFailure(id, transaction, event, "denied", "expected_hash does not match preflight")
	}
	event.BeforeHash, event.AfterHash, event.InputBytes = before, response.SHA256, response.Bytes
	written, writeErr := s.fs.Execute(ctx, fileworker.Request{Operation: "write_file", Path: arguments.Path, Data: body, ExpectedHash: before, MaxBytes: s.policy.MaxWriteBytes(), TokenID: newID("cap-")})
	status := "success"
	if writeErr != nil {
		status = statusForError(writeErr)
	}
	event.TokenID, event.WorkerID, event.AfterHash, event.OutputBytes = written.TokenID, written.WorkerID, written.Checksum, int64(len(body))
	finishErr := s.finishExternalAudit(transaction, event, status)
	if writeErr != nil {
		return toolError(id, externalWorkerError("file", writeErr), event.PolicyID)
	}
	if finishErr != nil {
		return toolError(id, "audit unavailable; download result cannot be confirmed", event.PolicyID)
	}
	return toolSuccess(id, map[string]any{"written": true, "path": arguments.Path, "bytes": len(body), "sha256": written.Checksum, "untrusted_source": true, "token_id": written.TokenID, "worker_id": written.WorkerID})
}

func (s *Server) callRemote(ctx context.Context, id json.RawMessage, spec toolSpec, arguments toolArguments, event audit.Event, transaction *audit.Transaction) protocol.Response {
	meta, _ := requestmeta.FromContext(ctx)
	request := remoteworker.Request{
		RequestID: meta.RequestID, Principal: meta.AuthPrincipal, WorkspaceID: s.cfg.WorkspaceID,
		BridgeID: meta.BridgeID, SessionID: meta.SessionID, ClientRequestID: meta.ClientRequestID,
		ProfileName: arguments.Profile, Operation: spec.Name, RemotePath: arguments.RemotePath,
		DestinationPath: arguments.DestinationPath, Argv: append([]string{}, arguments.Argv...),
		Limits: remoteworker.Limits{MaxOutputBytes: 2 << 20, MaxFileBytes: fileworker.MaxBinaryBytes, MaxEntries: 10000, TimeoutMillis: 30000},
	}
	if spec.Name == "ssh_exec" {
		request.RemotePath = "/"
	}
	if spec.Name == "sftp_write" {
		body, fileResult, err := s.readBinary(ctx, arguments.Path, request.Limits.MaxFileBytes)
		event.TokenID, event.WorkerID = fileResult.TokenID, fileResult.WorkerID
		if err != nil {
			return s.externalFailure(id, transaction, event, statusForError(err), externalWorkerError("file", err))
		}
		request.Content, event.InputBytes = body, int64(len(body))
	}
	response, err := s.remote.Execute(ctx, request)
	if err != nil {
		return s.externalFailure(id, transaction, event, statusForError(err), externalWorkerError("remote", err))
	}
	event.WorkerID, event.TokenID, event.OutputBytes = response.JobID, response.JobID, response.Bytes
	if err := s.finishExternalAudit(transaction, event, "success"); err != nil {
		return toolError(id, "audit unavailable; external operation result cannot be confirmed", event.PolicyID)
	}
	result := map[string]any{"job_id": response.JobID, "worker_id": response.JobID, "bytes": response.Bytes, "sha256": response.SHA256}
	switch spec.Name {
	case "ssh_exec":
		if utf8.Valid(response.Stdout) {
			result["stdout"] = string(response.Stdout)
		} else {
			result["stdout_base64"] = base64.StdEncoding.EncodeToString(response.Stdout)
		}
		if utf8.Valid(response.Stderr) {
			result["stderr"] = string(response.Stderr)
		} else {
			result["stderr_base64"] = base64.StdEncoding.EncodeToString(response.Stderr)
		}
		result["exit_status"] = response.ExitStatus
	case "sftp_list":
		result["entries"] = response.Entries
	case "sftp_read":
		result["base64"] = base64.StdEncoding.EncodeToString(response.Content)
	default:
		result["completed"] = true
	}
	return toolSuccess(id, result)
}

func (s *Server) callExec(ctx context.Context, id json.RawMessage, spec toolSpec, arguments toolArguments, event audit.Event, transaction *audit.Transaction) protocol.Response {
	profile, ok := s.execProfiles[arguments.Profile]
	if !ok || (s.cfg.WorkspaceReadOnly && profile.WorkspaceMode == execworker.WorkspaceReadWrite) {
		return s.externalFailure(id, transaction, event, "denied", "exec profile is unavailable")
	}
	meta, _ := requestmeta.FromContext(ctx)
	job := execworker.Job{
		CapabilityID: newID("exec-cap-"), Principal: meta.AuthPrincipal, SessionID: meta.SessionID,
		WorkspaceID: s.cfg.WorkspaceID, TaskID: meta.RequestID, Profile: profile.Name, Operation: spec.Name,
		Limits: profile.Limits, Argv: append([]string(nil), arguments.Argv...), Env: cloneStringMap(arguments.Env),
		ProcessID: arguments.ProcessID, Signal: arguments.Signal, Memory: arguments.Memory,
	}
	profileDigest, err := profile.Digest()
	if err != nil {
		return s.externalFailure(id, transaction, event, "error", "exec profile is invalid")
	}
	claims, err := execworker.ClaimsForJob(job, profileDigest, s.cfg.Now().UTC().Add(30*time.Second))
	if err == nil {
		job.Token, err = s.execSigner.Sign(claims)
	}
	if err != nil {
		return s.externalFailure(id, transaction, event, "error", "exec capability creation failed")
	}
	event.TokenID = job.CapabilityID
	scope, _ := WorkerExecutionScopeFromContext(ctx)
	scope.TokenID = job.CapabilityID
	ctx = withWorkerExecutionScope(ctx, scope)
	response, executeErr := s.exec.Do(ctx, job)
	event.WorkerID = s.execWorkerID
	event.OutputBytes = int64(len(response.Stdout) + len(response.Stderr))
	status := "success"
	if executeErr != nil {
		status = statusForError(executeErr)
	}
	if finishErr := s.finishExternalAudit(transaction, event, status); finishErr != nil {
		return toolError(id, "audit unavailable; exec result cannot be confirmed", event.PolicyID)
	}
	if executeErr != nil {
		return toolError(id, externalWorkerError("exec", executeErr), event.PolicyID)
	}
	return toolSuccess(id, execPublicResult(response, s.execWorkerID))
}

func execPublicResult(response execworker.Response, workerID string) map[string]any {
	return map[string]any{"process_id": response.ProcessID, "status": response.Status, "stdout": response.Stdout, "stderr": response.Stderr, "truncated": response.Truncated, "matches": response.Matches, "scanned_bytes": response.ScannedBytes, "worker_id": workerID}
}

func (s *Server) readBinary(ctx context.Context, workspacePath string, max int64) ([]byte, fileworker.Response, error) {
	max = min64(max, min64(s.policy.MaxReadBytes(), fileworker.MaxBinaryBytes))
	if max <= 0 {
		return nil, fileworker.Response{}, errors.New("binary transfer is disabled by policy")
	}
	response, err := s.fs.Execute(ctx, fileworker.Request{Operation: "read_binary", Path: workspacePath, MaxBytes: max, TokenID: newID("cap-")})
	if err != nil {
		return nil, response, err
	}
	raw, decodeErr := base64.StdEncoding.DecodeString(response.Base64)
	if decodeErr != nil || base64.StdEncoding.EncodeToString(raw) != response.Base64 || int64(len(raw)) > max || len(raw) != response.Bytes || digest(raw) != response.Checksum {
		return nil, response, errors.New("file worker returned invalid binary bytes")
	}
	return raw, response, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for name, value := range values {
		cloned[name] = value
	}
	return cloned
}

func (s *Server) applyClientManagedEdit(ctx context.Context, id json.RawMessage, spec toolSpec, arguments toolArguments, event audit.Event, preview fileworker.Response, targets []approval.Target) protocol.Response {
	apply := s.workerRequest(spec.Name, arguments)
	apply.Apply = true
	apply.Targets = workerTargets(targets)
	apply.TokenID = newID("cap-")
	event.TokenID = apply.TokenID
	event.BeforeHash, event.AfterHash = aggregateApprovalHashes(targets)
	event.InputBytes = totalAfterBytes(preview.Files)
	transaction, err := s.audit.Prewrite(event)
	if err != nil {
		return toolError(id, "audit unavailable; write denied", event.PolicyID)
	}
	result, executeErr := s.fs.Execute(ctx, apply)
	status := "success"
	if executeErr != nil {
		status = statusForError(executeErr)
	}
	finishErr := transaction.Complete(status, func(done *audit.Event) {
		done.TokenID, done.WorkerID, done.OutputBytes = result.TokenID, result.WorkerID, responseBytes(result)
		done.ApprovalVerified = false
		done.ApprovalSource = "mcp_client_policy"
	})
	if executeErr != nil {
		return toolError(id, safeToolError(executeErr), event.PolicyID)
	}
	if finishErr != nil {
		return toolError(id, "audit unavailable; write result cannot be confirmed", event.PolicyID)
	}
	return toolSuccess(id, publicResult(spec.Name, result))
}

func (s *Server) applyClientManagedWrite(ctx context.Context, id json.RawMessage, arguments toolArguments, event audit.Event, before, after string) protocol.Response {
	request := fileworker.Request{Operation: "write_file", Path: arguments.Path, Data: []byte(arguments.Content), ExpectedHash: before, MaxBytes: s.policy.MaxWriteBytes(), TokenID: newID("cap-")}
	event.TokenID, event.BeforeHash, event.AfterHash, event.InputBytes = request.TokenID, before, after, int64(len(arguments.Content))
	transaction, err := s.audit.Prewrite(event)
	if err != nil {
		return toolError(id, "audit unavailable; write denied", event.PolicyID)
	}
	result, executeErr := s.fs.Execute(ctx, request)
	status := "success"
	if executeErr != nil {
		status = statusForError(executeErr)
	}
	finishErr := transaction.Complete(status, func(done *audit.Event) {
		done.TokenID, done.WorkerID, done.AfterHash = result.TokenID, result.WorkerID, result.Checksum
		done.ApprovalVerified = false
		done.ApprovalSource = "mcp_client_policy"
	})
	if executeErr != nil {
		return toolError(id, safeToolError(executeErr), event.PolicyID)
	}
	if finishErr != nil {
		return toolError(id, "audit unavailable; write result cannot be confirmed", event.PolicyID)
	}
	return toolSuccess(id, map[string]any{"written": true, "sha256": result.Checksum, "token_id": result.TokenID, "worker_id": result.WorkerID, "approval_mode": ApprovalModeClientManaged})
}

func (s *Server) revokeExecSessionWithTimeout(principal, sessionID string) error {
	if principal == "" || sessionID == "" || s.exec == nil || s.execSigner == nil || len(s.execProfiles) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.revokeExecSession(ctx, principal, sessionID)
}

func (s *Server) revokeExecSessionsWithTimeout(sessions []mcpSession) {
	if s.exec == nil || s.execSigner == nil || len(s.execProfiles) == 0 || len(sessions) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	completed := make(chan struct{}, len(sessions))
	for _, session := range sessions {
		session := session
		go func() {
			_ = s.revokeExecSession(ctx, session.Principal, session.ID)
			completed <- struct{}{}
		}()
	}
	for range sessions {
		select {
		case <-completed:
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) evictSessions(sessions []mcpSession) {
	s.revokeExecSessionsWithTimeout(sessions)
	for _, session := range sessions {
		s.terminateActive(session.Principal, session.ID)
	}
}

func (s *Server) revokeExecSession(ctx context.Context, principal, sessionID string) error {
	var profile execworker.TaskProfile
	for _, configured := range s.execProfiles {
		profile = configured
		break
	}
	if profile.Name == "" {
		return nil
	}
	job := execworker.Job{
		CapabilityID: newID("exec-cap-"), Principal: principal, SessionID: sessionID,
		WorkspaceID: s.cfg.WorkspaceID, TaskID: newID("session-revoke-"), Profile: profile.Name,
		Operation: execworker.OperationSessionRevoke, Limits: profile.Limits,
	}
	digest, err := profile.Digest()
	if err != nil {
		return err
	}
	claims, err := execworker.ClaimsForJob(job, digest, s.cfg.Now().UTC().Add(30*time.Second))
	if err != nil {
		return err
	}
	job.Token, err = s.execSigner.Sign(claims)
	if err != nil {
		return err
	}
	_, err = s.exec.Do(ctx, job)
	return err
}
