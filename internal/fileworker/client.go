package fileworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/requestmeta"
)

const (
	capabilityTTL          = 30 * time.Second
	MaxWorkerResponseBytes = 15 << 20
)

// RemoteError is a path-safe worker failure whose stable workspace category is
// available through errors.Is.
type RemoteError struct {
	Kind    ErrorKind
	Message string
}

func (e *RemoteError) Error() string {
	if e == nil || e.Message == "" {
		return "file worker operation failed"
	}
	return e.Message
}

func (e *RemoteError) Unwrap() error {
	if e == nil {
		return nil
	}
	return workspaceErrorForKind(e.Kind)
}

type Edit struct {
	Old              string `json:"old"`
	New              string `json:"new"`
	Mode             string `json:"mode,omitempty"`
	AdaptIndentation bool   `json:"adapt_indentation,omitempty"`
}

type EditFile struct {
	Path  string `json:"path"`
	Edits []Edit `json:"edits"`
}

type Target struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
}

type Request struct {
	TokenID      string
	Operation    string
	Path         string
	Paths        []string
	MaxBytes     int64
	StartLine    int
	EndLine      int
	MaxEntries   int
	MaxFiles     int
	MaxResults   int
	Pattern      string
	Query        string
	Data         []byte
	ExpectedHash string
	Edits        []Edit
	Files        []EditFile
	Apply        bool
	Targets      []Target
}

type ProcessExecutor struct {
	binary     string
	root       string
	signer     *capability.Signer
	publicKey  ed25519.PublicKey
	timeout    time.Duration
	denied     []string
	policyID   string
	cgroupRoot string
}

func NewProcessExecutor(binary, root string, privateKeyMaterial []byte, timeout time.Duration) (*ProcessExecutor, error) {
	return NewProcessExecutorWithDenied(binary, root, privateKeyMaterial, timeout, nil)
}

func NewProcessExecutorWithDenied(binary, root string, privateKeyMaterial []byte, timeout time.Duration, deniedNames []string) (*ProcessExecutor, error) {
	return NewSecureProcessExecutor(binary, root, privateKeyMaterial, timeout, deniedNames, "")
}

// NewSecureProcessExecutor accepts either a 32-byte Ed25519 seed or a 64-byte
// Ed25519 private key. Only the derived public key is passed to worker processes.
func NewSecureProcessExecutor(binary, root string, privateKeyMaterial []byte, timeout time.Duration, deniedNames []string, cgroupRoot string) (*ProcessExecutor, error) {
	if binary == "" || root == "" {
		return nil, errors.New("worker binary and workspace are required")
	}
	canonicalRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("workspace path is invalid")
	}
	if resolved, resolveErr := filepath.EvalSymlinks(canonicalRoot); resolveErr == nil {
		canonicalRoot = resolved
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	signer, err := newCapabilitySigner(privateKeyMaterial)
	if err != nil {
		return nil, err
	}
	denied := append([]string(nil), deniedNames...)
	return &ProcessExecutor{binary: binary, root: canonicalRoot, signer: signer, publicKey: signer.PublicKey(), timeout: timeout, denied: denied, policyID: workerPolicyID(denied), cgroupRoot: cgroupRoot}, nil
}

func newCapabilitySigner(privateKeyMaterial []byte) (*capability.Signer, error) {
	switch len(privateKeyMaterial) {
	case ed25519.SeedSize:
		return capability.NewSignerFromSeed(privateKeyMaterial)
	case ed25519.PrivateKeySize:
		return capability.NewSigner(ed25519.PrivateKey(privateKeyMaterial))
	default:
		return nil, errors.New("worker capability key must be a 32-byte Ed25519 seed or 64-byte private key")
	}
}

// Execute creates exactly one capability-scoped worker process. Request,
// session, bridge, client, and policy identity must come from the caller's
// context; the executor never invents replacement request or session IDs.
func (e *ProcessExecutor) Execute(ctx context.Context, request Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{TokenID: request.TokenID}, err
	}
	meta, ok := requestmeta.FromContext(ctx)
	if !ok || meta.RequestID == "" || meta.SessionID == "" || meta.PolicyID == "" || meta.PolicyDecision == "" {
		return Response{}, errors.New("file worker request scope is incomplete")
	}
	job, err := jobFromRequest(request, meta, e.policyID)
	if err != nil {
		return Response{}, err
	}
	if request.TokenID == "" {
		job.TokenID = randomID("cap-")
	}
	claims, err := claimsForJob(job, job.TokenID, time.Now().UTC().Add(capabilityTTL))
	if err != nil {
		return Response{}, err
	}
	job.Token, err = e.signer.Sign(claims)
	if err != nil {
		return Response{}, err
	}
	input, err := json.Marshal(job)
	if err != nil {
		return Response{}, err
	}
	workerParent := ctx
	commit := isCommitRequest(request)
	if commit {
		// Once a commit worker starts, client cancellation must not SIGKILL it
		// between file replacements. The independent hard timeout still bounds
		// execution. This is not atomic across timeout, host failure, or power loss.
		workerParent = context.WithoutCancel(ctx)
	}
	workerCtx, cancel := context.WithTimeout(workerParent, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(workerCtx, e.binary, "-workspace", e.root)
	configureWorkerProcess(cmd)
	cmd.Cancel = func() error { return killWorkerProcess(cmd) }
	cmd.WaitDelay = 2 * time.Second
	cgroup, err := prepareCgroup(e.cgroupRoot, job.TokenID)
	if err != nil {
		return Response{}, err
	}
	defer cgroup.close()
	attachCgroup(cmd.SysProcAttr, cgroup)
	deniedJSON, err := json.Marshal(e.denied)
	if err != nil {
		return Response{}, err
	}
	cmd.Env = []string{
		"REMOTE_AGENT_WORKER_PUBLIC_KEY=" + base64.RawStdEncoding.EncodeToString(e.publicKey),
		"REMOTE_AGENT_DENIED_NAMES=" + string(deniedJSON),
	}
	cmd.Stdin = bytes.NewReader(input)
	stdout := newBoundedBuffer(MaxWorkerResponseBytes)
	stderr := newBoundedBuffer(16 << 10)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Cancellation before process launch is always honored, including commits.
	if err := ctx.Err(); err != nil {
		return Response{TokenID: job.TokenID}, err
	}
	runErr := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return Response{TokenID: job.TokenID}, errors.New("file worker output exceeded limit")
	}
	if runErr != nil {
		if errors.Is(workerCtx.Err(), context.Canceled) {
			return Response{TokenID: job.TokenID}, context.Canceled
		}
		if errors.Is(workerCtx.Err(), context.DeadlineExceeded) {
			return Response{TokenID: job.TokenID}, fmt.Errorf("file worker timed out: %w", context.DeadlineExceeded)
		}
		detail := sanitizeWorkerError(stderr.String(), e.root)
		return Response{TokenID: job.TokenID}, fmt.Errorf("file worker failed: %w: %s", runErr, truncate(detail, 512))
	}
	var response Response
	if err := protocol.DecodeStrict(stdout.Bytes(), &response); err != nil {
		return Response{TokenID: job.TokenID}, errors.New("file worker returned an invalid response")
	}
	if response.TokenID != job.TokenID || response.WorkerID == "" {
		return Response{TokenID: job.TokenID}, errors.New("file worker response identity mismatch")
	}
	if response.Error != "" {
		response.Error = sanitizeWorkerError(response.Error, e.root)
		if response.ErrorKind != "" {
			return response, &RemoteError{Kind: response.ErrorKind, Message: response.Error}
		}
		return response, errors.New(response.Error)
	}
	return response, nil
}

func isCommitRequest(request Request) bool {
	return request.Operation == "write_file" || request.Apply && (request.Operation == "edit" || request.Operation == "multi_edit")
}

func jobFromRequest(request Request, meta requestmeta.Scope, workerPolicy string) (Job, error) {
	job := Job{
		TokenID: request.TokenID, WorkerType: FileWorkerType,
		RequestID: meta.RequestID, BridgeID: meta.BridgeID, SessionID: meta.SessionID,
		ClientRequestID: meta.ClientRequestID, AuthPrincipal: meta.AuthPrincipal,
		Operation: request.Operation, Path: request.Path, Paths: append([]string(nil), request.Paths...),
		PolicyID: meta.PolicyID, PolicyDecision: meta.PolicyDecision, ApprovalRequired: meta.ApprovalRequired,
		WorkerPolicyID: workerPolicy, MaxBytes: request.MaxBytes, StartLine: request.StartLine, EndLine: request.EndLine,
		MaxEntries: request.MaxEntries, MaxFiles: request.MaxFiles, MaxResults: request.MaxResults, Pattern: request.Pattern, Query: request.Query,
		ExpectedHash: request.ExpectedHash, Edits: append([]Edit(nil), request.Edits...), Files: cloneEditFiles(request.Files),
		Apply: request.Apply, Targets: append([]Target(nil), request.Targets...),
	}
	if len(request.Data) > 0 {
		job.Data = base64.StdEncoding.EncodeToString(request.Data)
		job.ContentSHA256 = digestBytes(request.Data)
	}
	if job.Path == "" {
		switch {
		case len(job.Paths) > 0:
			job.Path = job.Paths[0]
		case len(job.Files) > 0:
			job.Path = job.Files[0].Path
		case len(job.Targets) > 0:
			job.Path = job.Targets[0].Path
		}
	}
	if err := normalizeJobPaths(&job); err != nil {
		return Job{}, err
	}
	job.ArgumentsSHA256 = jobArgumentsDigest(job)
	return job, nil
}

func cloneEditFiles(files []EditFile) []EditFile {
	out := make([]EditFile, len(files))
	for i := range files {
		out[i] = EditFile{Path: files[i].Path, Edits: append([]Edit(nil), files[i].Edits...)}
	}
	return out
}

func normalizeJobPaths(job *Job) error {
	normalize := func(raw string) (string, error) { return capability.NormalizePath(raw) }
	var err error
	job.Path, err = normalize(job.Path)
	if err != nil {
		return err
	}
	for i := range job.Paths {
		job.Paths[i], err = normalize(job.Paths[i])
		if err != nil {
			return err
		}
	}
	for i := range job.Files {
		job.Files[i].Path, err = normalize(job.Files[i].Path)
		if err != nil {
			return err
		}
	}
	for i := range job.Targets {
		job.Targets[i].Path, err = normalize(job.Targets[i].Path)
		if err != nil {
			return err
		}
	}
	return nil
}

func sanitizeWorkerError(value, root string) string {
	value = strings.TrimSpace(value)
	for _, candidate := range []string{root, filepath.Clean(root), filepath.ToSlash(filepath.Clean(root))} {
		if candidate != "" {
			value = strings.ReplaceAll(value, candidate, "[workspace]")
		}
	}
	return value
}

func randomID(prefix string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
	}
	return prefix + hex.EncodeToString(value)
}

type boundedBuffer struct {
	bytes.Buffer
	max      int
	exceeded bool
}

func newBoundedBuffer(max int) *boundedBuffer { return &boundedBuffer{max: max} }

func (b *boundedBuffer) Write(value []byte) (int, error) {
	remaining := b.max - b.Len()
	if len(value) > remaining {
		if remaining > 0 {
			_, _ = b.Buffer.Write(value[:remaining])
		}
		b.exceeded = true
		return len(value), errors.New("output limit exceeded")
	}
	return b.Buffer.Write(value)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
