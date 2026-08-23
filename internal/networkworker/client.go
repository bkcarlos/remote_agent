package networkworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const capabilityTTL = 30 * time.Second

type Request struct {
	TokenID         string
	RequestID       string
	Principal       string
	WorkspaceID     string
	BridgeID        string
	SessionID       string
	ClientRequestID string
	Operation       string
	URL             string
	Method          string
	Headers         Headers
	Body            []byte
	PolicyID        string
	ProfileID       string
	Policy          Policy
	Limits          ResourceLimits
}

type ProcessExecutor struct {
	binary    string
	signer    *Signer
	publicKey ed25519.PublicKey
	timeout   time.Duration
}

func NewProcessExecutor(binary string, privateKeyMaterial []byte, timeout time.Duration) (*ProcessExecutor, error) {
	if binary == "" {
		return nil, errors.New("network worker binary is required")
	}
	var signer *Signer
	var err error
	switch len(privateKeyMaterial) {
	case ed25519.SeedSize:
		signer, err = NewSignerFromSeed(privateKeyMaterial)
	case ed25519.PrivateKeySize:
		signer, err = NewSigner(ed25519.PrivateKey(privateKeyMaterial))
	default:
		return nil, errors.New("network capability key must be a 32-byte Ed25519 seed or 64-byte private key")
	}
	if err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > maxTimeout+5*time.Second {
		timeout = maxTimeout + 5*time.Second
	}
	return &ProcessExecutor{binary: binary, signer: signer, publicKey: signer.PublicKey(), timeout: timeout}, nil
}

// BuildSignedJob normalizes all request-controlled data and binds it into a
// single-use Ed25519 capability. The returned Job contains no local path.
func BuildSignedJob(signer *Signer, request Request, expiresAt time.Time) (Job, error) {
	if signer == nil {
		return Job{}, errors.New("network capability signer is required")
	}
	if request.RequestID == "" || request.Principal == "" || request.WorkspaceID == "" || request.BridgeID == "" || request.SessionID == "" || request.ClientRequestID == "" || request.PolicyID == "" || request.ProfileID == "" {
		return Job{}, errors.New("network request scope is incomplete")
	}
	if err := validateOperationMethod(request.Operation, request.Method); err != nil {
		return Job{}, err
	}
	normalizedURL, err := NormalizeURL(request.URL)
	if err != nil {
		return Job{}, err
	}
	normalizedPolicy, err := normalizePolicy(request.Policy)
	if err != nil {
		return Job{}, err
	}
	if err := validateLimits(request.Limits); err != nil {
		return Job{}, err
	}
	normalizedHeaders, headerBytes, err := normalizeHeaders(request.Headers, normalizedPolicy)
	if err != nil {
		return Job{}, err
	}
	if headerBytes > request.Limits.MaxRequestHeaderBytes {
		return Job{}, errors.New("request headers exceed the signed limit")
	}
	if int64(len(request.Body)) > request.Limits.MaxRequestBodyBytes {
		return Job{}, errors.New("request body exceeds the signed limit")
	}
	if request.Operation != OperationUpload && len(request.Body) != 0 {
		return Job{}, errors.New("only upload jobs may contain a request body")
	}
	tokenID := request.TokenID
	if tokenID == "" {
		tokenID = randomID("net-cap-")
	}
	job := Job{
		TokenID: tokenID, WorkerType: WorkerType, RequestID: request.RequestID,
		Principal: request.Principal, WorkspaceID: request.WorkspaceID, BridgeID: request.BridgeID,
		SessionID: request.SessionID, ClientRequestID: request.ClientRequestID,
		Operation: request.Operation, URL: normalizedURL, Method: request.Method,
		Headers: normalizedHeaders, PolicyID: request.PolicyID, ProfileID: request.ProfileID,
		Policy: normalizedPolicy, Limits: request.Limits,
	}
	if len(request.Body) > 0 {
		job.BodyBase64 = base64.StdEncoding.EncodeToString(request.Body)
	}
	headersSHA256, err := headersDigest(job.Headers)
	if err != nil {
		return Job{}, err
	}
	policySHA256, err := policyDigest(job.Policy)
	if err != nil {
		return Job{}, err
	}
	claims := Claims{
		TokenID: tokenID, WorkerType: WorkerType, RequestID: request.RequestID,
		Principal: request.Principal, WorkspaceID: request.WorkspaceID, BridgeID: request.BridgeID,
		SessionID: request.SessionID, ClientRequestID: request.ClientRequestID,
		Operation: request.Operation, URL: normalizedURL, Method: request.Method,
		HeadersSHA256: headersSHA256, BodySHA256: digest(request.Body), PolicyID: request.PolicyID,
		ProfileID: request.ProfileID, PolicySHA256: policySHA256, Limits: request.Limits,
		ExpiresAt: expiresAt.UTC(), SingleUse: true,
	}
	job.Token, err = signer.Sign(claims)
	if err != nil {
		return Job{}, err
	}
	return job, nil
}

// Execute starts exactly one worker process for exactly one signed job. Only the
// Ed25519 public key is placed in the worker's otherwise empty environment.
func (executor *ProcessExecutor) Execute(ctx context.Context, request Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{TokenID: request.TokenID, Untrusted: true}, err
	}
	job, err := BuildSignedJob(executor.signer, request, time.Now().UTC().Add(capabilityTTL))
	if err != nil {
		return Response{}, err
	}
	input, err := json.Marshal(job)
	if err != nil {
		return Response{}, err
	}
	workerTimeout := executor.timeout
	jobTimeout := time.Duration(job.Limits.TimeoutMillis)*time.Millisecond + 5*time.Second
	if jobTimeout < workerTimeout {
		workerTimeout = jobTimeout
	}
	workerCtx, cancel := context.WithTimeout(ctx, workerTimeout)
	defer cancel()
	command := exec.CommandContext(workerCtx, executor.binary)
	configureWorkerProcess(command)
	command.Cancel = func() error { return killWorkerProcess(command) }
	command.WaitDelay = 2 * time.Second
	command.Env = []string{"REMOTE_AGENT_NETWORK_WORKER_PUBLIC_KEY=" + base64.RawStdEncoding.EncodeToString(executor.publicKey)}
	command.Stdin = bytes.NewReader(input)
	stdout := newLimitBuffer(MaxWorkerResponseBytes)
	stderr := newLimitBuffer(16 << 10)
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return Response{TokenID: job.TokenID, Untrusted: true}, errors.New("network worker output exceeded limit")
	}
	if runErr != nil {
		if errors.Is(workerCtx.Err(), context.Canceled) {
			return Response{TokenID: job.TokenID, Untrusted: true}, context.Canceled
		}
		if errors.Is(workerCtx.Err(), context.DeadlineExceeded) {
			return Response{TokenID: job.TokenID, Untrusted: true}, fmt.Errorf("network worker timed out: %w", context.DeadlineExceeded)
		}
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 512 {
			detail = detail[:512]
		}
		return Response{TokenID: job.TokenID, Untrusted: true}, fmt.Errorf("network worker failed: %w: %s", runErr, detail)
	}
	var response Response
	if err := decodeStrict(stdout.Bytes(), &response); err != nil {
		return Response{TokenID: job.TokenID, Untrusted: true}, errors.New("network worker returned an invalid response")
	}
	if response.TokenID != job.TokenID || response.WorkerID == "" || !response.Untrusted {
		return Response{TokenID: job.TokenID, Untrusted: true}, errors.New("network worker response identity mismatch")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

type limitBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newLimitBuffer(limit int) *limitBuffer {
	return &limitBuffer{limit: limit}
}

func (buffer *limitBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return originalLength, nil
	}
	if len(value) > remaining {
		buffer.exceeded = true
		value = value[:remaining]
	}
	_, _ = buffer.buffer.Write(value)
	return originalLength, nil
}

func (buffer *limitBuffer) Bytes() []byte  { return buffer.buffer.Bytes() }
func (buffer *limitBuffer) String() string { return buffer.buffer.String() }
