package remoteworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bkcarlos/remote_agent/internal/credentialstore"
	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const maxWorkerResponseBytes = 16 << 20

type Request struct {
	RequestID       string
	Principal       string
	WorkspaceID     string
	BridgeID        string
	SessionID       string
	ClientRequestID string
	ProfileName     string
	Operation       string
	RemotePath      string
	DestinationPath string
	Argv            []string
	Content         []byte
	Limits          Limits
}

type ProcessExecutor struct {
	binary     string
	configPath string
	signer     *Signer
	publicKey  ed25519.PublicKey
}

func NewProcessExecutor(binary, configPath string, privateKeyMaterial []byte) (*ProcessExecutor, error) {
	if binary == "" || configPath == "" {
		return nil, errors.New("remote worker binary and profile configuration path are required")
	}
	var signer *Signer
	var err error
	switch len(privateKeyMaterial) {
	case ed25519.SeedSize:
		signer, err = NewSignerFromSeed(privateKeyMaterial)
	case ed25519.PrivateKeySize:
		signer, err = NewSigner(ed25519.PrivateKey(privateKeyMaterial))
	default:
		err = errors.New("remote worker signing key must be a 32-byte seed or 64-byte Ed25519 private key")
	}
	if err != nil {
		return nil, err
	}
	return &ProcessExecutor{binary: binary, configPath: configPath, signer: signer, publicKey: signer.PublicKey()}, nil
}

// Execute resolves exactly one opaque profile name in the trusted parent and
// starts exactly one short-lived worker. No credential path or key enters argv,
// environment, stdin, stdout, stderr, or the returned response.
func (executor *ProcessExecutor) Execute(ctx context.Context, request Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if request.RequestID == "" || request.Principal == "" || request.WorkspaceID == "" || request.BridgeID == "" || request.SessionID == "" || request.ClientRequestID == "" {
		return Response{}, errors.New("remote request scope is incomplete")
	}
	credential, err := credentialstore.Load(executor.configPath, request.ProfileName)
	if err != nil {
		return Response{}, errors.New("remote profile is unavailable")
	}
	defer credential.Close()
	snapshotDigest, err := credential.SnapshotDigest()
	if err != nil {
		return Response{}, errors.New("remote profile snapshot failed")
	}
	expiresAt := time.Now().UTC().Add(30 * time.Second)
	if profileExpiry := credential.Snapshot().ExpiresAt; profileExpiry.Before(expiresAt) {
		expiresAt = profileExpiry
	}
	job := Job{
		JobID: randomID(), WorkerType: WorkerType, RequestID: request.RequestID,
		Principal: request.Principal, WorkspaceID: request.WorkspaceID, BridgeID: request.BridgeID,
		SessionID: request.SessionID, ClientRequestID: request.ClientRequestID,
		ProfileName: request.ProfileName, ProfileSnapshotSHA256: snapshotDigest, Operation: request.Operation,
		RemotePath: request.RemotePath, DestinationPath: request.DestinationPath,
		Argv: append([]string{}, request.Argv...), Content: append([]byte(nil), request.Content...),
		Limits: request.Limits, ExpiresAt: expiresAt,
	}
	if request.Operation == OperationSFTPWrite {
		sum := sha256Bytes(job.Content)
		job.ContentSHA256 = sum
	}
	signedJob, err := executor.signer.Sign(job)
	if err != nil {
		return Response{}, err
	}

	credentialReader, credentialWriter, err := os.Pipe()
	if err != nil {
		return Response{}, errors.New("create credential pipe")
	}
	defer credentialReader.Close()
	defer credentialWriter.Close()
	extraFiles := []*os.File{credentialReader}
	agentFile, err := credential.DuplicateAgentFile()
	if err != nil {
		return Response{}, errors.New("prepare ssh-agent descriptor")
	}
	if agentFile != nil {
		defer agentFile.Close()
		extraFiles = append(extraFiles, agentFile)
	}

	workingDirectory, err := os.MkdirTemp("", "remote-worker-empty-*")
	if err != nil {
		return Response{}, errors.New("prepare remote worker directory")
	}
	defer os.Remove(workingDirectory)
	workerContext, cancel := context.WithTimeout(ctx, time.Duration(request.Limits.TimeoutMillis)*time.Millisecond+5*time.Second)
	defer cancel()
	arguments := []string{"-public-key", base64.RawStdEncoding.EncodeToString(executor.publicKey), "-credential-fd", "3"}
	if agentFile != nil {
		arguments = append(arguments, "-agent-fd", "4")
	}
	command := exec.CommandContext(workerContext, executor.binary, arguments...)
	configureWorkerProcess(command)
	command.Cancel = func() error { return killWorkerProcess(command) }
	command.WaitDelay = 2 * time.Second
	command.Dir = workingDirectory
	command.Env = []string{}
	command.ExtraFiles = extraFiles
	command.Stdin = bytes.NewReader(signedJob)
	stdout := &boundedBuffer{limit: maxWorkerResponseBytes}
	stderr := &boundedBuffer{limit: 16 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return Response{}, errors.New("start remote worker")
	}
	_ = credentialReader.Close()
	deliveryErr := credential.WriteWorkerEnvelope(credentialWriter)
	_ = credentialWriter.Close()
	waitErr := command.Wait()
	if deliveryErr != nil {
		return Response{}, errors.New("deliver remote worker credential")
	}
	if stdout.exceeded || stderr.exceeded {
		return Response{}, errors.New("remote worker response exceeded limit")
	}
	if waitErr != nil {
		if errors.Is(workerContext.Err(), context.DeadlineExceeded) {
			return Response{}, fmt.Errorf("remote worker timed out: %w", context.DeadlineExceeded)
		}
		if errors.Is(workerContext.Err(), context.Canceled) {
			return Response{}, context.Canceled
		}
		return Response{}, errors.New("remote worker failed")
	}
	var response Response
	if err := protocol.DecodeStrict(stdout.Bytes(), &response); err != nil {
		return Response{}, errors.New("remote worker returned an invalid response")
	}
	if response.JobID != job.JobID {
		return Response{}, errors.New("remote worker response identity mismatch")
	}
	if response.Error != "" {
		return response, &RemoteError{Kind: response.ErrorKind}
	}
	return response, nil
}

type RemoteError struct{ Kind string }

func (err *RemoteError) Error() string { return "remote worker operation failed" }

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - int64(buffer.buffer.Len())
	if remaining <= 0 {
		buffer.exceeded = true
		return len(value), nil
	}
	if int64(len(value)) > remaining {
		_, _ = buffer.buffer.Write(value[:remaining])
		buffer.exceeded = true
		return len(value), nil
	}
	return buffer.buffer.Write(value)
}

func (buffer *boundedBuffer) Bytes() []byte { return buffer.buffer.Bytes() }

func randomID() string {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(value)
}

func sha256Bytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
