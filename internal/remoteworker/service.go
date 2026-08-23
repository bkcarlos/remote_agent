package remoteworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/bkcarlos/remote_agent/internal/credentialstore"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Entry struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
}

type Response struct {
	JobID      string  `json:"job_id"`
	Stdout     []byte  `json:"stdout,omitempty"`
	Stderr     []byte  `json:"stderr,omitempty"`
	ExitStatus int     `json:"exit_status,omitempty"`
	Entries    []Entry `json:"entries,omitempty"`
	Content    []byte  `json:"content,omitempty"`
	SHA256     string  `json:"sha256,omitempty"`
	Bytes      int64   `json:"bytes,omitempty"`
	Error      string  `json:"error,omitempty"`
	ErrorKind  string  `json:"error_kind,omitempty"`
}

type Service struct {
	credential *credentialstore.Credential
	verifier   *Verifier
	connector  connector
	lockdown   func() error
}

type connector interface {
	Connect(context.Context, *credentialstore.Credential) (remoteConnection, error)
}

type remoteConnection interface {
	Exec([]string, int64) ([]byte, []byte, int, error)
	SFTP() (sftpClient, error)
	Close() error
}

type remoteFile interface {
	io.Reader
	io.Writer
	io.Closer
}

type sftpClient interface {
	RealPath(string) (string, error)
	Stat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.FileInfo, error)
	Open(string) (remoteFile, error)
	OpenFile(string, int) (remoteFile, error)
	Mkdir(string) error
	Rename(string, string) error
	Close() error
}

func NewService(publicKey ed25519.PublicKey, credential *credentialstore.Credential, lockdown func() error) (*Service, error) {
	if credential == nil {
		return nil, errors.New("remote worker credential is required")
	}
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		return nil, err
	}
	if lockdown == nil {
		lockdown = func() error { return nil }
	}
	return &Service{credential: credential, verifier: verifier, connector: networkConnector{}, lockdown: lockdown}, nil
}

func newServiceWithConnector(publicKey ed25519.PublicKey, credential *credentialstore.Credential, connector connector, lockdown func() error) (*Service, error) {
	service, err := NewService(publicKey, credential, lockdown)
	if err != nil {
		return nil, err
	}
	service.connector = connector
	return service, nil
}

func (service *Service) Execute(ctx context.Context, signedJob []byte) Response {
	snapshot := service.credential.Snapshot()
	digest, err := snapshot.Digest()
	if err != nil {
		return failedResponse("", "authorization_failed")
	}
	job, err := service.verifier.Verify(signedJob, digest)
	if err != nil {
		return failedResponse("", "authorization_failed")
	}
	response := Response{JobID: job.JobID}
	if !time.Now().UTC().Before(snapshot.ExpiresAt) {
		return failedResponse(job.JobID, "profile_expired")
	}
	if err := operationAllowed(job, snapshot); err != nil {
		return failedResponse(job.JobID, "policy_denied")
	}
	if err := service.lockdown(); err != nil {
		return failedResponse(job.JobID, "sandbox_failed")
	}
	jobTimeout := time.Duration(job.Limits.TimeoutMillis) * time.Millisecond
	deadline := time.Now().UTC().Add(jobTimeout)
	if job.ExpiresAt.Before(deadline) {
		deadline = job.ExpiresAt
	}
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	connection, err := service.connector.Connect(operationContext, service.credential)
	if err != nil {
		return failedResponse(job.JobID, "connection_failed")
	}
	defer connection.Close()

	switch job.Operation {
	case OperationSSHExec:
		response.Stdout, response.Stderr, response.ExitStatus, err = connection.Exec(job.Argv, job.Limits.MaxOutputBytes)
	case OperationSFTPList, OperationSFTPRead, OperationSFTPWrite, OperationSFTPMkdir, OperationSFTPRename:
		client, openErr := connection.SFTP()
		if openErr != nil {
			return failedResponse(job.JobID, "sftp_unavailable")
		}
		defer client.Close()
		response, err = executeSFTP(job, snapshot, client)
	default:
		err = errors.New("unsupported operation")
	}
	if err == nil {
		err = enforceResponseLimit(job, response)
	}
	if err != nil {
		kind := "operation_failed"
		if errors.Is(err, errLimitExceeded) {
			kind = "limit_exceeded"
		}
		return failedResponse(job.JobID, kind)
	}
	return response
}

func enforceResponseLimit(job Job, response Response) error {
	if job.Operation == OperationSSHExec {
		return nil
	}
	if int64(len(response.Content)) > job.Limits.MaxOutputBytes {
		return errLimitExceeded
	}
	if len(response.Entries) > 0 {
		raw, err := json.Marshal(response.Entries)
		if err != nil || int64(len(raw)) > job.Limits.MaxOutputBytes {
			return errLimitExceeded
		}
	}
	return nil
}

func failedResponse(jobID, kind string) Response {
	return Response{JobID: jobID, Error: "remote worker operation failed", ErrorKind: kind}
}

var errLimitExceeded = errors.New("remote operation limit exceeded")

type networkConnector struct{}

type sshRemoteConnection struct {
	client *ssh.Client
}

func (networkConnector) Connect(ctx context.Context, credential *credentialstore.Credential) (remoteConnection, error) {
	snapshot := credential.Snapshot()
	config, err := credential.SSHClientConfig()
	if err != nil {
		return nil, err
	}
	endpoint := net.JoinHostPort(snapshot.Host, fmt.Sprintf("%d", snapshot.Port))
	networkConnection, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = networkConnection.SetDeadline(deadline)
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(networkConnection, endpoint, config)
	if err != nil {
		networkConnection.Close()
		return nil, err
	}
	return &sshRemoteConnection{client: ssh.NewClient(clientConnection, channels, requests)}, nil
}

func (connection *sshRemoteConnection) Close() error { return connection.client.Close() }

func (connection *sshRemoteConnection) Exec(argv []string, maxOutput int64) ([]byte, []byte, int, error) {
	command, err := QuoteArgv(argv)
	if err != nil {
		return nil, nil, 0, err
	}
	session, err := connection.client.NewSession()
	if err != nil {
		return nil, nil, 0, err
	}
	defer session.Close()
	budget := &outputBudget{remaining: maxOutput}
	stdout := &limitedOutput{budget: budget}
	stderr := &limitedOutput{budget: budget}
	session.Stdout = stdout
	session.Stderr = stderr
	runErr := session.Run(command)
	if budget.exceeded {
		return nil, nil, 0, errLimitExceeded
	}
	exitStatus := 0
	if runErr != nil {
		var exitError *ssh.ExitError
		if !errors.As(runErr, &exitError) {
			return nil, nil, 0, runErr
		}
		exitStatus = exitError.ExitStatus()
	}
	return stdout.buffer.Bytes(), stderr.buffer.Bytes(), exitStatus, nil
}

func (connection *sshRemoteConnection) SFTP() (sftpClient, error) {
	client, err := sftp.NewClient(connection.client, sftp.UseConcurrentReads(false), sftp.UseConcurrentWrites(false))
	if err != nil {
		return nil, err
	}
	return realSFTPClient{client}, nil
}

type realSFTPClient struct{ *sftp.Client }

func (client realSFTPClient) Open(name string) (remoteFile, error) {
	return client.Client.Open(name)
}

func (client realSFTPClient) OpenFile(name string, flags int) (remoteFile, error) {
	return client.Client.OpenFile(name, flags)
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int64
	exceeded  bool
}

type limitedOutput struct {
	budget *outputBudget
	buffer bytes.Buffer
}

func (writer *limitedOutput) Write(value []byte) (int, error) {
	writer.budget.mu.Lock()
	defer writer.budget.mu.Unlock()
	if int64(len(value)) > writer.budget.remaining {
		allowed := writer.budget.remaining
		if allowed > 0 {
			_, _ = writer.buffer.Write(value[:allowed])
		}
		writer.budget.remaining = 0
		writer.budget.exceeded = true
		return int(allowed), errLimitExceeded
	}
	writer.budget.remaining -= int64(len(value))
	return writer.buffer.Write(value)
}

func executeSFTP(job Job, snapshot credentialstore.Snapshot, client sftpClient) (Response, error) {
	response := Response{JobID: job.JobID}
	canonicalRoots, err := canonicalSFTPRoots(client, snapshot.SFTP.Roots)
	if err != nil {
		return response, err
	}
	switch job.Operation {
	case OperationSFTPList:
		securePath, err := secureExistingPath(client, job.RemotePath, canonicalRoots)
		if err != nil {
			return response, err
		}
		entries, err := client.ReadDir(securePath)
		if err != nil {
			return response, err
		}
		if len(entries) > job.Limits.MaxEntries {
			return response, errLimitExceeded
		}
		response.Entries = make([]Entry, len(entries))
		for i, entry := range entries {
			response.Entries[i] = Entry{Name: entry.Name(), Size: entry.Size(), Mode: entry.Mode().String(), ModTime: entry.ModTime().UTC()}
		}
	case OperationSFTPRead:
		securePath, err := secureExistingPath(client, job.RemotePath, canonicalRoots)
		if err != nil {
			return response, err
		}
		info, err := client.Stat(securePath)
		if err != nil || !info.Mode().IsRegular() || info.Size() > job.Limits.MaxFileBytes {
			if info != nil && info.Size() > job.Limits.MaxFileBytes {
				return response, errLimitExceeded
			}
			return response, errors.New("remote file is not readable")
		}
		file, err := client.Open(securePath)
		if err != nil {
			return response, err
		}
		defer file.Close()
		response.Content, err = io.ReadAll(io.LimitReader(file, job.Limits.MaxFileBytes+1))
		if err != nil {
			return response, err
		}
		if int64(len(response.Content)) > job.Limits.MaxFileBytes {
			return response, errLimitExceeded
		}
		response.Bytes = int64(len(response.Content))
		sum := sha256.Sum256(response.Content)
		response.SHA256 = hex.EncodeToString(sum[:])
	case OperationSFTPWrite:
		securePath, err := secureCreationPath(client, job.RemotePath, canonicalRoots)
		if err != nil {
			return response, err
		}
		file, err := client.OpenFile(securePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return response, err
		}
		written, writeErr := io.Copy(file, bytes.NewReader(job.Content))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || written != int64(len(job.Content)) {
			return response, errors.New("remote write failed")
		}
		response.Bytes = written
		response.SHA256 = job.ContentSHA256
	case OperationSFTPMkdir:
		securePath, err := secureCreationPath(client, job.RemotePath, canonicalRoots)
		if err != nil {
			return response, err
		}
		if err := client.Mkdir(securePath); err != nil {
			return response, err
		}
	case OperationSFTPRename:
		source, err := secureExistingPath(client, job.RemotePath, canonicalRoots)
		if err != nil {
			return response, err
		}
		destination, err := secureCreationPath(client, job.DestinationPath, canonicalRoots)
		if err != nil {
			return response, err
		}
		if err := client.Rename(source, destination); err != nil {
			return response, err
		}
	}
	return response, nil
}

func canonicalSFTPRoots(client sftpClient, roots []string) ([]string, error) {
	canonical := make([]string, len(roots))
	for i, root := range roots {
		resolved, err := client.RealPath(root)
		if err != nil || !path.IsAbs(resolved) {
			return nil, errors.New("resolve configured SFTP root")
		}
		canonical[i] = path.Clean(resolved)
	}
	return canonical, nil
}

func secureExistingPath(client sftpClient, requested string, canonicalRoots []string) (string, error) {
	resolved, err := client.RealPath(requested)
	if err != nil {
		return "", err
	}
	resolved = path.Clean(resolved)
	if err := authorizeResolvedPath(resolved, canonicalRoots); err != nil {
		return "", err
	}
	return resolved, nil
}

func secureCreationPath(client sftpClient, requested string, canonicalRoots []string) (string, error) {
	if resolved, err := client.RealPath(requested); err == nil {
		resolved = path.Clean(resolved)
		if err := authorizeResolvedPath(resolved, canonicalRoots); err != nil {
			return "", err
		}
		return resolved, nil
	}
	parent, err := client.RealPath(path.Dir(requested))
	if err != nil {
		return "", err
	}
	resolved := path.Join(path.Clean(parent), path.Base(requested))
	if err := authorizeResolvedPath(resolved, canonicalRoots); err != nil {
		return "", err
	}
	return resolved, nil
}
