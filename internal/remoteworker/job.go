package remoteworker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const (
	JobVersion      = 1
	WorkerType      = "remote"
	MaxSignedBytes  = 16 << 20
	maxJobLifetime  = time.Minute
	maxOutputBytes  = 8 << 20
	maxFileBytes    = 8 << 20
	maxListEntries  = 10000
	maxTimeout      = 30 * time.Second
	signatureDomain = "remote-agent/remote-job/v1\x00"
)

const (
	OperationSSHExec    = "ssh_exec"
	OperationSFTPList   = "sftp_list"
	OperationSFTPRead   = "sftp_read"
	OperationSFTPWrite  = "sftp_write"
	OperationSFTPMkdir  = "sftp_mkdir"
	OperationSFTPRename = "sftp_rename"
)

type Limits struct {
	MaxOutputBytes int64 `json:"max_output_bytes"`
	MaxFileBytes   int64 `json:"max_file_bytes"`
	MaxEntries     int   `json:"max_entries"`
	TimeoutMillis  int64 `json:"timeout_millis"`
}

type Job struct {
	JobID                 string    `json:"job_id"`
	WorkerType            string    `json:"worker_type"`
	RequestID             string    `json:"request_id"`
	Principal             string    `json:"principal"`
	WorkspaceID           string    `json:"workspace_id"`
	BridgeID              string    `json:"bridge_id"`
	SessionID             string    `json:"session_id"`
	ClientRequestID       string    `json:"client_request_id"`
	ProfileName           string    `json:"profile_name"`
	ProfileSnapshotSHA256 string    `json:"profile_snapshot_sha256"`
	Operation             string    `json:"operation"`
	RemotePath            string    `json:"remote_path"`
	DestinationPath       string    `json:"destination_path,omitempty"`
	Argv                  []string  `json:"argv"`
	Content               []byte    `json:"content,omitempty"`
	ContentSHA256         string    `json:"content_sha256,omitempty"`
	Limits                Limits    `json:"limits"`
	ExpiresAt             time.Time `json:"expires_at"`
}

type SignedJob struct {
	Version   int    `json:"version"`
	Job       Job    `json:"job"`
	Signature string `json:"signature"`
}

type Signer struct {
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

type Verifier struct {
	publicKey ed25519.PublicKey
	now       func() time.Time
	mu        sync.Mutex
	used      map[string]struct{}
}

func NewSigner(privateKey ed25519.PrivateKey) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("remote worker Ed25519 private key must be 64 bytes")
	}
	return &Signer{privateKey: append(ed25519.PrivateKey(nil), privateKey...), now: time.Now}, nil
}

func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("remote worker Ed25519 seed must be 32 bytes")
	}
	return NewSigner(ed25519.NewKeyFromSeed(seed))
}

func (signer *Signer) PublicKey() ed25519.PublicKey {
	publicKey := signer.privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

func (signer *Signer) Sign(job Job) ([]byte, error) {
	if err := validateJob(job, signer.now().UTC()); err != nil {
		return nil, err
	}
	jobRaw, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(signer.privateKey, append([]byte(signatureDomain), jobRaw...))
	return json.Marshal(SignedJob{Version: JobVersion, Job: job, Signature: base64.RawURLEncoding.EncodeToString(signature)})
}

func NewVerifier(publicKey ed25519.PublicKey) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("remote worker Ed25519 public key must be 32 bytes")
	}
	return &Verifier{publicKey: append(ed25519.PublicKey(nil), publicKey...), now: time.Now, used: make(map[string]struct{})}, nil
}

func (verifier *Verifier) Verify(raw []byte, profileSnapshotDigest string) (Job, error) {
	var signed SignedJob
	if len(raw) == 0 || len(raw) > MaxSignedBytes {
		return Job{}, errors.New("invalid signed remote job")
	}
	if err := protocol.DecodeStrict(raw, &signed); err != nil || signed.Version != JobVersion {
		return Job{}, errors.New("invalid signed remote job")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Job{}, errors.New("invalid remote job signature")
	}
	jobRaw, err := json.Marshal(signed.Job)
	if err != nil || !ed25519.Verify(verifier.publicKey, append([]byte(signatureDomain), jobRaw...), signature) {
		return Job{}, errors.New("invalid remote job signature")
	}
	if err := validateJob(signed.Job, verifier.now().UTC()); err != nil {
		return Job{}, errors.New("invalid remote job: " + err.Error())
	}
	if signed.Job.ProfileSnapshotSHA256 != profileSnapshotDigest {
		return Job{}, errors.New("remote job profile snapshot mismatch")
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if _, exists := verifier.used[signed.Job.JobID]; exists {
		return Job{}, errors.New("remote job was already used")
	}
	verifier.used[signed.Job.JobID] = struct{}{}
	return signed.Job, nil
}

func validateJob(job Job, now time.Time) error {
	if job.JobID == "" || job.WorkerType != WorkerType || job.RequestID == "" || job.Principal == "" || job.WorkspaceID == "" || job.BridgeID == "" || job.SessionID == "" || job.ClientRequestID == "" || job.ProfileName == "" || job.Operation == "" {
		return errors.New("job identity is incomplete")
	}
	if !validDigest(job.ProfileSnapshotSHA256) {
		return errors.New("profile snapshot digest is invalid")
	}
	if job.ExpiresAt.IsZero() || !now.Before(job.ExpiresAt) {
		return errors.New("job has expired")
	}
	if job.ExpiresAt.After(now.Add(maxJobLifetime)) {
		return errors.New("job lifetime exceeds one minute")
	}
	if job.Limits.MaxOutputBytes <= 0 || job.Limits.MaxOutputBytes > maxOutputBytes ||
		job.Limits.MaxFileBytes < 0 || job.Limits.MaxFileBytes > maxFileBytes ||
		job.Limits.MaxEntries < 0 || job.Limits.MaxEntries > maxListEntries ||
		job.Limits.TimeoutMillis <= 0 || job.Limits.TimeoutMillis > maxTimeout.Milliseconds() {
		return errors.New("job limits are invalid")
	}
	if strings.IndexByte(job.ProfileName, 0) >= 0 {
		return errors.New("profile name is invalid")
	}
	if err := validateOperationShape(job); err != nil {
		return err
	}
	return nil
}

func validateOperationShape(job Job) error {
	if job.Argv == nil {
		return errors.New("argv must be a JSON array")
	}
	for _, argument := range job.Argv {
		if strings.IndexByte(argument, 0) >= 0 {
			return errors.New("argv cannot contain NUL")
		}
	}
	switch job.Operation {
	case OperationSSHExec:
		if job.RemotePath != "/" || job.DestinationPath != "" || len(job.Argv) == 0 || len(job.Content) != 0 || job.ContentSHA256 != "" {
			return errors.New("ssh_exec job shape is invalid")
		}
	case OperationSFTPList:
		if err := requireSFTPShape(job, false); err != nil || job.Limits.MaxEntries <= 0 {
			return errors.New("sftp_list job shape is invalid")
		}
	case OperationSFTPRead:
		if err := requireSFTPShape(job, false); err != nil || job.Limits.MaxFileBytes <= 0 {
			return errors.New("sftp_read job shape is invalid")
		}
	case OperationSFTPWrite:
		if err := requireSFTPShape(job, true); err != nil || job.Limits.MaxFileBytes <= 0 || int64(len(job.Content)) > job.Limits.MaxFileBytes || !validDigest(job.ContentSHA256) {
			return errors.New("sftp_write job shape is invalid")
		}
		sum := sha256.Sum256(job.Content)
		if hex.EncodeToString(sum[:]) != job.ContentSHA256 {
			return errors.New("sftp_write content digest mismatch")
		}
	case OperationSFTPMkdir:
		if err := requireSFTPShape(job, false); err != nil {
			return errors.New("sftp_mkdir job shape is invalid")
		}
	case OperationSFTPRename:
		if normalizeRemotePath(job.RemotePath) != nil || normalizeRemotePath(job.DestinationPath) != nil || len(job.Argv) != 0 || len(job.Content) != 0 || job.ContentSHA256 != "" {
			return errors.New("sftp_rename job shape is invalid")
		}
	default:
		return errors.New("unsupported remote operation")
	}
	return nil
}

func requireSFTPShape(job Job, withContent bool) error {
	if normalizeRemotePath(job.RemotePath) != nil || job.DestinationPath != "" || len(job.Argv) != 0 {
		return errors.New("invalid SFTP job")
	}
	if !withContent && (len(job.Content) != 0 || job.ContentSHA256 != "") {
		return errors.New("unexpected SFTP content")
	}
	return nil
}

func normalizeRemotePath(raw string) error {
	if raw == "" || !path.IsAbs(raw) || strings.IndexByte(raw, 0) >= 0 || path.Clean(raw) != raw {
		return errors.New("remote path must be a clean absolute POSIX path")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
