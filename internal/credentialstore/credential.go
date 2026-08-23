package credentialstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Credential struct {
	mu              sync.Mutex
	snapshot        Snapshot
	privateKey      []byte
	signers         []ssh.Signer
	hostKeyCallback ssh.HostKeyCallback
	knownHosts      []byte
	agentConn       net.Conn
	closed          bool
}

// MarshalJSON deliberately prevents accidental serialization into logs,
// requests, caches, or AI-visible tool responses.
func (*Credential) MarshalJSON() ([]byte, error) {
	return nil, errors.New("SSH credentials are not serializable")
}

func loadCredential(profile profile) (*Credential, error) {
	knownHosts, err := readBoundedFile(profile.KnownHostsPath, maxKnownHostsBytes, "known_hosts")
	if err != nil {
		return nil, err
	}
	hostKeyCallback, err := validateKnownHosts(profile, knownHosts)
	if err != nil {
		zero(knownHosts)
		return nil, err
	}
	knownHostsSum := sha256.Sum256(knownHosts)

	credential := &Credential{knownHosts: knownHosts, hostKeyCallback: hostKeyCallback}
	if profile.PrivateKeyPath != "" {
		privateKey, err := readPrivateKey(profile.PrivateKeyPath)
		if err != nil {
			credential.Close()
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			zero(privateKey)
			credential.Close()
			return nil, errors.New("private key is invalid or encrypted")
		}
		credential.privateKey = privateKey
		credential.signers = []ssh.Signer{signer}
		authDigest := digestPublicKeys([]ssh.PublicKey{signer.PublicKey()})
		credential.snapshot = snapshotFor(profile, "private_key", authDigest, hex.EncodeToString(knownHostsSum[:]))
		return credential, nil
	}

	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		credential.Close()
		return nil, errors.New("SSH_AUTH_SOCK must name an absolute agent socket")
	}
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		credential.Close()
		return nil, errors.New("connect ssh-agent")
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) == 0 {
		conn.Close()
		credential.Close()
		return nil, errors.New("ssh-agent has no usable identities")
	}
	keys := make([]ssh.PublicKey, len(signers))
	for i := range signers {
		keys[i] = signers[i].PublicKey()
	}
	credential.agentConn = conn
	credential.signers = append([]ssh.Signer(nil), signers...)
	credential.snapshot = snapshotFor(profile, "ssh_agent", digestPublicKeys(keys), hex.EncodeToString(knownHostsSum[:]))
	return credential, nil
}

func (credential *Credential) Snapshot() Snapshot {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	return cloneSnapshot(credential.snapshot)
}

func (credential *Credential) SnapshotDigest() (string, error) {
	return credential.Snapshot().Digest()
}

// DuplicateAgentFile returns only a capability to the already-connected agent;
// it never reveals SSH_AUTH_SOCK. The caller passes this descriptor directly to
// a worker as an inherited anonymous descriptor.
func (credential *Credential) DuplicateAgentFile() (*os.File, error) {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.closed {
		return nil, errors.New("credential is closed")
	}
	if credential.snapshot.Authentication != "ssh_agent" || credential.agentConn == nil {
		return nil, nil
	}
	type fileConner interface{ File() (*os.File, error) }
	conn, ok := credential.agentConn.(fileConner)
	if !ok {
		return nil, errors.New("ssh-agent connection cannot be inherited")
	}
	return conn.File()
}

func (credential *Credential) SSHClientConfig() (*ssh.ClientConfig, error) {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.closed {
		return nil, errors.New("credential is closed")
	}
	if !time.Now().UTC().Before(credential.snapshot.ExpiresAt) {
		return nil, errors.New("SSH profile has expired")
	}
	var methods []ssh.AuthMethod
	switch credential.snapshot.Authentication {
	case "private_key":
		if len(credential.signers) != 1 {
			return nil, errors.New("private-key credential is unavailable")
		}
		methods = []ssh.AuthMethod{ssh.PublicKeys(credential.signers...)}
	case "ssh_agent":
		if credential.agentConn == nil || len(credential.signers) == 0 {
			return nil, errors.New("ssh-agent credential is unavailable")
		}
		methods = []ssh.AuthMethod{ssh.PublicKeys(credential.signers...)}
	default:
		return nil, errors.New("credential authentication is invalid")
	}
	if credential.hostKeyCallback == nil {
		return nil, errors.New("host-key verifier is unavailable")
	}
	return &ssh.ClientConfig{
		User: credential.snapshot.User, Auth: methods,
		HostKeyCallback: credential.hostKeyCallback,
	}, nil
}

func (credential *Credential) Close() error {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.closed {
		return nil
	}
	credential.closed = true
	zero(credential.privateKey)
	zero(credential.knownHosts)
	credential.privateKey = nil
	credential.knownHosts = nil
	credential.signers = nil
	credential.hostKeyCallback = nil
	if credential.agentConn != nil {
		return credential.agentConn.Close()
	}
	return nil
}

func readPrivateKey(keyPath string) ([]byte, error) {
	file, err := openSecureRegular(keyPath, "private key")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("private key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key permissions are too broad")
	}
	return readAllBounded(file, maxPrivateKeyBytes, "private key")
}

func digestPublicKeys(keys []ssh.PublicKey) string {
	encoded := make([]string, len(keys))
	for i := range keys {
		sum := sha256.Sum256(keys[i].Marshal())
		encoded[i] = hex.EncodeToString(sum[:])
	}
	sort.Strings(encoded)
	raw, _ := json.Marshal(encoded)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func callbackFromKnownHosts(raw []byte) (ssh.HostKeyCallback, error) {
	file, err := os.CreateTemp("", "remote-agent-known-hosts-*")
	if err != nil {
		return nil, errors.New("prepare host-key verifier")
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, errors.New("prepare host-key verifier")
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return nil, errors.New("prepare host-key verifier")
	}
	if err := file.Close(); err != nil {
		return nil, errors.New("prepare host-key verifier")
	}
	callback, err := knownhosts.New(name)
	if err != nil {
		return nil, errors.New("known_hosts data is invalid")
	}
	return callback, nil
}

func readAllBounded(reader io.Reader, max int64, description string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s", description)
	}
	if int64(len(raw)) > max {
		zero(raw)
		return nil, fmt.Errorf("%s exceeds size limit", description)
	}
	return raw, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
