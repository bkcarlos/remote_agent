package credentialstore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"

	"github.com/bkcarlos/remote_agent/internal/protocol"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var envelopeMagic = [8]byte{'R', 'A', 'S', 'S', 'H', 'C', '1', 0}

const maxEnvelopeHeaderBytes = 256 << 10

type envelopeHeader struct {
	Version  int      `json:"version"`
	Snapshot Snapshot `json:"snapshot"`
	AuthKind string   `json:"auth_kind"`
}

// WriteWorkerEnvelope streams credential material to a dedicated anonymous
// pipe. It intentionally has no []byte/string return form.
func (credential *Credential) WriteWorkerEnvelope(writer io.Writer) error {
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.closed {
		return errors.New("credential is closed")
	}
	header, err := json.Marshal(envelopeHeader{Version: 1, Snapshot: credential.snapshot, AuthKind: credential.snapshot.Authentication})
	if err != nil {
		return errors.New("encode credential envelope")
	}
	if len(header) > maxEnvelopeHeaderBytes {
		return errors.New("credential envelope header exceeds limit")
	}
	secret := credential.privateKey
	if credential.snapshot.Authentication == "ssh_agent" {
		secret = nil
	}
	lengths := make([]byte, 12)
	binary.BigEndian.PutUint32(lengths[0:4], uint32(len(header)))
	binary.BigEndian.PutUint32(lengths[4:8], uint32(len(secret)))
	binary.BigEndian.PutUint32(lengths[8:12], uint32(len(credential.knownHosts)))
	for _, part := range [][]byte{envelopeMagic[:], lengths, header, secret, credential.knownHosts} {
		if _, err := writer.Write(part); err != nil {
			return errors.New("deliver credential envelope")
		}
	}
	return nil
}

// ReadWorkerEnvelope is only for the isolated worker. Private-key input bytes
// are cleared immediately after ssh.ParsePrivateKey returns.
func ReadWorkerEnvelope(reader io.Reader, agentFile *os.File) (*Credential, error) {
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || magic != envelopeMagic {
		return nil, errors.New("invalid credential envelope")
	}
	lengths := make([]byte, 12)
	if _, err := io.ReadFull(reader, lengths); err != nil {
		return nil, errors.New("invalid credential envelope")
	}
	headerLength := int64(binary.BigEndian.Uint32(lengths[0:4]))
	secretLength := int64(binary.BigEndian.Uint32(lengths[4:8]))
	knownHostsLength := int64(binary.BigEndian.Uint32(lengths[8:12]))
	if headerLength <= 0 || headerLength > maxEnvelopeHeaderBytes || secretLength > maxPrivateKeyBytes || knownHostsLength <= 0 || knownHostsLength > maxKnownHostsBytes {
		return nil, errors.New("invalid credential envelope lengths")
	}
	headerRaw := make([]byte, headerLength)
	if _, err := io.ReadFull(reader, headerRaw); err != nil {
		return nil, errors.New("incomplete credential envelope")
	}
	var header envelopeHeader
	if err := protocol.DecodeStrict(headerRaw, &header); err != nil || header.Version != 1 {
		return nil, errors.New("invalid credential envelope header")
	}
	secret := make([]byte, secretLength)
	if _, err := io.ReadFull(reader, secret); err != nil {
		zero(secret)
		return nil, errors.New("incomplete credential envelope")
	}
	knownHosts := make([]byte, knownHostsLength)
	if _, err := io.ReadFull(reader, knownHosts); err != nil {
		zero(secret)
		zero(knownHosts)
		return nil, errors.New("incomplete credential envelope")
	}
	knownHostsSum := sha256.Sum256(knownHosts)
	if hex.EncodeToString(knownHostsSum[:]) != header.Snapshot.KnownHostsSHA256 {
		zero(secret)
		zero(knownHosts)
		return nil, errors.New("credential known_hosts digest mismatch")
	}
	callback, err := callbackFromKnownHosts(knownHosts)
	zero(knownHosts)
	if err != nil {
		zero(secret)
		return nil, err
	}
	credential := &Credential{snapshot: cloneSnapshot(header.Snapshot), hostKeyCallback: callback}
	switch header.AuthKind {
	case "private_key":
		if len(secret) == 0 || agentFile != nil {
			zero(secret)
			return nil, errors.New("invalid private-key envelope")
		}
		signer, parseErr := ssh.ParsePrivateKey(secret)
		zero(secret)
		if parseErr != nil {
			return nil, errors.New("invalid private-key credential")
		}
		credential.signers = []ssh.Signer{signer}
		if digestPublicKeys([]ssh.PublicKey{signer.PublicKey()}) != header.Snapshot.AuthenticationKeysSHA256 {
			return nil, errors.New("credential authentication digest mismatch")
		}
	case "ssh_agent":
		zero(secret)
		if secretLength != 0 || agentFile == nil {
			return nil, errors.New("invalid ssh-agent envelope")
		}
		conn, err := net.FileConn(agentFile)
		if err != nil {
			return nil, errors.New("invalid ssh-agent descriptor")
		}
		client := agent.NewClient(conn)
		signers, err := client.Signers()
		if err != nil || len(signers) == 0 {
			conn.Close()
			return nil, errors.New("ssh-agent descriptor has no identities")
		}
		keys := make([]ssh.PublicKey, len(signers))
		for i := range signers {
			keys[i] = signers[i].PublicKey()
		}
		if digestPublicKeys(keys) != header.Snapshot.AuthenticationKeysSHA256 {
			conn.Close()
			return nil, errors.New("credential authentication digest mismatch")
		}
		credential.agentConn = conn
		credential.signers = append([]ssh.Signer(nil), signers...)
	default:
		zero(secret)
		return nil, errors.New("unsupported credential authentication")
	}
	if header.Snapshot.Authentication != header.AuthKind {
		credential.Close()
		return nil, errors.New("credential envelope authentication mismatch")
	}
	if err := validateSnapshot(header.Snapshot); err != nil {
		credential.Close()
		return nil, err
	}
	return credential, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Name == "" || snapshot.Host == "" || snapshot.Port < 1 || snapshot.Port > 65535 || snapshot.User == "" || snapshot.ExpiresAt.IsZero() {
		return errors.New("credential snapshot is incomplete")
	}
	if snapshot.Authentication != "private_key" && snapshot.Authentication != "ssh_agent" {
		return errors.New("credential snapshot authentication is invalid")
	}
	if len(snapshot.AuthenticationKeysSHA256) != 64 || len(snapshot.KnownHostsSHA256) != 64 {
		return errors.New("credential snapshot digest is invalid")
	}
	if snapshot.AllowedCommands == nil || snapshot.SFTP.Roots == nil {
		return errors.New("credential snapshot policy is incomplete")
	}
	return nil
}
