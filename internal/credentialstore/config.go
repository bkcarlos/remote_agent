package credentialstore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/bkcarlos/remote_agent/internal/protocol"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	ConfigVersion       = 1
	maxConfigBytes      = 1 << 20
	maxPrivateKeyBytes  = 1 << 20
	maxKnownHostsBytes  = 8 << 20
	maxProfileNameBytes = 1024
)

type config struct {
	Version  int       `json:"version"`
	Profiles []profile `json:"profiles"`
}

type profile struct {
	Name            string     `json:"name"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	User            string     `json:"user"`
	PrivateKeyPath  string     `json:"private_key_path,omitempty"`
	UseSSHAgent     bool       `json:"use_ssh_agent,omitempty"`
	KnownHostsPath  string     `json:"known_hosts_path"`
	AllowedCommands [][]string `json:"allowed_commands"`
	SFTP            SFTPPolicy `json:"sftp"`
	ExpiresAt       time.Time  `json:"expiry"`
}

type SFTPPolicy struct {
	Roots []string `json:"roots"`
	Read  bool     `json:"read"`
	Write bool     `json:"write"`
}

// Snapshot is the path-free, immutable policy sent to a worker. Its digest
// binds a signed job to the exact destination, trust store, identity and policy.
type Snapshot struct {
	Name                     string     `json:"name"`
	Host                     string     `json:"host"`
	Port                     int        `json:"port"`
	User                     string     `json:"user"`
	Authentication           string     `json:"authentication"`
	AuthenticationKeysSHA256 string     `json:"authentication_keys_sha256"`
	KnownHostsSHA256         string     `json:"known_hosts_sha256"`
	AllowedCommands          [][]string `json:"allowed_commands"`
	SFTP                     SFTPPolicy `json:"sftp"`
	ExpiresAt                time.Time  `json:"expiry"`
}

type RedactedProfile struct {
	Name            string     `json:"name"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	User            string     `json:"user"`
	Authentication  string     `json:"authentication"`
	AllowedCommands int        `json:"allowed_command_prefixes"`
	SFTP            SFTPPolicy `json:"sftp"`
	ExpiresAt       time.Time  `json:"expiry"`
}

func loadConfig(configPath string) (*config, error) {
	file, err := openSecureRegular(configPath, "profile configuration")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, errors.New("read profile configuration")
	}
	if len(raw) > maxConfigBytes {
		return nil, errors.New("profile configuration exceeds 1 MiB")
	}
	var config config
	if err := protocol.DecodeStrict(raw, &config); err != nil {
		return nil, fmt.Errorf("invalid profile configuration: %w", err)
	}
	if err := validateConfig(&config, time.Now().UTC()); err != nil {
		return nil, err
	}
	return &config, nil
}

// Validate parses and validates an administrator-selected configuration file
// without exposing its credential paths.
func Validate(configPath string) error {
	_, err := loadConfig(configPath)
	return err
}

func Load(configPath, profileName string) (*Credential, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	for i := range config.Profiles {
		if config.Profiles[i].Name == profileName {
			return loadCredential(config.Profiles[i])
		}
	}
	return nil, errors.New("unknown SSH profile")
}

func Redacted(configPath, profileName string) (RedactedProfile, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return RedactedProfile{}, err
	}
	for _, profile := range config.Profiles {
		if profile.Name != profileName {
			continue
		}
		authentication := "private_key"
		if profile.UseSSHAgent {
			authentication = "ssh_agent"
		}
		return RedactedProfile{
			Name: profile.Name, Host: profile.Host, Port: profile.Port, User: profile.User,
			Authentication: authentication, AllowedCommands: len(profile.AllowedCommands),
			SFTP: cloneSFTPPolicy(profile.SFTP), ExpiresAt: profile.ExpiresAt,
		}, nil
	}
	return RedactedProfile{}, errors.New("unknown SSH profile")
}

func validateConfig(config *config, now time.Time) error {
	if config.Version != ConfigVersion {
		return fmt.Errorf("unsupported profile configuration version %d", config.Version)
	}
	if config.Profiles == nil {
		return errors.New("profiles must be a JSON array")
	}
	seen := make(map[string]struct{}, len(config.Profiles))
	for i := range config.Profiles {
		profile := &config.Profiles[i]
		if _, exists := seen[profile.Name]; exists {
			return errors.New("duplicate profile name")
		}
		seen[profile.Name] = struct{}{}
		if err := validateProfile(profile, now); err != nil {
			return fmt.Errorf("invalid profile at index %d: %w", i, err)
		}
	}
	return nil
}

func validateProfile(profile *profile, now time.Time) error {
	if profile.Name == "" || len(profile.Name) > maxProfileNameBytes {
		return errors.New("profile name must be non-empty and at most 1024 bytes")
	}
	if profile.Host == "" || strings.ContainsAny(profile.Host, "\x00/\\[]") {
		return errors.New("host is invalid")
	}
	for _, r := range profile.Host {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("host is invalid")
		}
	}
	if profile.Port < 1 || profile.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if profile.User == "" || strings.IndexByte(profile.User, 0) >= 0 {
		return errors.New("user is invalid")
	}
	if (profile.PrivateKeyPath != "") == profile.UseSSHAgent {
		return errors.New("exactly one of private_key_path or use_ssh_agent is required")
	}
	if profile.PrivateKeyPath != "" && !filepath.IsAbs(profile.PrivateKeyPath) {
		return errors.New("private_key_path must be absolute")
	}
	if profile.KnownHostsPath == "" || !filepath.IsAbs(profile.KnownHostsPath) {
		return errors.New("known_hosts_path must be absolute")
	}
	if profile.ExpiresAt.IsZero() || !now.Before(profile.ExpiresAt) {
		return errors.New("profile has expired")
	}
	if profile.AllowedCommands == nil {
		return errors.New("allowed_commands must be a JSON array")
	}
	for _, prefix := range profile.AllowedCommands {
		if len(prefix) == 0 {
			return errors.New("allowed command prefixes cannot be empty")
		}
		for _, argument := range prefix {
			if argument == "" || strings.IndexByte(argument, 0) >= 0 {
				return errors.New("allowed command prefix arguments must be non-empty and contain no NUL")
			}
		}
	}
	if profile.SFTP.Roots == nil {
		return errors.New("sftp.roots must be a JSON array")
	}
	seenRoots := make(map[string]struct{}, len(profile.SFTP.Roots))
	for _, root := range profile.SFTP.Roots {
		if err := validateRemoteRoot(root); err != nil {
			return err
		}
		if _, exists := seenRoots[root]; exists {
			return errors.New("duplicate SFTP root")
		}
		seenRoots[root] = struct{}{}
	}
	if (profile.SFTP.Read || profile.SFTP.Write) && len(profile.SFTP.Roots) == 0 {
		return errors.New("enabled SFTP access requires at least one root")
	}
	return nil
}

func validateRemoteRoot(root string) error {
	if root == "" || !path.IsAbs(root) || strings.IndexByte(root, 0) >= 0 || path.Clean(root) != root {
		return errors.New("SFTP roots must be clean absolute POSIX paths")
	}
	return nil
}

func cloneSFTPPolicy(policy SFTPPolicy) SFTPPolicy {
	return SFTPPolicy{Roots: append([]string(nil), policy.Roots...), Read: policy.Read, Write: policy.Write}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copy := snapshot
	copy.AllowedCommands = make([][]string, len(snapshot.AllowedCommands))
	for i := range snapshot.AllowedCommands {
		copy.AllowedCommands[i] = append([]string(nil), snapshot.AllowedCommands[i]...)
	}
	copy.SFTP = cloneSFTPPolicy(snapshot.SFTP)
	return copy
}

func (snapshot Snapshot) Digest() (string, error) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func snapshotFor(profile profile, authentication, authenticationDigest, knownHostsDigest string) Snapshot {
	commands := make([][]string, len(profile.AllowedCommands))
	for i := range profile.AllowedCommands {
		commands[i] = append([]string(nil), profile.AllowedCommands[i]...)
	}
	return Snapshot{
		Name: profile.Name, Host: profile.Host, Port: profile.Port, User: profile.User,
		Authentication: authentication, AuthenticationKeysSHA256: authenticationDigest,
		KnownHostsSHA256: knownHostsDigest, AllowedCommands: commands,
		SFTP: cloneSFTPPolicy(profile.SFTP), ExpiresAt: profile.ExpiresAt.UTC(),
	}
}

func readBoundedFile(filePath string, max int64, description string) ([]byte, error) {
	file, err := openSecureRegular(filePath, description)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s", description)
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s exceeds size limit", description)
	}
	return raw, nil
}

func validateKnownHosts(profile profile, raw []byte) (ssh.HostKeyCallback, error) {
	if len(raw) == 0 {
		return nil, errors.New("known_hosts file is empty")
	}
	callback, err := callbackFromKnownHosts(raw)
	if err != nil {
		return nil, errors.New("known_hosts file is invalid")
	}
	seed := make([]byte, ed25519.SeedSize)
	dummy, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		return nil, errors.New("initialize host-key validation")
	}
	hostname := net.JoinHostPort(profile.Host, fmt.Sprintf("%d", profile.Port))
	err = callback(hostname, staticAddr(hostname), dummy)
	if err == nil {
		return callback, nil
	}
	var keyError *knownhosts.KeyError
	if !errors.As(err, &keyError) || len(keyError.Want) == 0 {
		return nil, errors.New("known_hosts has no entry for profile host and port")
	}
	return callback, nil
}

type staticAddr string

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return string(a) }
