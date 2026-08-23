//go:build !windows

package credentialstore

import (
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type profileFixture struct {
	configPath string
	keyPath    string
	hostKey    ssh.PublicKey
}

func newProfileFixture(t *testing.T, keyMode os.FileMode) profileFixture {
	t.Helper()
	directory := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), keyMode); err != nil {
		t.Fatal(err)
	}
	hostPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPath := filepath.Join(directory, "known_hosts")
	line := knownhosts.Line([]string{"example.test"}, hostPublicKey) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	config := config{Version: ConfigVersion, Profiles: []profile{{
		Name: " prod opaque ", Host: "example.test", Port: 22, User: "deploy",
		PrivateKeyPath: keyPath, KnownHostsPath: knownHostsPath,
		AllowedCommands: [][]string{{"git", "status"}},
		SFTP:            SFTPPolicy{Roots: []string{"/srv/app"}, Read: true, Write: false},
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
	}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "profiles.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return profileFixture{configPath: configPath, keyPath: keyPath, hostKey: hostPublicKey}
}

func TestStrictProfileConfiguration(t *testing.T) {
	fixture := newProfileFixture(t, 0o600)
	raw, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	cases := map[string]string{
		"unknown":              strings.Replace(valid, `"host":"example.test"`, `"host":"example.test","unexpected":true`, 1),
		"duplicate":            strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"trailing":             valid + ` {}`,
		"shell command string": strings.Replace(valid, `[["git","status"]]`, `["git status"]`, 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profiles.json")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("expected strict configuration rejection")
			}
		})
	}
}

func TestProfileRejectsDuplicateNamesAndRelativeCredentialPaths(t *testing.T) {
	fixture := newProfileFixture(t, 0o600)
	config, err := loadConfig(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config.Profiles = append(config.Profiles, config.Profiles[0])
	writeConfigForTest(t, fixture.configPath, config)
	if _, err := loadConfig(fixture.configPath); err == nil {
		t.Fatal("expected duplicate opaque profile name rejection")
	}

	fixture = newProfileFixture(t, 0o600)
	config, err = loadConfig(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config.Profiles[0].PrivateKeyPath = "id_ed25519"
	writeConfigForTest(t, fixture.configPath, config)
	if _, err := loadConfig(fixture.configPath); err == nil {
		t.Fatal("expected relative private key path rejection")
	}
}

func TestPrivateKeyPermissionsAreRestricted(t *testing.T) {
	fixture := newProfileFixture(t, 0o644)
	if _, err := Load(fixture.configPath, " prod opaque "); err == nil {
		t.Fatal("expected broad private key permissions to be rejected")
	}
}

func TestCredentialIsOpaqueAndRedactedViewHasNoLocalPaths(t *testing.T) {
	fixture := newProfileFixture(t, 0o600)
	credential, err := Load(fixture.configPath, " prod opaque ")
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Close()
	if _, err := json.Marshal(credential); err == nil {
		t.Fatal("credential unexpectedly serialized")
	}
	view, err := Redacted(fixture.configPath, " prod opaque ")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), fixture.keyPath) || strings.Contains(string(raw), "known_hosts") {
		t.Fatal("redacted view disclosed a local credential path")
	}
}

func TestKnownHostsIsRequiredAndStrict(t *testing.T) {
	fixture := newProfileFixture(t, 0o600)
	credential, err := Load(fixture.configPath, " prod opaque ")
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Close()
	clientConfig, err := credential.SSHClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	host := net.JoinHostPort("example.test", "22")
	if err := clientConfig.HostKeyCallback(host, staticAddr(host), fixture.hostKey); err != nil {
		t.Fatalf("configured host key was rejected: %v", err)
	}
	_, otherPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherHostKey, err := ssh.NewPublicKey(otherPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := clientConfig.HostKeyCallback(host, staticAddr(host), otherHostKey); err == nil {
		t.Fatal("unexpected host key was accepted")
	}

	config, err := loadConfig(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config.Profiles[0].KnownHostsPath = filepath.Join(t.TempDir(), "missing")
	writeConfigForTest(t, fixture.configPath, config)
	if _, err := Load(fixture.configPath, " prod opaque "); err == nil {
		t.Fatal("expected missing known_hosts rejection")
	}
}

func writeConfigForTest(t *testing.T, path string, config *config) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
