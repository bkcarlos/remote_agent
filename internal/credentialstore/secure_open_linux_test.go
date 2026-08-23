//go:build linux

package credentialstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSecureRegularRejectsSymlinkBroadWritesAndWrongOwnerWithoutPathLeak(t *testing.T) {
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "host-secret-config")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "host-secret-link")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecureRegular(linkPath, "profile configuration"); err == nil || strings.Contains(err.Error(), linkPath) {
		t.Fatalf("symlink error = %v", err)
	}
	if err := os.Chmod(secretPath, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecureRegular(secretPath, "known_hosts"); err == nil || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("group-writable error = %v", err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chmod(secretPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(secretPath, 1, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := openSecureRegular(secretPath, "private key"); err == nil || strings.Contains(err.Error(), secretPath) {
			t.Fatalf("wrong-owner error = %v", err)
		}
	}
}
