//go:build linux

package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenat2RejectsSymlinkWithoutPrecheck(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if f, err := secureOpen(root, "escape/secret", false); err == nil {
		f.Close()
		t.Fatal("openat2 followed a symlink outside the workspace")
	}
}

func TestSecureWalkDoesNotFollowLinksOrDeniedDirectories(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(root, "visible.txt"), []byte("ok"), 0600)
	os.Mkdir(filepath.Join(root, ".secret"), 0700)
	os.WriteFile(filepath.Join(root, ".secret", "hidden.txt"), []byte("hidden"), 0600)
	os.WriteFile(filepath.Join(outside, "outside.txt"), []byte("outside"), 0600)
	os.Symlink(outside, filepath.Join(root, "escape"))
	var visited []string
	err := secureWalkFiles(root, ".", map[string]bool{".secret": true}, 10, func(path string) error {
		visited = append(visited, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != 1 || visited[0] != "visible.txt" {
		t.Fatalf("unsafe traversal results: %v", visited)
	}
}

func TestSecureAtomicWriteRechecksExpectedHash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	os.WriteFile(path, []byte("changed concurrently"), 0644)
	if err := secureAtomicWrite(root, "a.txt", []byte("new"), 0644, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"); err == nil {
		t.Fatal("stale expected hash was accepted")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "changed concurrently" {
		t.Fatal("failed write changed destination")
	}
}
