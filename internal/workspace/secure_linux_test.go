//go:build linux

package workspace

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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

func TestSecureAtomicWriteFinalHashDetectsSameInodeChangeDuringTempWrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	var mutationErr error
	mutated := false
	hooks := &secureAtomicWriteHooks{afterTempWriteChunk: func(written int) {
		if mutated {
			return
		}
		mutated = true
		mutationErr = os.WriteFile(path, []byte("jello"), 0o640)
	}}
	replacement := bytes.Repeat([]byte("x"), 4*secureAtomicWriteChunkSize)
	err = secureAtomicWriteWithHooks(root, "a.txt", replacement, 0o640, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hooks)
	if mutationErr != nil {
		t.Fatalf("concurrent same-inode mutation failed: %v", mutationErr)
	}
	if !mutated {
		t.Fatal("temp-write hook was not called")
	}
	if err != ErrConflict {
		t.Fatalf("same-inode change error = %v, want ErrConflict", err)
	}
	after, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !os.SameFile(before, after) {
		t.Fatal("test mutation replaced the inode instead of modifying it")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "jello" {
		t.Fatalf("conflicting target = %q, %v; want same-inode mutation", got, readErr)
	}
}

func TestSecureAtomicWriteRejectsExistingTargetWithoutExpectedHash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := secureAtomicWrite(root, "a.txt", []byte("replacement"), 0o640, ""); err != ErrConflict {
		t.Fatalf("empty expected hash error = %v, want ErrConflict", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "original" {
		t.Fatalf("existing target changed: %q, %v", got, err)
	}
	if err := secureAtomicWrite(root, "new.txt", []byte("created"), 0o600, ""); err != nil {
		t.Fatalf("new target failed: %v", err)
	}
}

func TestSecureWalkResistsDirectorySymlinkExchange(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	live := filepath.Join(root, "swap")
	parked := filepath.Join(root, "parked")
	if err := os.Mkdir(live, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "safe.txt"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "outside-secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(live, parked) == nil {
				if os.Symlink(outside, live) == nil {
					runtime.Gosched()
					_ = os.Remove(live)
				}
				_ = os.Rename(parked, live)
			}
			runtime.Gosched()
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	for i := 0; i < 200; i++ {
		var visited []string
		_ = secureWalkFilesWithDepth(root, ".", nil, 20, 5, func(name string) error {
			visited = append(visited, name)
			return nil
		})
		for _, name := range visited {
			if name == "swap/outside-secret.txt" {
				t.Fatalf("walk followed a directory exchanged for a symlink: %v", visited)
			}
		}
	}
}
