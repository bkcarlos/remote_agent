//go:build unix

package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectsHardLinkedFileContent(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "innocent.txt")
	if err := os.Link(outside, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	fs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile("innocent.txt", 100); err == nil {
		t.Fatal("hard-linked outside file was read")
	}
	matches, err := fs.Grep(".", "secret", 10, 10, 100)
	if err != nil || len(matches) != 0 {
		t.Fatalf("hard-linked content entered search: %+v %v", matches, err)
	}
}
