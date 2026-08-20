package workspace

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func setup(t *testing.T) (*FS, string) {
	t.Helper()
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, "a.txt"), []byte("hello"), 0640); e != nil {
		t.Fatal(e)
	}
	f, e := New(d)
	if e != nil {
		t.Fatal(e)
	}
	return f, d
}
func TestReadListChecksumWrite(t *testing.T) {
	f, d := setup(t)
	b, e := f.ReadFile("a.txt", 10)
	if e != nil || string(b) != "hello" {
		t.Fatalf("read %q %v", b, e)
	}
	if _, e = f.ReadFile("a.txt", 4); e == nil {
		t.Fatal("size limit not enforced")
	}
	names, e := f.List(".", 10)
	if e != nil || len(names) != 1 || names[0] != "a.txt" {
		t.Fatalf("list %v %v", names, e)
	}
	sum, e := f.Checksum("a.txt")
	if e != nil || len(sum) != 64 {
		t.Fatalf("checksum %q %v", sum, e)
	}
	if _, e = f.WriteFile("a.txt", []byte("new"), "wrong", 10); e == nil {
		t.Fatal("hash mismatch accepted")
	}
	newsum, e := f.WriteFile("a.txt", []byte("new"), sum, 10)
	if e != nil || len(newsum) != 64 {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(d, "a.txt"))
	if string(got) != "new" {
		t.Fatal("write failed")
	}
	st, _ := os.Stat(filepath.Join(d, "a.txt"))
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0640 {
		t.Fatalf("mode changed: %o", st.Mode().Perm())
	}
}
func TestInfoGlobAndGrep(t *testing.T) {
	f, d := setup(t)
	os.MkdirAll(filepath.Join(d, "src"), 0755)
	os.WriteFile(filepath.Join(d, "src", "one.go"), []byte("package one\n// needle\n"), 0644)
	os.WriteFile(filepath.Join(d, "src", "two.txt"), []byte("needle twice needle\n"), 0644)
	info, err := f.Info("src/one.go")
	if err != nil || info.IsDir || info.Size == 0 {
		t.Fatalf("info %+v: %v", info, err)
	}
	paths, err := f.Glob("src", "*.go", 10, 10)
	if err != nil || len(paths) != 1 || paths[0] != "src/one.go" {
		t.Fatalf("glob %v: %v", paths, err)
	}
	matches, err := f.Grep("src", "needle", 10, 10, 1024)
	if err != nil || len(matches) != 2 || matches[0].Line != 2 {
		t.Fatalf("grep %+v: %v", matches, err)
	}
	if _, err := f.Glob(".", "../*", 10, 10); err == nil {
		t.Fatal("unsafe glob accepted")
	}
	if _, err := f.Grep(".", "needle", 1, 10, 1024); err == nil {
		t.Fatal("file limit ignored")
	}
	os.WriteFile(filepath.Join(d, ".env"), []byte("TOP_SECRET=needle"), 0600)
	matches, err = f.Grep(".", "TOP_SECRET", 20, 20, 4096)
	if err != nil || len(matches) != 0 {
		t.Fatalf("default-sensitive file was searched: %+v %v", matches, err)
	}
	custom, err := NewWithDenied(d, []string{"two.txt"})
	if err != nil {
		t.Fatal(err)
	}
	matches, err = custom.Grep(".", "twice", 20, 20, 4096)
	if err != nil || len(matches) != 0 {
		t.Fatalf("custom-sensitive file was searched: %+v %v", matches, err)
	}
}

func TestRejectTraversalAbsoluteAndSymlink(t *testing.T) {
	f, d := setup(t)
	for _, p := range []string{"../secret", filepath.Join(string(filepath.Separator), "tmp", "x"), "", "x\x00y"} {
		if _, e := f.ReadFile(p, 100); e == nil {
			t.Errorf("accepted unsafe path %q", p)
		}
	}
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("secret"), 0600)
	if e := os.Symlink(outside, filepath.Join(d, "link")); e == nil {
		if _, e = f.ReadFile("link", 100); e == nil {
			t.Fatal("followed symlink")
		}
	}
}
func TestWriteLimitsAndCreate(t *testing.T) {
	f, d := setup(t)
	if _, e := f.WriteFile("new.txt", []byte(strings.Repeat("x", 11)), "", 10); e == nil {
		t.Fatal("write limit ignored")
	}
	if _, e := f.WriteFile("new.txt", []byte("ok"), "", 10); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "new.txt")); string(b) != "ok" {
		t.Fatal("create failed")
	}
}
