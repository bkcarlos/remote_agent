package workspace

import (
	"errors"
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
	if err != nil || len(matches) != 2 {
		t.Fatalf("grep %+v: %v", matches, err)
	}
	lines := map[string]int{}
	for _, match := range matches {
		lines[match.Path] = match.Line
	}
	if lines["src/one.go"] != 2 || lines["src/two.txt"] != 1 {
		t.Fatalf("unexpected grep locations: %+v", matches)
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

func TestWriteRequiresExpectedHashForLargeExistingFile(t *testing.T) {
	root := t.TempDir()
	largePath := filepath.Join(root, "large.bin")
	large, err := os.OpenFile(largePath, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	const largeSize = int64(64<<20) + 1
	if err := large.Truncate(largeSize); err != nil {
		large.Close()
		t.Fatal(err)
	}
	marker := []byte("unchanged")
	if _, err := large.WriteAt(marker, largeSize-int64(len(marker))); err != nil {
		large.Close()
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	fsys, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Checksum("large.bin"); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("large checksum error = %v, want ErrLimitExceeded", err)
	}
	if _, err := fsys.WriteFile("large.bin", []byte("replacement"), "", 32); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty expected hash for existing file error = %v, want ErrConflict", err)
	}
	info, err := os.Stat(largePath)
	if err != nil || info.Size() != largeSize {
		t.Fatalf("large file size changed: size=%d err=%v", info.Size(), err)
	}
	large, err = os.Open(largePath)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(marker))
	_, readErr := large.ReadAt(got, largeSize-int64(len(marker)))
	large.Close()
	if readErr != nil || string(got) != string(marker) {
		t.Fatalf("large file content changed: %q, %v", got, readErr)
	}
	if _, err := fsys.WriteFile("created.bin", []byte("new"), "", 32); err != nil {
		t.Fatalf("new file with empty expected hash failed: %v", err)
	}
}

func TestListFiltersDeniedNamesBeforeEntryLimit(t *testing.T) {
	f, root := setup(t)
	for _, name := range []string{".env", ".ssh", "ADMIN.SECRET"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	custom, err := NewWithDenied(root, []string{"admin.secret"})
	if err != nil {
		t.Fatal(err)
	}
	names, err := custom.List(".", 1)
	if err != nil || len(names) != 1 || names[0] != "a.txt" {
		t.Fatalf("denied names affected listing or its limit: %v, %v", names, err)
	}
	if _, err := f.Info(".env"); !errors.Is(err, ErrDeniedPath) {
		t.Fatalf("direct access to a default denied name was not denied: %v", err)
	}
}

func TestExportedErrorsDoNotExposeHostPaths(t *testing.T) {
	f, root := setup(t)
	_, err := f.ReadFile("missing/secret.txt", 100)
	if err == nil {
		t.Fatal("missing path unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), root) {
		t.Fatalf("error exposed workspace host path: %q", err)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing path has no stable category: %v", err)
	}
	var safe *SafeError
	if !errors.As(err, &safe) || safe.Kind() != ErrNotFound {
		t.Fatalf("error is not a testable SafeError: %#v", err)
	}
}

func TestNormalizePath(t *testing.T) {
	for input, want := range map[string]string{
		".":             ".",
		"src//one.go":   "src/one.go",
		"src/../one.go": "one.go",
		`src\..\one.go`: "one.go",
	} {
		got, err := NormalizePath(input)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "../secret", "/tmp/secret", `C:\secret`, "bad\x00path"} {
		if _, err := NormalizePath(input); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NormalizePath(%q) accepted an unsafe path: %v", input, err)
		}
	}
}

func TestSecureWalkHonorsRootAndNestedGitignore(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", "\n# root rules\n*.log\n!important.log\nignored-dir/\nglob/**/secret?.txt\n/anchored.txt\n!.env\n")
	write(".env", "policy must win")
	write("dropped.log", "hidden")
	write("important.log", "visible")
	write("ignored-dir/file.txt", "hidden")
	write("glob/a/secret1.txt", "hidden")
	write("glob/a/visible.txt", "visible")
	write("anchored.txt", "hidden")
	write("deep/anchored.txt", "visible")
	write("src/.gitignore", "*.tmp\n!keep.tmp\ngenerated/\n")
	write("src/drop.tmp", "hidden")
	write("src/keep.tmp", "visible")
	write("src/generated/code.go", "hidden")
	write("src/ok.go", "visible")
	write("src/root-rule.log", "hidden")

	fsys, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	visited := map[string]bool{}
	if err := fsys.walkFilesWithDepth(".", 100, 10, func(name string) error {
		visited[name] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"important.log", "glob/a/visible.txt", "deep/anchored.txt", "src/keep.tmp", "src/ok.go"} {
		if !visited[name] {
			t.Errorf("expected %q to be visited: %v", name, visited)
		}
	}
	for _, name := range []string{".env", "dropped.log", "ignored-dir/file.txt", "glob/a/secret1.txt", "anchored.txt", "src/drop.tmp", "src/generated/code.go", "src/root-rule.log"} {
		if visited[name] {
			t.Errorf("ignored path %q was visited", name)
		}
	}

	visited = map[string]bool{}
	if err := fsys.walkFilesWithDepth("src", 100, 10, func(name string) error {
		visited[name] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if visited["src/root-rule.log"] {
		t.Fatal("workspace-root .gitignore was not applied to a nested traversal root")
	}
}

func TestGitignoreAndTraversalDepthLimits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(strings.Repeat("#", int(maxGitignoreBytes)+1)), 0644); err != nil {
		t.Fatal(err)
	}
	fsys, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Glob(".", "*", 10, 10); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("oversized .gitignore did not fail safely: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, ".gitignore"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "one", "two"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "one", "two", "deep.txt"), []byte("deep"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.GlobWithDepth(".", "*", 20, 20, 1); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("depth limit was not enforced: %v", err)
	}
	paths, err := fsys.GlobWithDepth(".", "one/two/*.txt", 20, 20, 3)
	if err != nil || len(paths) != 1 || paths[0] != "one/two/deep.txt" {
		t.Fatalf("valid depth traversal failed: %v, %v", paths, err)
	}
}
