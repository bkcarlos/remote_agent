package fileworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/capability"
)

func testService(t *testing.T) (*Service, *capability.Manager, string, []byte) {
	t.Helper()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0644)
	key := []byte(strings.Repeat("k", 32))
	s, err := New(root, key)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := capability.New(key)
	return s, m, root, key
}
func signedJob(t *testing.T, m *capability.Manager, operation, path string) Job {
	t.Helper()
	rid := "request-" + operation
	tok, err := m.Sign(Claims(rid, operation, path, "token-"+operation))
	if err != nil {
		t.Fatal(err)
	}
	return Job{Token: tok, RequestID: rid, Operation: operation, Path: path}
}
func TestServiceOperationsAndReplay(t *testing.T) {
	s, m, root, _ := testService(t)
	read := signedJob(t, m, "read_file", "a.txt")
	read.MaxBytes = 10
	r := s.Execute(read)
	if r.Error != "" || r.Content != "aGVsbG8=" {
		t.Fatalf("read: %+v", r)
	}
	if replay := s.Execute(read); !strings.Contains(replay.Error, "already used") {
		t.Fatalf("replay accepted: %+v", replay)
	}
	list := signedJob(t, m, "list_dir", ".")
	list.MaxEntries = 10
	if r := s.Execute(list); r.Error != "" || len(r.Entries) != 1 {
		t.Fatalf("list: %+v", r)
	}
	checksum := signedJob(t, m, "checksum", "a.txt")
	r = s.Execute(checksum)
	expected := sha256.Sum256([]byte("hello"))
	if r.Checksum != hex.EncodeToString(expected[:]) {
		t.Fatalf("checksum: %+v", r)
	}
	info := signedJob(t, m, "file_info", "a.txt")
	if r := s.Execute(info); r.Error != "" || r.Info == nil || r.Info.Size != 5 {
		t.Fatalf("info: %+v", r)
	}
	glob := signedJob(t, m, "glob", ".")
	glob.Pattern, glob.MaxFiles, glob.MaxResults = "*.txt", 10, 10
	if r := s.Execute(glob); r.Error != "" || len(r.Paths) != 1 {
		t.Fatalf("glob: %+v", r)
	}
	grep := signedJob(t, m, "grep", ".")
	grep.Query, grep.MaxFiles, grep.MaxResults, grep.MaxBytes = "hell", 10, 10, 100
	if r := s.Execute(grep); r.Error != "" || len(r.Matches) != 1 {
		t.Fatalf("grep: %+v", r)
	}
	write := signedJob(t, m, "write_file", "a.txt")
	write.MaxBytes, write.Data, write.ExpectedHash = 10, "bmV3", r.Checksum
	r = s.Execute(write)
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "a.txt")); string(got) != "new" {
		t.Fatalf("write got %q", got)
	}
}
func TestServiceRejectsCapabilityAndLimits(t *testing.T) {
	s, m, _, _ := testService(t)
	j := signedJob(t, m, "read_file", "a.txt")
	j.Path = "other.txt"
	if r := s.Execute(j); !strings.Contains(r.Error, "scope mismatch") {
		t.Fatalf("scope accepted: %+v", r)
	}
	j = signedJob(t, m, "read_file", "a.txt")
	if r := s.Execute(j); r.Error != "invalid read limit" {
		t.Fatalf("limit accepted: %+v", r)
	}
	if r := s.Execute(Job{}); r.Error == "" {
		t.Fatal("empty job accepted")
	}
}
func TestServeStrictJSON(t *testing.T) {
	s, m, _, _ := testService(t)
	j := signedJob(t, m, "checksum", "a.txt")
	b, _ := json.Marshal(j)
	var out bytes.Buffer
	if err := s.Serve(bytes.NewReader(b), &out); err != nil {
		t.Fatal(err)
	}
	var r Response
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Checksum == "" {
		t.Fatalf("bad response %q", out.String())
	}
	if err := s.Serve(strings.NewReader(`{"unknown":1}`), &out); err == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestBoundedBuffer(t *testing.T) {
	buffer := newBoundedBuffer(4)
	if n, err := buffer.Write([]byte("abcdef")); err == nil || n != 6 || !buffer.exceeded || buffer.String() != "abcd" {
		t.Fatalf("buffer did not enforce limit: n=%d err=%v exceeded=%v content=%q", n, err, buffer.exceeded, buffer.String())
	}
}

func TestProcessExecutorEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds worker executable")
	}
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	binary := filepath.Join(t.TempDir(), "file-worker")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/file-worker")
	cmd.Dir = repo
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build worker: %v: %s", err, output)
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0644)
	e, err := NewProcessExecutor(binary, root, []byte(strings.Repeat("z", 32)), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.ReadFile("a.txt", 10)
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q: %v", b, err)
	}
	sum, err := e.Checksum("a.txt")
	if err != nil || len(sum) != 64 {
		t.Fatalf("checksum %q: %v", sum, err)
	}
	if _, err := e.WriteFile("a.txt", []byte("changed"), sum, 20); err != nil {
		t.Fatal(err)
	}
	entries, err := e.List(".", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list %v: %v", entries, err)
	}
	info, err := e.Info("a.txt")
	if err != nil || info.Size != 7 {
		t.Fatalf("info %+v: %v", info, err)
	}
	paths, err := e.Glob(".", "*.txt", 10, 10)
	if err != nil || len(paths) != 1 {
		t.Fatalf("glob %v: %v", paths, err)
	}
	matches, err := e.Grep(".", "change", 10, 10, 100)
	if err != nil || len(matches) != 1 {
		t.Fatalf("grep %+v: %v", matches, err)
	}
}
