package remoteworker

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestArgvPrefixPolicyBeforePOSIXQuoting(t *testing.T) {
	allowed := [][]string{{"git", "status"}, {"printf"}}
	if !CommandAllowed([]string{"git", "status", "--short"}, allowed) {
		t.Fatal("expected exact argv prefix to be allowed")
	}
	if CommandAllowed([]string{"git", "status-and-run"}, allowed) {
		t.Fatal("string prefix must not satisfy argv-element prefix policy")
	}
	if CommandAllowed([]string{"sh", "-c", "git status"}, allowed) {
		t.Fatal("shell string bypass was allowed")
	}
	command, err := QuoteArgv([]string{"printf", "a b", "x'y", "$(touch /tmp/no)", ""})
	if err != nil {
		t.Fatal(err)
	}
	expected := `'printf' 'a b' 'x'"'"'y' '$(touch /tmp/no)' ''`
	if command != expected {
		t.Fatalf("unexpected POSIX quoting\nwant: %s\n got: %s", expected, command)
	}
}

func TestRemotePathPolicy(t *testing.T) {
	roots := []string{"/srv/app", "/var/data"}
	allowed := []string{"/srv/app", "/srv/app/releases/current", "/var/data/a.txt"}
	for _, candidate := range allowed {
		if got, err := NormalizeAndAuthorizeRemotePath(candidate, roots); err != nil || got != candidate {
			t.Errorf("expected %q to be allowed: %v", candidate, err)
		}
	}
	denied := []string{
		"srv/app/file", "/srv/app/../secret", "/srv/app//file", "/srv/application/file",
		"/etc/passwd", "/var/data/../../etc/passwd", "/srv/app/with\x00nul",
	}
	for _, candidate := range denied {
		if _, err := NormalizeAndAuthorizeRemotePath(candidate, roots); err == nil {
			t.Errorf("expected %q to be denied", candidate)
		}
	}
	if err := authorizeResolvedPath("/etc/shadow", []string{"/srv/app"}); err == nil {
		t.Fatal("expected server-side symlink resolution outside root to be denied")
	}
}

func TestSignedJobRejectsTampering(t *testing.T) {
	seed := []byte(strings.Repeat("k", ed25519.SeedSize))
	signer, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	profileDigest := strings.Repeat("a", 64)
	job := Job{
		JobID: "job-1", WorkerType: WorkerType, RequestID: "request-1", Principal: "principal-1",
		WorkspaceID: "workspace-1", BridgeID: "bridge-1", SessionID: "session-1", ClientRequestID: "client-request-1",
		ProfileName: "opaque profile", ProfileSnapshotSHA256: profileDigest,
		Operation: OperationSSHExec, RemotePath: "/", Argv: []string{"git", "status"},
		Limits:    Limits{MaxOutputBytes: 1024, TimeoutMillis: 1000},
		ExpiresAt: time.Now().UTC().Add(30 * time.Second),
	}
	raw, err := signer.Sign(job)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Job){
		"request":        func(job *Job) { job.RequestID = "request-2" },
		"principal":      func(job *Job) { job.Principal = "principal-2" },
		"workspace":      func(job *Job) { job.WorkspaceID = "workspace-2" },
		"bridge":         func(job *Job) { job.BridgeID = "bridge-2" },
		"session":        func(job *Job) { job.SessionID = "session-2" },
		"client request": func(job *Job) { job.ClientRequestID = "client-request-2" },
		"profile":        func(job *Job) { job.ProfileName = "other" },
		"profile digest": func(job *Job) { job.ProfileSnapshotSHA256 = strings.Repeat("b", 64) },
		"operation":      func(job *Job) { job.Operation = OperationSFTPRead },
		"path":           func(job *Job) { job.RemotePath = "/other" },
		"argv":           func(job *Job) { job.Argv[1] = "push" },
		"content":        func(job *Job) { job.Content = []byte("injected") },
		"limits":         func(job *Job) { job.Limits.MaxOutputBytes++ },
		"expiry":         func(job *Job) { job.ExpiresAt = job.ExpiresAt.Add(time.Second) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var candidate SignedJob
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate.Job)
			tampered, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			candidateVerifier, err := NewVerifier(signer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := candidateVerifier.Verify(tampered, profileDigest); err == nil {
				t.Fatal("tampered job retained a valid signature")
			}
		})
	}

	verifier, err = NewVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(raw, strings.Repeat("b", 64)); err == nil {
		t.Fatal("job was not bound to the profile snapshot digest")
	}
}

func TestSignedWriteBindsContentDigest(t *testing.T) {
	seed := []byte(strings.Repeat("w", ed25519.SeedSize))
	signer, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("release payload")
	job := Job{
		JobID: "job-write", WorkerType: WorkerType, RequestID: "request", Principal: "principal",
		WorkspaceID: "workspace", BridgeID: "bridge", SessionID: "session", ClientRequestID: "client-request",
		ProfileName: "prod", ProfileSnapshotSHA256: strings.Repeat("c", 64),
		Operation: OperationSFTPWrite, RemotePath: "/srv/app/release.txt", Argv: []string{},
		Content: content, ContentSHA256: sha256Bytes(content),
		Limits:    Limits{MaxOutputBytes: 1024, MaxFileBytes: 1024, TimeoutMillis: 1000},
		ExpiresAt: time.Now().UTC().Add(30 * time.Second),
	}
	if _, err := signer.Sign(job); err != nil {
		t.Fatal(err)
	}
	job.Content[0] ^= 1
	if _, err := signer.Sign(job); err == nil {
		t.Fatal("content inconsistent with its digest was signed")
	}
}
