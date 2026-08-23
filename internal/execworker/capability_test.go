package execworker

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func testJob() Job {
	return Job{
		CapabilityID: "cap-1", Principal: "principal-a", SessionID: "session-a",
		WorkspaceID: "workspace-a", TaskID: "task-a", Profile: "go-test",
		Operation: OperationProcessStart, Limits: testLimits(), Argv: []string{"./..."},
		Env: map[string]string{"GOFLAGS": "-count=1"},
	}
}

func TestExecCapabilityBindsScopeAndIsSingleUse(t *testing.T) {
	signer, err := NewCapabilitySignerFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCapabilityVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	job := testJob()
	profileDigest, err := testProfile().Digest()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ClaimsForJob(job, profileDigest, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	tampered := claims
	tampered.SessionID = "session-b"
	if _, err := verifier.Verify(token, tampered); err == nil {
		t.Fatal("cross-session capability scope was accepted")
	}
	if _, err := verifier.Verify(token, claims); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}
	if _, err := verifier.Verify(token, claims); err == nil {
		t.Fatal("single-use capability replay was accepted")
	}
}

func TestExecCapabilityBindsEnvironmentValuesByDigest(t *testing.T) {
	left := testJob()
	right := testJob()
	right.Env["GOFLAGS"] = "-run=Injected"
	leftDigest, _ := JobInputDigest(left)
	rightDigest, _ := JobInputDigest(right)
	if leftDigest == rightDigest {
		t.Fatal("environment values were not bound into the capability input digest")
	}
}
