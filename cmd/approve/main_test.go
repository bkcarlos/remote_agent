package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/approvalview"
)

const (
	testBeforeHash = "1111111111111111111111111111111111111111111111111111111111111111"
	testAfterHash  = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestRunSignsAndDisplaysEveryNormalizedBatchTarget(t *testing.T) {
	key := strings.Repeat("batch-key-", 4)
	t.Setenv(approvalKeyEnvironment, key)
	t.Setenv(approverEnvironment, "reviewer-batch")
	targetsJSON := `[
			{"path":"dir/../a.txt","before_sha256":"` + testBeforeHash + `","after_sha256":"` + testAfterHash + `"},
			{"path":"nested/b.txt","after_sha256":"3333333333333333333333333333333333333333333333333333333333333333"}
		]`
	wantTargets := []approval.Target{
		{Path: "a.txt", BeforeSHA256: testBeforeHash, AfterSHA256: testAfterHash},
		{Path: "nested/b.txt", AfterSHA256: strings.Repeat("3", 64)},
	}
	reviewJSON, reviewSHA256 := testReview(t, "approval-batch", "session-1", "multi_edit", wantTargets)
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--approval-id", "approval-batch",
		"--session", "session-1",
		"--operation", "multi_edit",
		"--targets-json", targetsJSON,
		"--review-json", reviewJSON,
		"--approve",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr: %s", err, stderr.String())
	}

	token := strings.TrimSpace(stdout.String())
	if token == "" || strings.Contains(token, "\n") {
		t.Fatalf("stdout must contain only one token, got %q", stdout.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatal("approval token leaked to stderr")
	}
	for _, want := range []string{
		"approver=reviewer-batch",
		"operation=multi_edit",
		"Target 1: path=a.txt before_sha256=" + testBeforeHash + " after_sha256=" + testAfterHash,
		"Target 2: path=nested/b.txt before_sha256=(none) after_sha256=3333333333333333333333333333333333333333333333333333333333333333",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr.String())
		}
	}

	manager, err := approval.New([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := manager.Verify(token, approval.Scope{
		SessionID:    "session-1",
		Operation:    "multi_edit",
		Targets:      wantTargets,
		ReviewSHA256: reviewSHA256,
	})
	if err != nil {
		t.Fatalf("verify batch token: %v", err)
	}
	if claims.ApprovalID != "approval-batch" || claims.Approver != "reviewer-batch" || len(claims.Targets) != len(wantTargets) {
		t.Fatalf("unexpected verified claims: %+v", claims)
	}
	for i := range wantTargets {
		if claims.Targets[i] != wantTargets[i] {
			t.Errorf("target %d = %+v, want %+v", i, claims.Targets[i], wantTargets[i])
		}
	}
}

func TestRunRejectsTargetsJSONMixedWithLegacyTargetFlags(t *testing.T) {
	t.Setenv(approverEnvironment, "reviewer-mixed")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--approval-id", "approval-1",
		"--session", "session-1",
		"--targets-json", `[{"path":"a.txt","after_sha256":"` + testAfterHash + `"}]`,
		"--path", "",
		"--approve",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("run error = %v, want mutual-exclusion error", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty on rejection, got %q", stdout.String())
	}
}

func TestRunRequiresExplicitApproval(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--approval-id", "approval-1",
		"--session", "session-1",
		"--path", "a.txt",
		"--content-sha256", testAfterHash,
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "pass --approve") {
		t.Fatalf("run error = %v, want confirmation error", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty without confirmation, got %q", stdout.String())
	}
}

func TestRunRequiresApprover(t *testing.T) {
	t.Setenv(approvalKeyEnvironment, strings.Repeat("approver-key-", 3))
	t.Setenv(approverEnvironment, "")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--approval-id", "approval-1",
		"--session", "session-1",
		"--path", "a.txt",
		"--content-sha256", testAfterHash,
		"--approve",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--approver is required") {
		t.Fatalf("run error = %v, want approver requirement", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty without approver, got %q", stdout.String())
	}
}

func TestRunKeepsLegacySingleWriteCompatible(t *testing.T) {
	key := strings.Repeat("legacy-key-", 4)
	t.Setenv(approvalKeyEnvironment, key)
	t.Setenv(approverEnvironment, "reviewer-write")
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--approval-id", "approval-write",
		"--session", "session-write",
		"--path", "dir/../file.txt",
		"--content-sha256", testAfterHash,
		"--expected-hash", testBeforeHash,
		"--legacy-without-review",
		"--approve",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run legacy command: %v", err)
	}

	manager, err := approval.New([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := manager.Verify(strings.TrimSpace(stdout.String()), approval.Scope{
		SessionID:     "session-write",
		Operation:     "write_file",
		Path:          "file.txt",
		ContentSHA256: testAfterHash,
		ExpectedHash:  testBeforeHash,
	})
	if err != nil {
		t.Fatalf("verify legacy write token: %v", err)
	}
	if claims.Path != "file.txt" || claims.Operation != "write_file" || claims.Approver != "reviewer-write" {
		t.Fatalf("unexpected legacy claims: %+v", claims)
	}
	if !strings.Contains(stderr.String(), "WARNING") || !strings.Contains(stderr.String(), "\x1b[1;31m") {
		t.Fatalf("legacy warning was not highlighted: %q", stderr.String())
	}
}

func TestRunDoesNotRestrictFutureOperations(t *testing.T) {
	key := strings.Repeat("future-key-", 4)
	t.Setenv(approvalKeyEnvironment, key)
	t.Setenv(approverEnvironment, "reviewer-future")
	reviewJSON, reviewSHA256 := testReview(t, "approval-future", "session-future", "future_write_operation", []approval.Target{{Path: "file.txt", AfterSHA256: testAfterHash}})
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--approval-id", "approval-future",
		"--session", "session-future",
		"--operation", "future_write_operation",
		"--path", "file.txt",
		"--content-sha256", testAfterHash,
		"--review-json", reviewJSON,
		"--approve",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run future operation: %v", err)
	}
	manager, err := approval.New([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(strings.TrimSpace(stdout.String()), approval.Scope{
		SessionID:    "session-future",
		Operation:    "future_write_operation",
		Targets:      []approval.Target{{Path: "file.txt", AfterSHA256: testAfterHash}},
		ReviewSHA256: reviewSHA256,
	}); err != nil {
		t.Fatalf("verify future operation token: %v", err)
	}
}

func TestRunRequiresReviewUnlessExplicitLegacyWrite(t *testing.T) {
	t.Setenv(approvalKeyEnvironment, strings.Repeat("review-key-", 4))
	t.Setenv(approverEnvironment, "reviewer")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--approval-id", "approval-review-required",
		"--session", "session-review-required",
		"--path", "file.txt",
		"--content-sha256", testAfterHash,
		"--approve",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--review-json") {
		t.Fatalf("missing review error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("missing review produced a token: %q", stdout.String())
	}
}

func TestRunReviewFileAndExactBinding(t *testing.T) {
	t.Setenv(approvalKeyEnvironment, strings.Repeat("review-file-key-", 3))
	t.Setenv(approverEnvironment, "reviewer-file")
	reviewJSON, reviewSHA256 := testReview(t, "approval-file", "session-file", "write_file", []approval.Target{{Path: "file.txt", BeforeSHA256: testBeforeHash, AfterSHA256: testAfterHash}})
	path := t.TempDir() + "/review.json"
	if err := os.WriteFile(path, []byte(reviewJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--approval-id", "approval-file",
		"--session", "session-file",
		"--path", "file.txt",
		"--content-sha256", testAfterHash,
		"--expected-hash", testBeforeHash,
		"--review-file", path,
		"--approve",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("review file run: %v", err)
	}
	for _, value := range []string{"risk=L2", "operation=write_file", "path=file.txt", "Diff 1:", reviewSHA256} {
		if !strings.Contains(stderr.String(), value) {
			t.Errorf("stderr missing %q: %s", value, stderr.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	err := run([]string{
		"--approval-id", "approval-file",
		"--session", "different-session",
		"--path", "file.txt",
		"--content-sha256", testAfterHash,
		"--expected-hash", testBeforeHash,
		"--review-file", path,
		"--approve",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("review/session mismatch error = %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	duplicate := strings.Replace(reviewJSON, `"schema":`, `"schema":"approval-review/v1","schema":`, 1)
	err = run([]string{
		"--approval-id", "approval-file",
		"--session", "session-file",
		"--path", "file.txt",
		"--content-sha256", testAfterHash,
		"--expected-hash", testBeforeHash,
		"--review-json", duplicate,
		"--approve",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "duplicate") || stdout.Len() != 0 {
		t.Fatalf("duplicate review result: error=%v stdout=%q", err, stdout.String())
	}
}

func TestRunNeverPrintsApprovalKey(t *testing.T) {
	secret := "DO-NOT-PRINT-this-approval-key-1234567890"
	t.Setenv(approvalKeyEnvironment, secret)
	t.Setenv(approverEnvironment, "reviewer-secret")
	reviewJSON, _ := testReview(t, "approval-secret", "session-secret", "edit", []approval.Target{{Path: "file.txt", AfterSHA256: testAfterHash}})
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--approval-id", "approval-secret",
		"--session", "session-secret",
		"--operation", "edit",
		"--path", "file.txt",
		"--content-sha256", testAfterHash,
		"--review-json", reviewJSON,
		"--approve",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatal("approval key leaked in successful command output")
	}

	stdout.Reset()
	stderr.Reset()
	err := run([]string{
		"--approval-id", "approval-secret-error",
		"--session", "session-secret",
		"--path", "file.txt",
		"--content-sha256", "invalid",
		"--approve",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run with invalid hash unexpectedly succeeded")
	}
	if strings.Contains(stdout.String()+stderr.String()+err.Error(), secret) {
		t.Fatal("approval key leaked in command failure")
	}
}

func testReview(t *testing.T, approvalID, session, operation string, targets []approval.Target) (string, string) {
	t.Helper()
	claims := approval.Claims{
		ApprovalID: approvalID, ChallengeID: approvalID, SessionID: session, Operation: operation,
		Targets: targets, ExpiresAt: time.Now().UTC().Add(4 * time.Minute),
	}
	files := make([]approvalview.DryRunFile, len(targets))
	for i, target := range targets {
		files[i] = approvalview.DryRunFile{
			Path: target.Path, BeforeSHA256: target.BeforeSHA256, AfterSHA256: target.AfterSHA256,
			Diff: "--- a/" + target.Path + "\n+++ b/" + target.Path + "\n", Encoding: "utf-8", Newline: "lf", Bytes: int64(i + 1),
		}
	}
	view, err := approvalview.New(claims, approvalview.DryRun{Risk: approvalview.RiskL2, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := view.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := view.ReviewDigest()
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical), digest
}
