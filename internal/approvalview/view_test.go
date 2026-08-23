package approvalview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
)

const (
	beforeA = "1111111111111111111111111111111111111111111111111111111111111111"
	afterA  = "2222222222222222222222222222222222222222222222222222222222222222"
	beforeB = "3333333333333333333333333333333333333333333333333333333333333333"
	afterB  = "4444444444444444444444444444444444444444444444444444444444444444"
)

func testClaims() approval.Claims {
	return approval.Claims{
		ApprovalID:  "approval-1",
		ChallengeID: "approval-1",
		Approver:    "reviewer-1",
		SessionID:   "session-1",
		Operation:   "multi_edit",
		Targets: []approval.Target{
			{Path: "z-last.txt", BeforeSHA256: beforeB, AfterSHA256: afterB},
			{Path: "a-first.txt", BeforeSHA256: beforeA, AfterSHA256: afterA},
		},
		ExpiresAt: time.Date(2026, 8, 23, 12, 34, 56, 789, time.FixedZone("offset", 2*60*60)),
	}
}

func testDryRun() DryRun {
	return DryRun{
		Risk: RiskL2,
		Files: []DryRunFile{
			{Path: "a-first.txt", BeforeSHA256: beforeA, AfterSHA256: afterA, Diff: "--- a/a-first.txt\n+++ b/a-first.txt\n", Encoding: "utf-8", Newline: "lf", Bytes: 12},
			{Path: "z-last.txt", BeforeSHA256: beforeB, AfterSHA256: afterB, Diff: "--- a/z-last.txt\n+++ b/z-last.txt\n", Encoding: "utf-16le", Newline: "crlf", Bytes: 24},
		},
	}
}

func TestNewOrdersFilesByClaimsAndBindsTargetOrder(t *testing.T) {
	claims := testClaims()
	view, err := New(claims, testDryRun())
	if err != nil {
		t.Fatal(err)
	}
	if view.Persisted {
		t.Fatal("dry-run view reported persisted content")
	}
	if got := []string{view.Targets[0].Path, view.Targets[1].Path}; !reflect.DeepEqual(got, []string{"z-last.txt", "a-first.txt"}) {
		t.Fatalf("target order = %v, want claims order", got)
	}
	if view.Targets[0].Order != 1 || view.Targets[1].Order != 2 {
		t.Fatalf("explicit target order = %d, %d", view.Targets[0].Order, view.Targets[1].Order)
	}

	canonical, err := view.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := view.ReviewDigest()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(canonical)
	if digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("review digest = %q, want SHA-256 of canonical JSON", digest)
	}

	reorderedFiles := testDryRun()
	reorderedFiles.Files[0], reorderedFiles.Files[1] = reorderedFiles.Files[1], reorderedFiles.Files[0]
	sameView, err := New(claims, reorderedFiles)
	if err != nil {
		t.Fatal(err)
	}
	sameCanonical, _ := sameView.CanonicalJSON()
	if !bytes.Equal(canonical, sameCanonical) {
		t.Fatalf("neutral input order changed canonical JSON:\n%s\n%s", canonical, sameCanonical)
	}

	claims.Targets[0], claims.Targets[1] = claims.Targets[1], claims.Targets[0]
	differentView, err := New(claims, testDryRun())
	if err != nil {
		t.Fatal(err)
	}
	differentDigest, _ := differentView.ReviewDigest()
	if differentDigest == digest {
		t.Fatal("claims target order was not bound by the review digest")
	}
}

func TestNewRejectsTruncatedOrOversizedDiff(t *testing.T) {
	claims := testClaims()

	atLimit := testDryRun()
	atLimit.Files[0].Diff = strings.Repeat("x", MaxDiffBytes-len(atLimit.Files[1].Diff))
	if _, err := New(claims, atLimit); err != nil {
		t.Fatalf("exact diff limit rejected: %v", err)
	}

	overLimit := testDryRun()
	overLimit.Files[0].Diff = strings.Repeat("x", MaxDiffBytes-len(overLimit.Files[1].Diff)+1)
	if _, err := New(claims, overLimit); err == nil {
		t.Fatal("oversized aggregate diff accepted")
	}

	truncated := testDryRun()
	truncated.Files[0].DiffTruncated = true
	if _, err := New(claims, truncated); err == nil {
		t.Fatal("truncated diff accepted")
	}
}

func TestNewRejectsInvalidOrMismatchedTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*approval.Claims, *DryRun)
	}{
		{
			name: "unnormalized claims path",
			mutate: func(claims *approval.Claims, dryRun *DryRun) {
				claims.Targets[0].Path = "dir/../z-last.txt"
				dryRun.Files[1].Path = "dir/../z-last.txt"
			},
		},
		{
			name: "unnormalized dry-run path",
			mutate: func(_ *approval.Claims, dryRun *DryRun) {
				dryRun.Files[1].Path = "dir/../z-last.txt"
			},
		},
		{
			name: "invalid claims hash",
			mutate: func(claims *approval.Claims, _ *DryRun) {
				claims.Targets[0].AfterSHA256 = "A" + afterB[1:]
			},
		},
		{
			name: "invalid dry-run hash",
			mutate: func(_ *approval.Claims, dryRun *DryRun) {
				dryRun.Files[0].AfterSHA256 = "not-a-sha256"
			},
		},
		{
			name: "hash mismatch",
			mutate: func(_ *approval.Claims, dryRun *DryRun) {
				dryRun.Files[0].AfterSHA256 = afterB
			},
		},
		{
			name: "path mismatch",
			mutate: func(_ *approval.Claims, dryRun *DryRun) {
				dryRun.Files[0].Path = "other.txt"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := testClaims()
			dryRun := testDryRun()
			test.mutate(&claims, &dryRun)
			if _, err := New(claims, dryRun); err == nil {
				t.Fatal("invalid target input accepted")
			}
		})
	}
}

func TestNewEnforcesTwentyFileLimit(t *testing.T) {
	claims := testClaims()
	dryRun := testDryRun()
	claims.Targets = nil
	dryRun.Files = nil
	for i := 0; i < MaxFiles+1; i++ {
		path := "file-" + string(rune('a'+i)) + ".txt"
		target := approval.Target{Path: path, AfterSHA256: afterA}
		claims.Targets = append(claims.Targets, target)
		dryRun.Files = append(dryRun.Files, DryRunFile{Path: path, AfterSHA256: afterA})
	}
	if _, err := New(claims, dryRun); err == nil {
		t.Fatal("more than twenty files accepted")
	}
}

func TestStrictParseViewRejectsUnknownDuplicateMissingAndTrailingJSON(t *testing.T) {
	view, err := New(testClaims(), testDryRun())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := view.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := StrictParseView(canonical)
	if err != nil {
		t.Fatalf("strict parse rejected canonical view: %v", err)
	}
	if !reflect.DeepEqual(parsed, view) {
		t.Fatalf("strict parse changed view: %+v != %+v", parsed, view)
	}

	valid := string(canonical)
	cases := map[string]string{
		"unknown":          strings.Replace(valid, `"schema":`, `"unknown":true,"schema":`, 1),
		"duplicate":        strings.Replace(valid, `"schema":`, `"schema":"approval-review/v1","schema":`, 1),
		"nested duplicate": strings.Replace(valid, `"order":1`, `"order":1,"order":1`, 1),
		"missing":          strings.Replace(valid, `"approver":"reviewer-1",`, "", 1),
		"trailing":         valid + `{}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := StrictParseView([]byte(input)); err == nil {
				t.Fatal("invalid approval review JSON accepted")
			}
		})
	}
}

func TestViewAndInputExposeNoTokenKeyOrContentFields(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(DryRun{}),
		reflect.TypeOf(DryRunFile{}),
		reflect.TypeOf(View{}),
		reflect.TypeOf(Target{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(name, "token") || strings.Contains(name, "key") || name == "content" {
				t.Fatalf("secret-bearing field %s.%s exists", typ.Name(), typ.Field(i).Name)
			}
		}
	}

	view, err := New(testClaims(), testDryRun())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := view.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"token"`, `"key"`, `"content"`, `"approval_id"`} {
		if bytes.Contains(canonical, []byte(forbidden)) {
			t.Fatalf("canonical review JSON contains forbidden field %s: %s", forbidden, canonical)
		}
	}
	for _, required := range []string{`"risk":"L2"`, `"persisted":false`, `"before_sha256"`, `"after_sha256"`, `"diff"`, `"encoding"`, `"newline"`, `"bytes"`} {
		if !bytes.Contains(canonical, []byte(required)) {
			t.Fatalf("canonical review JSON is missing %s: %s", required, canonical)
		}
	}
}
