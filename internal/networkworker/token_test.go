package networkworker

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCapabilityBindsEverySecurityRelevantFieldAndIsSingleUse(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	signer := testSigner(t, now)
	request := Request{
		TokenID: "token-1", RequestID: "request-1", SessionID: "session-1",
		Operation: OperationUpload, URL: "https://example.com/upload?a=1", Method: "POST",
		Headers: Headers{"content-type": {"application/octet-stream"}}, Body: []byte("payload"),
		PolicyID: "policy-1", ProfileID: "profile-1",
		Policy: Policy{
			AllowedDomains: []string{"example.com"}, AllowedPorts: []uint16{443},
			AllowedSchemes: []string{"https"}, AllowedRequestHeaders: []string{"content-type"},
		},
		Limits: testLimits(),
	}
	job := signedTestJob(t, signer, now, request)
	_, _, scope, err := prepareJob(job)
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*Scope){
		"token":          func(value *Scope) { value.TokenID = "token-2" },
		"request":        func(value *Scope) { value.RequestID = "request-2" },
		"principal":      func(value *Scope) { value.Principal = "principal-2" },
		"workspace":      func(value *Scope) { value.WorkspaceID = "workspace-2" },
		"bridge":         func(value *Scope) { value.BridgeID = "bridge-2" },
		"session":        func(value *Scope) { value.SessionID = "session-2" },
		"client request": func(value *Scope) { value.ClientRequestID = "client-request-2" },
		"operation":      func(value *Scope) { value.Operation = OperationDownload },
		"URL":            func(value *Scope) { value.URL = "https://example.com/other" },
		"method":         func(value *Scope) { value.Method = "PUT" },
		"headers":        func(value *Scope) { value.HeadersSHA256 = strings.Repeat("0", 64) },
		"body":           func(value *Scope) { value.BodySHA256 = strings.Repeat("1", 64) },
		"limits":         func(value *Scope) { value.Limits.MaxRedirects++ },
		"policy ID":      func(value *Scope) { value.PolicyID = "policy-2" },
		"profile":        func(value *Scope) { value.ProfileID = "profile-2" },
		"policy":         func(value *Scope) { value.PolicySHA256 = strings.Repeat("2", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			verifier, err := NewVerifier(signer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			verifier.now = func() time.Time { return now }
			changed := scope
			mutate(&changed)
			if _, err := verifier.Verify(job.Token, changed); err == nil || !strings.Contains(err.Error(), "scope mismatch") {
				t.Fatalf("expected scope mismatch, got %v", err)
			}
		})
	}

	verifier, err := NewVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	if _, err := verifier.Verify(job.Token, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(job.Token, scope); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected single-use rejection, got %v", err)
	}
}

func TestCapabilityRejectsSignatureTampering(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	signer := testSigner(t, now)
	job := signedTestJob(t, signer, now, Request{
		RequestID: "request", SessionID: "session", Operation: OperationWebFetch,
		URL: "https://example.com/", Method: "GET", PolicyID: "policy", ProfileID: "profile",
		Policy: Policy{AllowedDomains: []string{"example.com"}, AllowedPorts: []uint16{443}, AllowedSchemes: []string{"https"}},
		Limits: testLimits(),
	})
	_, _, scope, err := prepareJob(job)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(job.Token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0x80
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	verifier, err := NewVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	if _, err := verifier.Verify(strings.Join(parts, "."), scope); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature rejection, got %v", err)
	}
}

func TestJobHasNoLocalPathField(t *testing.T) {
	jobType := reflect.TypeOf(Job{})
	for index := 0; index < jobType.NumField(); index++ {
		name := strings.Split(jobType.Field(index).Tag.Get("json"), ",")[0]
		if name == "path" || name == "local_path" || name == "workspace" {
			t.Fatalf("Job exposes forbidden local path field %q", name)
		}
	}
}
