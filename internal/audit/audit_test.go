package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordJSONL(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	if e := l.Record(Event{RequestID: "r\ninjected", Status: "ok"}); e != nil {
		t.Fatal(e)
	}
	if strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("event was not one JSON line: %q", b.String())
	}
	var e Event
	if json.Unmarshal(b.Bytes(), &e) != nil || e.Time.IsZero() || e.RequestID != "r\ninjected" {
		t.Fatalf("bad event: %+v", e)
	}
	if e.StartedAt.IsZero() || e.EndedAt.IsZero() || e.Stage != "completed" {
		t.Fatalf("standalone terminal timing not populated: %+v", e)
	}
}

func TestEventCoversFR014Fields(t *testing.T) {
	summary, err := SummarizeParameters(map[string]any{"path": "src/main.go"})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	end := start.Add(1250 * time.Millisecond)
	event := Event{
		Time: start, UserID: "user-1", ClientID: "client-1", SessionID: "session-1",
		AuthPrincipal: "spiffe://agent/client-1", Transport: "https", BridgeInstanceID: "bridge-1",
		RemoteIP: "192.0.2.10", RequestID: "request-1", ClientRequestID: "client-request-1", TokenID: "token-id-1", Tool: "write_file",
		ParameterSummary: &summary, WorkspaceID: "workspace-1", WorkspacePath: "/workspace", Path: "src/main.go",
		PolicyID: "write-policy", PolicyVersion: "v7", PolicyDecision: "allow", Allowed: true,
		ApprovalRequired: true, ApprovalMode: "server_token", ApprovalVerified: true, ApprovalSource: "server_token",
		ApprovalID: "approval-1", Approver: "reviewer-1", WorkerID: "worker-1",
		Stage: "completed", StartedAt: start, EndedAt: end, InputBytes: 10, OutputBytes: 20,
		BeforeHash: strings.Repeat("a", 64), AfterHash: strings.Repeat("b", 64), Status: "success",
		SecurityDegraded: true, SecurityDegradationReason: "landlock unavailable",
		SecurityDegradationFields: []string{"landlock"},
	}
	var output bytes.Buffer
	if err := New(&output).Record(event); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"time", "user_id", "client_id", "session_id", "auth_principal", "transport",
		"bridge_instance_id", "remote_ip", "request_id", "client_request_id", "token_id", "tool", "parameter_summary",
		"workspace_id", "workspace_path", "path", "policy_version", "policy_decision", "allowed",
		"approval_required", "approved", "approval_mode", "approval_verified", "approval_source", "approval_id", "approver", "worker_id", "stage", "started_at", "ended_at",
		"duration_ms", "input_bytes", "output_bytes", "before_hash", "after_hash", "status",
		"security_degraded", "security_degradation_reason", "security_degradation_fields",
	} {
		if _, ok := got[field]; !ok {
			t.Errorf("missing FR-014 field %q in %s", field, output.String())
		}
	}
	if got["duration_ms"] != float64(1250) {
		t.Fatalf("duration_ms = %v, want 1250", got["duration_ms"])
	}
}

func TestSummarizeParametersRedactsSecretsAndNormalizes(t *testing.T) {
	privateKey := "-----BEGIN PRIVATE KEY-----\nvery-secret-key\n-----END PRIVATE KEY-----"
	parameters := map[string]any{
		"path":          "src/main.go",
		"content":       "new file contents",
		"Authorization": "Bearer authorization-secret",
		"headers": map[string]any{
			"Cookie":   "session=cookie-secret",
			"password": "password-secret",
			"token_id": "safe-token-id",
		},
		"private_key": privateKey,
	}
	summary, err := SummarizeParameters(parameters)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"authorization-secret", "cookie-secret", "password-secret", "very-secret-key", "new file contents"} {
		if strings.Contains(summary.Normalized, secret) {
			t.Errorf("normalized parameters leaked %q: %s", secret, summary.Normalized)
		}
	}
	if !strings.Contains(summary.Normalized, "safe-token-id") || !strings.Contains(summary.Normalized, "src/main.go") {
		t.Fatalf("safe identifiers were removed: %s", summary.Normalized)
	}
	if !strings.Contains(summary.Normalized, DigestString("new file contents")) {
		t.Fatalf("content digest missing: %s", summary.Normalized)
	}
	if strings.Contains(summary.Normalized, DigestString(privateKey)) {
		t.Fatalf("private key was digested instead of fully redacted: %s", summary.Normalized)
	}
	if summary.SHA256 != DigestString(summary.Normalized) {
		t.Fatalf("summary digest does not cover normalized parameters")
	}
	wantFields := []string{"Authorization", "headers.Cookie", "headers.password", "private_key"}
	if fmt.Sprint(summary.RedactedFields) != fmt.Sprint(wantFields) {
		t.Fatalf("redacted fields = %v, want %v", summary.RedactedFields, wantFields)
	}

	second, err := SummarizeParameters(json.RawMessage(`{"private_key":"ignored","content":"new file contents","headers":{"token_id":"safe-token-id","password":"ignored","Cookie":"ignored"},"Authorization":"ignored","path":"src/main.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	if second.Normalized != summary.Normalized {
		t.Fatalf("normalization depends on map order or secret values:\n%s\n%s", summary.Normalized, second.Normalized)
	}
}

func TestRedactSensitiveValue(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{"authorization", "Authorization: Bearer top-secret"},
		{"cookie", "Cookie=session-secret"},
		{"password", "password='password-secret'"},
		{"token", "access_token=token-secret"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nkey-secret\n-----END RSA PRIVATE KEY-----"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := RedactSensitiveValue(test.value)
			if strings.Contains(got, "secret") || strings.Contains(got, "PRIVATE KEY-----") {
				t.Fatalf("sensitive value was not redacted: %q", got)
			}
		})
	}
	if IsSensitiveKey("token_id") || !IsSensitiveKey("approval-token") || !IsSensitiveKey("client_password") {
		t.Fatal("sensitive-key classification is incorrect")
	}
}

func TestRecordResanitizesSummaryAndDoesNotMutateInput(t *testing.T) {
	degradations := []string{"Authorization=Bearer event-secret"}
	forged := &ParameterSummary{Normalized: `{"password":"summary-secret"}`, Bytes: 99}
	var output bytes.Buffer
	if err := New(&output).Record(Event{
		RequestID: "request", Status: "success", ParameterSummary: forged,
		SecurityDegradationFields: degradations,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "summary-secret") || strings.Contains(output.String(), "event-secret") {
		t.Fatalf("record leaked a caller-supplied secret: %s", output.String())
	}
	if degradations[0] != "Authorization=Bearer event-secret" {
		t.Fatalf("Record mutated caller-owned slice: %q", degradations[0])
	}
}

func TestRecordCorrelatesStartedEventByRequestID(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output)
	if err := logger.Record(Event{RequestID: "request-1", Status: "started"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := logger.Record(Event{RequestID: "request-1", Status: "success"}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	var started, completed Event
	if err := json.Unmarshal(lines[0], &started); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &completed); err != nil {
		t.Fatal(err)
	}
	if !completed.StartedAt.Equal(started.StartedAt) || completed.DurationMS < 1 {
		t.Fatalf("terminal event was not correlated with start: start=%+v completed=%+v", started, completed)
	}
}

func TestConcurrentRecordProducesValidJSONL(t *testing.T) {
	const records = 200
	var output bytes.Buffer
	logger := New(&output)
	var wg sync.WaitGroup
	errorsCh := make(chan error, records)
	for i := 0; i < records; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errorsCh <- logger.Record(Event{RequestID: fmt.Sprintf("request-%d\n", i), Status: "success"})
		}(i)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != records {
		t.Fatalf("got %d JSONL records, want %d", len(lines), records)
	}
	for i, line := range lines {
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("line %d is invalid JSON: %v: %q", i, err, line)
		}
	}
}

type durableBuffer struct {
	bytes.Buffer
	syncs int
}

func (b *durableBuffer) Sync() error {
	b.syncs++
	return nil
}

func TestPrewriteTransaction(t *testing.T) {
	var output durableBuffer
	logger := New(&output)
	tx, err := logger.Prewrite(Event{
		RequestID: "request-1", Tool: "write_file", PolicyID: "policy-1", Allowed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := tx.Complete("success", func(event *Event) {
		event.WorkerID = "worker-1"
		event.AfterHash = strings.Repeat("a", 64)
		event.OutputBytes = 12
	}); err != nil {
		t.Fatal(err)
	}
	if output.syncs != 2 {
		t.Fatalf("Sync called %d times, want 2", output.syncs)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("got %d transaction records, want 2", len(lines))
	}
	var started, completed Event
	if err := json.Unmarshal(lines[0], &started); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &completed); err != nil {
		t.Fatal(err)
	}
	if started.Status != "started" || started.Stage != "started" || !started.EndedAt.IsZero() {
		t.Fatalf("bad prewrite event: %+v", started)
	}
	if completed.Status != "success" || completed.Stage != "completed" || completed.RequestID != started.RequestID || !completed.Allowed {
		t.Fatalf("bad completed event: %+v", completed)
	}
	if completed.EndedAt.Before(completed.StartedAt) || completed.DurationMS < 1 || completed.WorkerID != "worker-1" {
		t.Fatalf("bad transaction timing/result: %+v", completed)
	}
	if err := tx.Finish(Event{Status: "error"}); !errors.Is(err, ErrTransactionFinished) {
		t.Fatalf("second finish error = %v, want ErrTransactionFinished", err)
	}
}

type partialFailWriter struct {
	calls int
}

func (w *partialFailWriter) Write(p []byte) (int, error) {
	w.calls++
	return min(5, len(p)), errors.New("storage failure")
}

func TestWriteFailurePoisonsLoggerAndPrewriteFailsClosed(t *testing.T) {
	writer := &partialFailWriter{}
	logger := New(writer)
	if tx, err := logger.Prewrite(Event{Status: "started"}); tx != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prewrite = (%v, %v), want nil ErrUnavailable", tx, err)
	}
	if err := logger.Record(Event{Status: "success"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Record error = %v, want ErrUnavailable", err)
	}
	if writer.calls != 1 {
		t.Fatalf("poisoned logger wrote %d times, want 1", writer.calls)
	}
}
