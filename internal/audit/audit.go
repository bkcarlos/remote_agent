package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const RedactedValue = "[REDACTED]"

var (
	ErrUnavailable         = errors.New("audit log unavailable")
	ErrTransactionFinished = errors.New("audit transaction already finished")

	authorizationValueRE = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[^\s,;]+`)
	secretAssignmentRE   = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|[a-z0-9_-]*token|api[_-]?key|client[_-]?secret|private[_-]?key)\b\s*[:=][^\r\n]*`)
	urlPasswordRE        = regexp.MustCompile(`://([^:/@\s]+):([^@\s]+)@`)
)

// ParameterSummary is a deterministic, safe-to-log representation of tool
// parameters. SHA256 covers Normalized after sensitive and content values have
// been replaced; it is never a digest of a secret value.
type ParameterSummary struct {
	Normalized     string   `json:"normalized"`
	SHA256         string   `json:"sha256"`
	Bytes          int64    `json:"bytes"`
	RedactedFields []string `json:"redacted_fields,omitempty"`
}

// Event is the structured audit envelope. The original fields remain for
// compatibility; the additional fields cover the identities, policy,
// approval, worker, timing, integrity, and degradation data required by
// FR-014.
type Event struct {
	Time time.Time `json:"time"`

	UserID           string `json:"user_id,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	SessionID        string `json:"session_id"`
	AuthPrincipal    string `json:"auth_principal,omitempty"`
	Transport        string `json:"transport"`
	BridgeInstanceID string `json:"bridge_instance_id,omitempty"`
	RemoteIP         string `json:"remote_ip,omitempty"`

	RequestID        string            `json:"request_id"`
	ClientRequestID  string            `json:"client_request_id,omitempty"`
	TokenID          string            `json:"token_id,omitempty"`
	Tool             string            `json:"tool"`
	ParameterSummary *ParameterSummary `json:"parameter_summary,omitempty"`

	WorkspaceID   string `json:"workspace_id,omitempty"`
	WorkspacePath string `json:"workspace_path,omitempty"`
	Path          string `json:"path,omitempty"`
	NetworkTarget string `json:"network_target,omitempty"`

	PolicyID       string `json:"policy_id"`
	PolicyVersion  string `json:"policy_version,omitempty"`
	PolicyDecision string `json:"policy_decision,omitempty"`
	Allowed        bool   `json:"allowed"`

	ApprovalRequired bool   `json:"approval_required"`
	Approved         bool   `json:"approved"`
	ApprovalMode     string `json:"approval_mode,omitempty"`
	ApprovalVerified bool   `json:"approval_verified"`
	ApprovalSource   string `json:"approval_source,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	Approver         string `json:"approver,omitempty"`

	WorkerID string `json:"worker_id,omitempty"`
	Stage    string `json:"stage,omitempty"`

	StartedAt  time.Time `json:"started_at,omitzero"`
	EndedAt    time.Time `json:"ended_at,omitzero"`
	DurationMS int64     `json:"duration_ms"`

	InputBytes  int64  `json:"input_bytes"`
	OutputBytes int64  `json:"output_bytes"`
	BeforeHash  string `json:"before_hash,omitempty"`
	AfterHash   string `json:"after_hash,omitempty"`

	Status                    string   `json:"status"`
	SecurityDegraded          bool     `json:"security_degraded"`
	SecurityDegradationReason string   `json:"security_degradation_reason,omitempty"`
	SecurityDegradationFields []string `json:"security_degradation_fields,omitempty"`
}

type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	failed  error
	pending map[string]time.Time
}

// Transaction represents an operation whose start record was successfully
// written before execution. It can be finished exactly once.
type Transaction struct {
	mu       sync.Mutex
	logger   *Logger
	start    Event
	finished bool
}

func New(w io.Writer) *Logger { return &Logger{w: w} }

// Record appends exactly one JSON object and one newline. Calls are serialized,
// and a failed/partial write permanently fails the logger so a corrupt JSONL
// tail cannot be silently extended.
func (l *Logger) Record(e Event) error {
	return l.record(e, false)
}

// Prewrite durably records an operation start before returning. Writers that
// implement Flush or Sync are flushed/synced while the logger lock is held.
// Callers performing L2+ operations should not execute when this returns an
// error.
func (l *Logger) Prewrite(e Event) (*Transaction, error) {
	e = prepareStart(e)
	if err := l.record(e, true); err != nil {
		return nil, err
	}
	return &Transaction{logger: l, start: e}, nil
}

// Begin is an alias for Prewrite.
func (l *Logger) Begin(e Event) (*Transaction, error) { return l.Prewrite(e) }

// Finish writes the terminal event. Missing correlation fields are inherited
// from the prewrite event, and terminal timing is populated automatically.
func (t *Transaction) Finish(result Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.finished {
		return ErrTransactionFinished
	}
	t.finished = true
	final := mergeEvents(t.start, result)
	// Time identifies this terminal audit record, not the prewrite record.
	final.Time = result.Time
	final.EndedAt = result.EndedAt
	prepareFinish(&final)
	return t.logger.record(final, true)
}

// Complete is a convenience wrapper around Finish. update may add result
// sizes, hashes, worker identity, or degradation details before the terminal
// event is written.
func (t *Transaction) Complete(status string, update func(*Event)) error {
	result := t.start
	result.Time = time.Time{}
	result.EndedAt = time.Time{}
	result.DurationMS = 0
	result.Status = status
	result.Stage = "completed"
	if update != nil {
		update(&result)
	}
	return t.Finish(result)
}

func (l *Logger) record(e Event, durable bool) error {
	startedAtProvided := !e.StartedAt.IsZero()
	prepareEvent(&e)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, l.failed)
	}
	if l.w == nil {
		l.failed = errors.New("nil writer")
		return fmt.Errorf("%w: %v", ErrUnavailable, l.failed)
	}
	if isTerminalStatus(e.Status) && !startedAtProvided && e.RequestID != "" {
		if startedAt, ok := l.pending[e.RequestID]; ok {
			e.StartedAt = startedAt
			e.DurationMS = max(0, e.EndedAt.Sub(startedAt).Milliseconds())
		}
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	line = append(line, '\n')
	if err := writeAll(l.w, line); err != nil {
		l.failed = err
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if durable {
		if f, ok := l.w.(interface{ Flush() error }); ok {
			if err := f.Flush(); err != nil {
				l.failed = fmt.Errorf("flush: %w", err)
				return fmt.Errorf("%w: %v", ErrUnavailable, l.failed)
			}
		}
		if s, ok := l.w.(interface{ Sync() error }); ok {
			if err := s.Sync(); err != nil {
				l.failed = fmt.Errorf("sync: %w", err)
				return fmt.Errorf("%w: %v", ErrUnavailable, l.failed)
			}
		}
	}
	if e.RequestID != "" {
		if isTerminalStatus(e.Status) {
			delete(l.pending, e.RequestID)
		} else {
			if l.pending == nil {
				l.pending = make(map[string]time.Time)
			}
			l.pending[e.RequestID] = e.StartedAt
		}
	}
	return nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return errors.New("audit writer returned an invalid byte count")
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func prepareEvent(e *Event) {
	now := time.Now().UTC()
	if e.Time.IsZero() {
		e.Time = now
	} else {
		e.Time = e.Time.UTC()
	}
	if e.StartedAt.IsZero() {
		e.StartedAt = e.Time
	} else {
		e.StartedAt = e.StartedAt.UTC()
	}
	if e.EndedAt.IsZero() && isTerminalStatus(e.Status) {
		e.EndedAt = e.Time
	}
	if !e.EndedAt.IsZero() {
		e.EndedAt = e.EndedAt.UTC()
		if e.DurationMS == 0 {
			e.DurationMS = max(0, e.EndedAt.Sub(e.StartedAt).Milliseconds())
		}
	}
	if e.Stage == "" && e.Status != "" {
		if isTerminalStatus(e.Status) {
			e.Stage = "completed"
		} else {
			e.Stage = "started"
		}
	}
	if e.ApprovalID != "" {
		e.Approved = true
	}
	if e.PolicyDecision == "" && e.PolicyID != "" {
		if e.Allowed {
			e.PolicyDecision = "allow"
		} else {
			e.PolicyDecision = "deny"
		}
	}
	sanitizeEvent(e)
}

func prepareStart(e Event) Event {
	now := time.Now().UTC()
	if e.StartedAt.IsZero() {
		e.StartedAt = now
	}
	if e.Time.IsZero() {
		e.Time = e.StartedAt
	}
	if e.Stage == "" {
		e.Stage = "started"
	}
	if e.Status == "" {
		e.Status = "started"
	}
	return e
}

func prepareFinish(e *Event) {
	now := time.Now().UTC()
	if e.EndedAt.IsZero() {
		e.EndedAt = now
	}
	if e.Time.IsZero() {
		e.Time = e.EndedAt
	}
	if e.Stage == "" || e.Stage == "started" {
		e.Stage = "completed"
	}
	if e.Status == "" || e.Status == "started" {
		e.Status = "success"
	}
	if !e.StartedAt.IsZero() {
		e.DurationMS = max(0, e.EndedAt.Sub(e.StartedAt).Milliseconds())
	}
}

func mergeEvents(start, result Event) Event {
	merged := reflect.ValueOf(&start).Elem()
	overlay := reflect.ValueOf(result)
	for i := 0; i < overlay.NumField(); i++ {
		if !overlay.Field(i).IsZero() {
			merged.Field(i).Set(overlay.Field(i))
		}
	}
	return start
}

func isTerminalStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "started", "starting", "pending", "running", "in_progress":
		return false
	default:
		return true
	}
}

// IsSensitiveKey reports whether a parameter name denotes a credential or
// secret. Token identifiers and non-secret hashes are intentionally excluded.
func IsSensitiveKey(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, key)
	if strings.HasSuffix(normalized, "tokenid") || strings.HasSuffix(normalized, "keyid") {
		return false
	}
	switch normalized {
	case "authorization", "proxyauthorization", "cookie", "setcookie",
		"password", "passwd", "pwd", "token", "accesstoken", "refreshtoken",
		"idtoken", "authtoken", "approvaltoken", "apikey", "privatekey",
		"clientsecret", "secret":
		return true
	}
	return strings.HasSuffix(normalized, "authorization") ||
		strings.HasSuffix(normalized, "cookie") ||
		strings.HasSuffix(normalized, "password") ||
		strings.HasSuffix(normalized, "secret") ||
		strings.HasSuffix(normalized, "privatekey") ||
		strings.HasSuffix(normalized, "apikey") ||
		strings.HasSuffix(normalized, "token")
}

// RedactSensitiveValue removes recognizable credentials from unstructured
// text. Structured parameters should use SummarizeParameters, which also uses
// key context.
func RedactSensitiveValue(value string) string {
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "-----BEGIN ") && strings.Contains(upper, "PRIVATE KEY-----") {
		return RedactedValue
	}
	value = authorizationValueRE.ReplaceAllString(value, "$1 "+RedactedValue)
	value = secretAssignmentRE.ReplaceAllStringFunc(value, func(match string) string {
		if i := strings.IndexAny(match, ":="); i >= 0 {
			return match[:i+1] + RedactedValue
		}
		return RedactedValue
	})
	return urlPasswordRE.ReplaceAllString(value, "://$1:"+RedactedValue+"@")
}

// DigestBytes returns a lowercase SHA-256 digest.
func DigestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// DigestString returns a lowercase SHA-256 digest.
func DigestString(value string) string { return DigestBytes([]byte(value)) }

// SummarizeParameters returns canonical JSON with recursive redaction. Large
// content-bearing values are replaced by their size and digest so request
// bodies are not copied into audit logs. Private keys are redacted without a
// digest.
func SummarizeParameters(parameters any) (ParameterSummary, error) {
	return summarizeParameters(parameters, true)
}

func summarizeParameters(parameters any, summarizeContents bool) (ParameterSummary, error) {
	raw, err := marshalParameters(parameters)
	if err != nil {
		return ParameterSummary{}, fmt.Errorf("marshal audit parameters: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return ParameterSummary{}, fmt.Errorf("decode audit parameters: %w", err)
	}
	var redacted []string
	value = sanitizeParameter(value, "", &redacted, summarizeContents)
	normalized, err := json.Marshal(value)
	if err != nil {
		return ParameterSummary{}, fmt.Errorf("normalize audit parameters: %w", err)
	}
	sort.Strings(redacted)
	return ParameterSummary{
		Normalized:     string(normalized),
		SHA256:         DigestBytes(normalized),
		Bytes:          int64(len(raw)),
		RedactedFields: redacted,
	}, nil
}

func marshalParameters(parameters any) ([]byte, error) {
	switch value := parameters.(type) {
	case json.RawMessage:
		if !json.Valid(value) {
			return nil, errors.New("invalid JSON parameters")
		}
		return value, nil
	case []byte:
		if json.Valid(value) {
			return value, nil
		}
		return json.Marshal(string(value))
	default:
		return json.Marshal(parameters)
	}
}

func sanitizeParameter(value any, path string, redacted *[]string, summarizeContents bool) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			safeKey := RedactSensitiveValue(key)
			childPath := safeKey
			if path != "" {
				childPath = path + "." + safeKey
			}
			if IsSensitiveKey(key) {
				result[safeKey] = RedactedValue
				*redacted = append(*redacted, childPath)
				continue
			}
			if summarizeContents && isContentKey(key) {
				result[safeKey] = summarizeContent(child, childPath, redacted)
				continue
			}
			result[safeKey] = sanitizeParameter(child, childPath, redacted, summarizeContents)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i, child := range typed {
			result[i] = sanitizeParameter(child, fmt.Sprintf("%s[%d]", path, i), redacted, summarizeContents)
		}
		return result
	case string:
		clean := RedactSensitiveValue(typed)
		if clean != typed {
			*redacted = append(*redacted, path)
		}
		return clean
	default:
		return value
	}
}

func isContentKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	switch normalized {
	case "content", "body", "data", "input", "output", "payload":
		return true
	default:
		return false
	}
}

func summarizeContent(value any, path string, redacted *[]string) any {
	var raw []byte
	if text, ok := value.(string); ok {
		if RedactSensitiveValue(text) != text {
			*redacted = append(*redacted, path)
			return RedactedValue
		}
		raw = []byte(text)
	} else {
		raw, _ = json.Marshal(value)
		if RedactSensitiveValue(string(raw)) != string(raw) {
			*redacted = append(*redacted, path)
			return RedactedValue
		}
	}
	return map[string]any{"bytes": len(raw), "sha256": DigestBytes(raw)}
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func sanitizeEvent(e *Event) {
	fields := []*string{
		&e.UserID, &e.ClientID, &e.SessionID, &e.AuthPrincipal, &e.Transport,
		&e.BridgeInstanceID, &e.RemoteIP, &e.RequestID, &e.ClientRequestID, &e.TokenID, &e.Tool,
		&e.WorkspaceID, &e.WorkspacePath, &e.Path, &e.NetworkTarget,
		&e.PolicyID, &e.PolicyVersion, &e.PolicyDecision, &e.ApprovalMode,
		&e.ApprovalSource, &e.ApprovalID, &e.Approver, &e.WorkerID, &e.Stage, &e.BeforeHash, &e.AfterHash,
		&e.Status, &e.SecurityDegradationReason,
	}
	for _, field := range fields {
		*field = RedactSensitiveValue(*field)
	}
	e.SecurityDegradationFields = append([]string(nil), e.SecurityDegradationFields...)
	for i := range e.SecurityDegradationFields {
		e.SecurityDegradationFields[i] = RedactSensitiveValue(e.SecurityDegradationFields[i])
	}
	if e.ParameterSummary != nil {
		original := e.ParameterSummary
		clean, err := summarizeParameters(json.RawMessage(original.Normalized), false)
		if err != nil {
			e.ParameterSummary = &ParameterSummary{
				Normalized:     `"[REDACTED]"`,
				SHA256:         DigestString(`"[REDACTED]"`),
				Bytes:          original.Bytes,
				RedactedFields: []string{"parameter_summary"},
			}
		} else {
			clean.Bytes = original.Bytes
			clean.RedactedFields = uniqueSorted(append(clean.RedactedFields, original.RedactedFields...))
			e.ParameterSummary = &clean
		}
	}
}
