package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/replay"
)

const maxApprovalLifetime = 5 * time.Minute

type Target struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	AfterSHA256  string `json:"after_sha256"`
}

type Claims struct {
	// ApprovalID remains the public identifier used by the existing approve CLI.
	ApprovalID    string    `json:"approval_id"`
	ChallengeID   string    `json:"challenge_id,omitempty"`
	Approver      string    `json:"approver,omitempty"`
	SessionID     string    `json:"session_id"`
	Operation     string    `json:"operation"`
	Targets       []Target  `json:"targets,omitempty"`
	Path          string    `json:"path,omitempty"`
	ContentSHA256 string    `json:"content_sha256,omitempty"`
	ExpectedHash  string    `json:"expected_hash,omitempty"`
	ReviewSHA256  string    `json:"review_sha256,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Scope struct {
	SessionID     string
	Operation     string
	Targets       []Target
	Path          string
	ContentSHA256 string
	ExpectedHash  string
	ReviewSHA256  string
}

type Manager struct {
	key        []byte
	store      replay.Store
	challenges replay.ChallengeStore
	now        func() time.Time
}

func New(key []byte) (*Manager, error) { return NewWithStore(key, replay.NewMemory()) }

func NewWithStore(key []byte, store replay.Store) (*Manager, error) {
	if len(key) < 32 {
		return nil, errors.New("approval key must be at least 32 bytes")
	}
	if store == nil {
		return nil, errors.New("approval replay store is required")
	}
	return &Manager{key: append([]byte(nil), key...), store: store, now: time.Now}, nil
}

func NewWithChallengeStore(key []byte, store replay.ChallengeStore) (*Manager, error) {
	m, err := NewWithStore(key, store)
	if err != nil {
		return nil, err
	}
	m.challenges = store
	return m, nil
}

func (m *Manager) RegisterChallenge(c Claims) error {
	if m.challenges == nil {
		return errors.New("approval challenge store is not configured")
	}
	normalized, err := normalizeClaims(c, false)
	if err != nil {
		return err
	}
	if !normalized.ExpiresAt.After(m.now().UTC()) || normalized.ExpiresAt.After(m.now().UTC().Add(maxApprovalLifetime)) {
		return errors.New("approval challenge expiry is invalid")
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	return m.challenges.Put("approval", normalized.ChallengeID, payload, normalized.ExpiresAt)
}

func (m *Manager) Sign(c Claims) (string, error) {
	normalized, err := normalizeClaims(c, true)
	if err != nil {
		return "", err
	}
	now := m.now().UTC()
	if !normalized.ExpiresAt.After(now) || normalized.ExpiresAt.After(now.Add(maxApprovalLifetime)) {
		return "", errors.New("approval expiry must be in the future and no more than five minutes")
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Inspect authenticates and binds an approval to its scope and registered
// challenge without consuming either the challenge or replay token.
func (m *Manager) Inspect(token string, scope Scope) (Claims, error) {
	c, _, err := m.inspect(token, scope)
	return c, err
}

// Verify repeats the full authentication and read-only binding checks, then
// atomically takes and rechecks the actual registered challenge before consuming
// the replay token. Callers must not rely on claims returned by an earlier
// Inspect because another verifier may win the consume race.
func (m *Manager) Verify(token string, scope Scope) (Claims, error) {
	c, now, err := m.inspect(token, scope)
	if err != nil {
		return c, err
	}
	if m.challenges != nil {
		registeredPayload, err := m.challenges.Take("approval", c.ChallengeID, now)
		if err != nil {
			return c, errors.New("approval challenge was not found, expired, or already consumed")
		}
		if err := validateChallengeBinding(registeredPayload, c); err != nil {
			return c, err
		}
	}
	if err := m.store.Consume("approval-used", c.ChallengeID, c.ExpiresAt, now); err != nil {
		if errors.Is(err, replay.ErrAlreadyUsed) {
			return c, errors.New("approval token already used")
		}
		return c, errors.New("approval replay protection unavailable")
	}
	return c, nil
}

func (m *Manager) inspect(token string, scope Scope) (Claims, time.Time, error) {
	c, now, err := m.authenticate(token, scope)
	if err != nil {
		return c, now, err
	}
	if m.challenges == nil {
		return c, now, nil
	}
	registeredPayload, err := m.challenges.Peek("approval", c.ChallengeID, now)
	if err != nil {
		return c, now, errors.New("approval challenge was not found, expired, or already consumed")
	}
	if err := validateChallengeBinding(registeredPayload, c); err != nil {
		return c, now, err
	}
	return c, now, nil
}

func (m *Manager) authenticate(token string, scope Scope) (Claims, time.Time, error) {
	var c Claims
	if len(token) == 0 || len(token) > 32<<10 {
		return c, time.Time{}, errors.New("invalid approval token format")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, time.Time{}, errors.New("invalid approval token format")
	}
	provided, err := decodeCanonical(parts[1])
	if err != nil {
		return c, time.Time{}, errors.New("invalid approval token signature")
	}
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return c, time.Time{}, errors.New("invalid approval token signature")
	}
	payload, err := decodeCanonical(parts[0])
	if err != nil || protocol.DecodeStrict(payload, &c) != nil {
		return c, time.Time{}, errors.New("invalid approval token payload")
	}
	c, err = normalizeClaims(c, true)
	if err != nil {
		return Claims{}, time.Time{}, errors.New("invalid approval token payload")
	}
	now := m.now().UTC()
	if !now.Before(c.ExpiresAt) || c.ExpiresAt.After(now.Add(maxApprovalLifetime)) {
		return c, now, errors.New("approval token expired or lifetime is too long")
	}
	targets, err := normalizeScope(scope)
	if err != nil || c.SessionID != scope.SessionID || c.Operation != scope.Operation || c.ReviewSHA256 != scope.ReviewSHA256 || !targetsEqual(c.Targets, targets) {
		return c, now, errors.New("approval scope mismatch")
	}
	return c, now, nil
}

func validateChallengeBinding(payload []byte, approved Claims) error {
	var registered Claims
	if protocol.DecodeStrict(payload, &registered) != nil {
		return errors.New("approval does not match the registered dry-run challenge")
	}
	registered, err := normalizeClaims(registered, false)
	if err != nil || !sameBinding(registered, approved) || approved.ExpiresAt.After(registered.ExpiresAt) {
		return errors.New("approval does not match the registered dry-run challenge")
	}
	return nil
}

func normalizeClaims(c Claims, requireApprover bool) (Claims, error) {
	if c.ApprovalID == "" || c.SessionID == "" || c.Operation == "" || c.ExpiresAt.IsZero() {
		return Claims{}, errors.New("approval claims are incomplete")
	}
	if requireApprover && !validApprover(c.Approver) {
		return Claims{}, errors.New("approval claims are incomplete")
	}
	if c.Approver != "" && !validApprover(c.Approver) {
		return Claims{}, errors.New("approval approver is invalid")
	}
	if c.ChallengeID == "" {
		c.ChallengeID = c.ApprovalID
	}
	if c.ChallengeID != c.ApprovalID {
		return Claims{}, errors.New("approval and challenge IDs must match")
	}
	if c.ReviewSHA256 == "" {
		if c.Operation != "write_file" {
			return Claims{}, errors.New("approval review SHA-256 is required")
		}
	} else if !validSHA256(c.ReviewSHA256) {
		return Claims{}, errors.New("approval review SHA-256 is invalid")
	}
	if len(c.Targets) == 0 {
		if c.Path == "" || c.ContentSHA256 == "" {
			return Claims{}, errors.New("approval claims are incomplete")
		}
		c.Targets = []Target{{Path: c.Path, BeforeSHA256: c.ExpectedHash, AfterSHA256: c.ContentSHA256}}
	}
	if len(c.Targets) > 20 {
		return Claims{}, errors.New("approval target limit exceeded")
	}
	seen := make(map[string]struct{}, len(c.Targets))
	for i := range c.Targets {
		normalized, err := capability.NormalizePath(c.Targets[i].Path)
		if err != nil {
			return Claims{}, errors.New("approval target path is invalid")
		}
		c.Targets[i].Path = normalized
		if _, exists := seen[normalized]; exists {
			return Claims{}, errors.New("approval target paths must be unique")
		}
		seen[normalized] = struct{}{}
		if !validSHA256(c.Targets[i].AfterSHA256) || (c.Targets[i].BeforeSHA256 != "" && !validSHA256(c.Targets[i].BeforeSHA256)) {
			return Claims{}, errors.New("approval target hashes are invalid")
		}
	}
	if len(c.Targets) == 1 {
		c.Path = c.Targets[0].Path
		c.ExpectedHash = c.Targets[0].BeforeSHA256
		c.ContentSHA256 = c.Targets[0].AfterSHA256
	} else {
		c.Path, c.ExpectedHash, c.ContentSHA256 = "", "", ""
	}
	return c, nil
}

func normalizeScope(s Scope) ([]Target, error) {
	claims := Claims{ApprovalID: "scope", ChallengeID: "scope", SessionID: s.SessionID, Operation: s.Operation, Targets: s.Targets, Path: s.Path, ContentSHA256: s.ContentSHA256, ExpectedHash: s.ExpectedHash, ReviewSHA256: s.ReviewSHA256, ExpiresAt: time.Unix(1, 0)}
	normalized, err := normalizeClaims(claims, false)
	return normalized.Targets, err
}

func validApprover(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func sameBinding(a, b Claims) bool {
	return a.ChallengeID == b.ChallengeID && a.SessionID == b.SessionID && a.Operation == b.Operation && a.ReviewSHA256 == b.ReviewSHA256 && targetsEqual(a.Targets, b.Targets)
}

func targetsEqual(a, b []Target) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func decodeCanonical(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}
