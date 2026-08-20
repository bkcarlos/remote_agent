package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/replay"
)

type Claims struct {
	ApprovalID    string    `json:"approval_id"`
	SessionID     string    `json:"session_id"`
	Operation     string    `json:"operation"`
	Path          string    `json:"path"`
	ContentSHA256 string    `json:"content_sha256"`
	ExpectedHash  string    `json:"expected_hash,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Scope struct {
	SessionID     string
	Operation     string
	Path          string
	ContentSHA256 string
	ExpectedHash  string
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
	if c.ApprovalID == "" || c.SessionID == "" || c.Operation == "" || c.Path == "" || c.ContentSHA256 == "" || c.ExpiresAt.IsZero() {
		return errors.New("approval challenge is incomplete")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return m.challenges.Put("approval", c.ApprovalID, payload, c.ExpiresAt)
}

func (m *Manager) Sign(c Claims) (string, error) {
	if c.ApprovalID == "" || c.SessionID == "" || c.Operation == "" || c.Path == "" || c.ContentSHA256 == "" || c.ExpiresAt.IsZero() {
		return "", errors.New("approval claims are incomplete")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (m *Manager) Verify(token string, scope Scope) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid approval token format")
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errors.New("invalid approval token signature")
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return c, errors.New("invalid approval token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return c, errors.New("invalid approval token payload")
	}
	now := m.now().UTC()
	if !now.Before(c.ExpiresAt) {
		return c, errors.New("approval token expired")
	}
	if c.SessionID != scope.SessionID || c.Operation != scope.Operation || c.Path != scope.Path || c.ContentSHA256 != scope.ContentSHA256 || c.ExpectedHash != scope.ExpectedHash {
		return c, errors.New("approval scope mismatch")
	}
	if m.challenges != nil {
		payload, err := m.challenges.Take("approval", c.ApprovalID, now)
		if err != nil {
			return c, errors.New("approval challenge was not found, expired, or already consumed")
		}
		var registered Claims
		if json.Unmarshal(payload, &registered) != nil || registered.ApprovalID != c.ApprovalID || registered.SessionID != c.SessionID || registered.Operation != c.Operation || registered.Path != c.Path || registered.ContentSHA256 != c.ContentSHA256 || registered.ExpectedHash != c.ExpectedHash {
			return c, errors.New("approval does not match the registered dry-run challenge")
		}
	}
	if err := m.store.Consume("approval-used", c.ApprovalID, c.ExpiresAt, now); err != nil {
		if errors.Is(err, replay.ErrAlreadyUsed) {
			return c, errors.New("approval token already used")
		}
		return c, errors.New("approval replay protection unavailable")
	}
	return c, nil
}
