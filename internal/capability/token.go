package capability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

type Claims struct {
	TokenID   string    `json:"token_id"`
	RequestID string    `json:"request_id"`
	SessionID string    `json:"session_id"`
	Operation string    `json:"operation"`
	Path      string    `json:"path"`
	ExpiresAt time.Time `json:"expires_at"`
	SingleUse bool      `json:"single_use"`
}
type Manager struct {
	key  []byte
	mu   sync.Mutex
	used map[string]struct{}
	now  func() time.Time
}

func New(key []byte) (*Manager, error) {
	if len(key) < 32 {
		return nil, errors.New("capability key must be at least 32 bytes")
	}
	return &Manager{append([]byte(nil), key...), sync.Mutex{}, map[string]struct{}{}, time.Now}, nil
}
func (m *Manager) Sign(c Claims) (string, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return "", e
	}
	p := base64.RawURLEncoding.EncodeToString(b)
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
func (m *Manager) Verify(token, requestID, operation, path string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid capability format")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return c, errors.New("invalid capability signature")
	}
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(parts[0]))
	if !hmac.Equal(sig, h.Sum(nil)) {
		return c, errors.New("invalid capability signature")
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return c, errors.New("invalid capability payload")
	}
	if json.Unmarshal(b, &c) != nil {
		return c, errors.New("invalid capability payload")
	}
	if !m.now().Before(c.ExpiresAt) {
		return c, errors.New("capability expired")
	}
	if c.RequestID != requestID || c.Operation != operation || c.Path != path {
		return c, errors.New("capability scope mismatch")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.used[c.TokenID]; ok {
		return c, errors.New("capability already used")
	}
	if c.SingleUse {
		m.used[c.TokenID] = struct{}{}
	}
	return c, nil
}
