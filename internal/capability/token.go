package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const (
	tokenVersion          = "v1"
	maxTokenBytes         = 32 << 10
	maxCapabilityLifetime = time.Minute
)

// Claims describes every security-relevant property of one worker job.
type Target struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
}

type Claims struct {
	TokenID          string    `json:"token_id"`
	WorkerType       string    `json:"worker_type"`
	RequestID        string    `json:"request_id"`
	BridgeID         string    `json:"bridge_id,omitempty"`
	SessionID        string    `json:"session_id"`
	ClientRequestID  string    `json:"client_request_id,omitempty"`
	AuthPrincipal    string    `json:"auth_principal,omitempty"`
	Operation        string    `json:"operation"`
	Path             string    `json:"path"`
	Targets          []Target  `json:"targets,omitempty"`
	PolicyID         string    `json:"policy_id"`
	WorkerPolicyID   string    `json:"worker_policy_id,omitempty"`
	PolicyDecision   string    `json:"policy_decision,omitempty"`
	ApprovalRequired bool      `json:"approval_required,omitempty"`
	ArgumentsSHA256  string    `json:"arguments_sha256,omitempty"`
	MaxBytes         int64     `json:"max_bytes"`
	StartLine        int       `json:"start_line,omitempty"`
	EndLine          int       `json:"end_line,omitempty"`
	MaxEntries       int       `json:"max_entries"`
	MaxFiles         int       `json:"max_files"`
	MaxResults       int       `json:"max_results"`
	ExpectedHash     string    `json:"expected_hash"`
	ContentSHA256    string    `json:"content_sha256"`
	PatternSHA256    string    `json:"pattern_sha256"`
	QuerySHA256      string    `json:"query_sha256"`
	ExpiresAt        time.Time `json:"expires_at"`
	SingleUse        bool      `json:"single_use"`
}

// Scope is the worker-observed security context that must exactly match a token.
type Scope struct {
	WorkerType       string
	RequestID        string
	BridgeID         string
	SessionID        string
	ClientRequestID  string
	AuthPrincipal    string
	Operation        string
	Path             string
	Targets          []Target
	PolicyID         string
	WorkerPolicyID   string
	PolicyDecision   string
	ApprovalRequired bool
	ArgumentsSHA256  string
	MaxBytes         int64
	StartLine        int
	EndLine          int
	MaxEntries       int
	MaxFiles         int
	MaxResults       int
	ExpectedHash     string
	ContentSHA256    string
	PatternSHA256    string
	QuerySHA256      string
}

// Signer owns an Ed25519 private key and can issue capabilities.
type Signer struct {
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

// Verifier owns only an Ed25519 public key and tracks consumed single-use tokens.
type Verifier struct {
	publicKey ed25519.PublicKey
	mu        sync.Mutex
	used      map[string]struct{}
	now       func() time.Time
}

func NewSigner(privateKey ed25519.PrivateKey) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("capability Ed25519 private key must be 64 bytes")
	}
	return &Signer{privateKey: append(ed25519.PrivateKey(nil), privateKey...), now: time.Now}, nil
}

func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("capability Ed25519 seed must be 32 bytes")
	}
	return NewSigner(ed25519.NewKeyFromSeed(seed))
}

func NewVerifier(publicKey ed25519.PublicKey) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("capability Ed25519 public key must be 32 bytes")
	}
	return &Verifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		used:      make(map[string]struct{}),
		now:       time.Now,
	}, nil
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

func (s *Signer) Sign(c Claims) (string, error) {
	now := s.now().UTC()
	if err := validateClaims(c); err != nil {
		return "", err
	}
	if !c.ExpiresAt.After(now) {
		return "", errors.New("capability expiry must be in the future")
	}
	if c.ExpiresAt.After(now.Add(maxCapabilityLifetime)) {
		return "", errors.New("capability lifetime exceeds one minute")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signed := tokenVersion + "." + encoded
	signature := ed25519.Sign(s.privateKey, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (v *Verifier) Verify(token string, scope Scope) (Claims, error) {
	var claims Claims
	if len(token) == 0 || len(token) > maxTokenBytes {
		return claims, errors.New("invalid capability format")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return claims, errors.New("invalid capability format")
	}
	payload, err := decodeCanonicalBase64(parts[1])
	if err != nil {
		return claims, errors.New("invalid capability payload")
	}
	signature, err := decodeCanonicalBase64(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return claims, errors.New("invalid capability signature")
	}
	if !ed25519.Verify(v.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, errors.New("invalid capability signature")
	}
	if err := protocol.DecodeStrict(payload, &claims); err != nil {
		return claims, errors.New("invalid capability payload")
	}
	if err := validateClaims(claims); err != nil {
		return claims, errors.New("invalid capability claims: " + err.Error())
	}
	now := v.now().UTC()
	if !now.Before(claims.ExpiresAt) {
		return claims, errors.New("capability expired")
	}
	if claims.ExpiresAt.After(now.Add(maxCapabilityLifetime)) {
		return claims, errors.New("capability lifetime exceeds one minute")
	}
	if !matchesScope(claims, scope) {
		return claims, errors.New("capability scope mismatch")
	}
	if claims.SingleUse {
		v.mu.Lock()
		defer v.mu.Unlock()
		if _, exists := v.used[claims.TokenID]; exists {
			return claims, errors.New("capability already used")
		}
		v.used[claims.TokenID] = struct{}{}
	}
	return claims, nil
}

func NormalizePath(raw string) (string, error) {
	if raw == "" || filepath.IsAbs(raw) || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("capability path must be a non-empty relative path")
	}
	clean := filepath.Clean(raw)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("capability path escapes workspace")
	}
	return filepath.ToSlash(clean), nil
}

func validateClaims(c Claims) error {
	if c.TokenID == "" || c.WorkerType == "" || c.RequestID == "" || c.SessionID == "" || c.Operation == "" || c.Path == "" || c.PolicyID == "" || c.ExpiresAt.IsZero() {
		return errors.New("capability claims are incomplete")
	}
	normalized, err := NormalizePath(c.Path)
	if err != nil || normalized != c.Path {
		return errors.New("capability path is not normalized")
	}
	if c.MaxBytes < 0 || c.StartLine < 0 || c.EndLine < 0 || c.MaxEntries < 0 || c.MaxFiles < 0 || c.MaxResults < 0 {
		return errors.New("capability resource limits cannot be negative")
	}
	if (c.StartLine == 0) != (c.EndLine == 0) || c.StartLine > c.EndLine || c.EndLine-c.StartLine+1 > 10000 {
		return errors.New("capability line range is invalid")
	}
	for _, target := range c.Targets {
		normalized, err := NormalizePath(target.Path)
		if err != nil || normalized != target.Path {
			return errors.New("capability target path is not normalized")
		}
		if target.BeforeSHA256 != "" && !validSHA256(target.BeforeSHA256) {
			return errors.New("target before hash must be a lowercase SHA-256 value")
		}
		if target.AfterSHA256 != "" && !validSHA256(target.AfterSHA256) {
			return errors.New("target after hash must be a lowercase SHA-256 value")
		}
	}
	for name, value := range map[string]string{
		"expected hash":    c.ExpectedHash,
		"content hash":     c.ContentSHA256,
		"pattern digest":   c.PatternSHA256,
		"query digest":     c.QuerySHA256,
		"arguments digest": c.ArgumentsSHA256,
	} {
		if value != "" && !validSHA256(value) {
			return errors.New(name + " must be a lowercase SHA-256 value")
		}
	}
	return nil
}

func matchesScope(c Claims, s Scope) bool {
	return c.WorkerType == s.WorkerType &&
		c.RequestID == s.RequestID &&
		c.BridgeID == s.BridgeID &&
		c.SessionID == s.SessionID &&
		c.ClientRequestID == s.ClientRequestID &&
		c.AuthPrincipal == s.AuthPrincipal &&
		c.Operation == s.Operation &&
		c.Path == s.Path &&
		targetsEqual(c.Targets, s.Targets) &&
		c.PolicyID == s.PolicyID &&
		c.WorkerPolicyID == s.WorkerPolicyID &&
		c.PolicyDecision == s.PolicyDecision &&
		c.ApprovalRequired == s.ApprovalRequired &&
		c.ArgumentsSHA256 == s.ArgumentsSHA256 &&
		c.MaxBytes == s.MaxBytes &&
		c.StartLine == s.StartLine &&
		c.EndLine == s.EndLine &&
		c.MaxEntries == s.MaxEntries &&
		c.MaxFiles == s.MaxFiles &&
		c.MaxResults == s.MaxResults &&
		c.ExpectedHash == s.ExpectedHash &&
		c.ContentSHA256 == s.ContentSHA256 &&
		c.PatternSHA256 == s.PatternSHA256 &&
		c.QuerySHA256 == s.QuerySHA256
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

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}
