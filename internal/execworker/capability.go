package execworker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const (
	execTokenVersion = "exec-v1"
	maxTokenBytes    = 64 << 10
	maxTokenLifetime = time.Minute
)

// CapabilityClaims bind every security-relevant property of an Exec job.
// InputDigest covers argv, environment values, opaque process handle, signal,
// and memory pattern without exposing those values in the token metadata.
type CapabilityClaims struct {
	CapabilityID  string    `json:"capability_id"`
	Principal     string    `json:"principal"`
	SessionID     string    `json:"session_id"`
	WorkspaceID   string    `json:"workspace_id"`
	TaskID        string    `json:"task_id"`
	Profile       string    `json:"profile"`
	ProfileDigest string    `json:"profile_digest"`
	Operation     string    `json:"operation"`
	Limits        Limits    `json:"limits"`
	InputDigest   string    `json:"input_digest"`
	ExpiresAt     time.Time `json:"expires_at"`
	SingleUse     bool      `json:"single_use"`
}

type CapabilitySigner struct {
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

type CapabilityVerifier struct {
	publicKey ed25519.PublicKey
	now       func() time.Time
	mu        sync.Mutex
	used      map[string]time.Time
}

func NewCapabilitySigner(key ed25519.PrivateKey) (*CapabilitySigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("exec capability Ed25519 private key must be 64 bytes")
	}
	return &CapabilitySigner{privateKey: append(ed25519.PrivateKey(nil), key...), now: time.Now}, nil
}

func NewCapabilitySignerFromSeed(seed []byte) (*CapabilitySigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("exec capability Ed25519 seed must be 32 bytes")
	}
	return NewCapabilitySigner(ed25519.NewKeyFromSeed(seed))
}

func NewCapabilityVerifier(key ed25519.PublicKey) (*CapabilityVerifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("exec capability Ed25519 public key must be 32 bytes")
	}
	return &CapabilityVerifier{publicKey: append(ed25519.PublicKey(nil), key...), now: time.Now, used: make(map[string]time.Time)}, nil
}

func (s *CapabilitySigner) PublicKey() ed25519.PublicKey {
	key := s.privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), key...)
}

func (s *CapabilitySigner) Sign(claims CapabilityClaims) (string, error) {
	now := s.now().UTC()
	if err := validateCapabilityClaims(claims); err != nil {
		return "", err
	}
	if !claims.ExpiresAt.After(now) || claims.ExpiresAt.After(now.Add(maxTokenLifetime)) {
		return "", errors.New("exec capability expiry is invalid")
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	signed := execTokenVersion + "." + payload
	signature := ed25519.Sign(s.privateKey, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (v *CapabilityVerifier) Verify(token string, expected CapabilityClaims) (CapabilityClaims, error) {
	var claims CapabilityClaims
	if len(token) == 0 || len(token) > maxTokenBytes {
		return claims, errors.New("invalid exec capability format")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != execTokenVersion {
		return claims, errors.New("invalid exec capability format")
	}
	payload, err := decodeCanonical(parts[1])
	if err != nil {
		return claims, errors.New("invalid exec capability payload")
	}
	signature, err := decodeCanonical(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(v.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, errors.New("invalid exec capability signature")
	}
	if err := protocol.DecodeStrict(payload, &claims); err != nil {
		return claims, errors.New("invalid exec capability payload")
	}
	if err := validateCapabilityClaims(claims); err != nil {
		return claims, errors.New("invalid exec capability claims")
	}
	now := v.now().UTC()
	if !now.Before(claims.ExpiresAt) || claims.ExpiresAt.After(now.Add(maxTokenLifetime)) {
		return claims, errors.New("exec capability expired or lifetime is invalid")
	}
	expected.ExpiresAt = claims.ExpiresAt
	expected.SingleUse = claims.SingleUse
	if !equalClaims(claims, expected) {
		return claims, errors.New("exec capability scope mismatch")
	}
	if !claims.SingleUse {
		return claims, errors.New("exec capability must be single-use")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, expiry := range v.used {
		if !now.Before(expiry) {
			delete(v.used, id)
		}
	}
	if _, exists := v.used[claims.CapabilityID]; exists {
		return claims, errors.New("exec capability already used")
	}
	v.used[claims.CapabilityID] = claims.ExpiresAt
	return claims, nil
}

func ClaimsForJob(job Job, profileDigest string, expiresAt time.Time) (CapabilityClaims, error) {
	inputDigest, err := JobInputDigest(job)
	if err != nil {
		return CapabilityClaims{}, err
	}
	claims := CapabilityClaims{
		CapabilityID: job.CapabilityID, Principal: job.Principal, SessionID: job.SessionID,
		WorkspaceID: job.WorkspaceID, TaskID: job.TaskID, Profile: job.Profile,
		ProfileDigest: profileDigest, Operation: job.Operation, Limits: job.Limits,
		InputDigest: inputDigest, ExpiresAt: expiresAt.UTC(), SingleUse: true,
	}
	if err := validateCapabilityClaims(claims); err != nil {
		return CapabilityClaims{}, err
	}
	return claims, nil
}

func JobInputDigest(job Job) (string, error) {
	type input struct {
		Argv      []string    `json:"argv,omitempty"`
		Env       [][2]string `json:"env,omitempty"`
		ProcessID string      `json:"process_id,omitempty"`
		Signal    string      `json:"signal,omitempty"`
		Memory    *MemoryScan `json:"memory,omitempty"`
	}
	names := make([]string, 0, len(job.Env))
	for name := range job.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	value := input{Argv: append([]string(nil), job.Argv...), ProcessID: job.ProcessID, Signal: job.Signal, Memory: job.Memory}
	for _, name := range names {
		value.Env = append(value.Env, [2]string{name, job.Env[name]})
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validateCapabilityClaims(c CapabilityClaims) error {
	if c.CapabilityID == "" || c.Principal == "" || c.SessionID == "" || c.WorkspaceID == "" || c.TaskID == "" || c.Profile == "" || c.Operation == "" || c.ExpiresAt.IsZero() {
		return errors.New("exec capability claims are incomplete")
	}
	if !validDigest(c.ProfileDigest) || !validDigest(c.InputDigest) {
		return errors.New("exec capability digest is invalid")
	}
	return c.Limits.Validate()
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func equalClaims(a, b CapabilityClaims) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return subtle.ConstantTimeCompare(left, right) == 1
}

func decodeCanonical(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}
