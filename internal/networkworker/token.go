package networkworker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	tokenVersion          = "v1"
	maxTokenBytes         = 32 << 10
	maxCapabilityLifetime = time.Minute
)

type Signer struct {
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

type Verifier struct {
	publicKey ed25519.PublicKey
	now       func() time.Time
	mu        sync.Mutex
	used      map[string]struct{}
}

func NewSigner(privateKey ed25519.PrivateKey) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("network capability Ed25519 private key must be 64 bytes")
	}
	return &Signer{privateKey: append(ed25519.PrivateKey(nil), privateKey...), now: time.Now}, nil
}

func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("network capability Ed25519 seed must be 32 bytes")
	}
	return NewSigner(ed25519.NewKeyFromSeed(seed))
}

func NewVerifier(publicKey ed25519.PublicKey) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("network capability Ed25519 public key must be 32 bytes")
	}
	return &Verifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		now:       time.Now,
		used:      make(map[string]struct{}),
	}, nil
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	key := s.privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), key...)
}

func (s *Signer) Sign(claims Claims) (string, error) {
	now := s.now().UTC()
	if err := validateClaims(claims); err != nil {
		return "", err
	}
	if !claims.ExpiresAt.After(now) {
		return "", errors.New("network capability expiry must be in the future")
	}
	if claims.ExpiresAt.After(now.Add(maxCapabilityLifetime)) {
		return "", errors.New("network capability lifetime exceeds one minute")
	}
	payload, err := json.Marshal(claims)
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
		return claims, errors.New("invalid network capability format")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return claims, errors.New("invalid network capability format")
	}
	payload, err := decodeCanonicalBase64(parts[1])
	if err != nil {
		return claims, errors.New("invalid network capability payload")
	}
	signature, err := decodeCanonicalBase64(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return claims, errors.New("invalid network capability signature")
	}
	if !ed25519.Verify(v.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, errors.New("invalid network capability signature")
	}
	if err := decodeStrict(payload, &claims); err != nil {
		return claims, errors.New("invalid network capability payload")
	}
	if err := validateClaims(claims); err != nil {
		return claims, errors.New("invalid network capability claims: " + err.Error())
	}
	now := v.now().UTC()
	if !now.Before(claims.ExpiresAt) {
		return claims, errors.New("network capability expired")
	}
	if claims.ExpiresAt.After(now.Add(maxCapabilityLifetime)) {
		return claims, errors.New("network capability lifetime exceeds one minute")
	}
	if !claimsMatchScope(claims, scope) {
		return claims, errors.New("network capability scope mismatch")
	}
	if claims.SingleUse {
		v.mu.Lock()
		defer v.mu.Unlock()
		if _, exists := v.used[claims.TokenID]; exists {
			return claims, errors.New("network capability already used")
		}
		v.used[claims.TokenID] = struct{}{}
	}
	return claims, nil
}

func validateClaims(claims Claims) error {
	if claims.TokenID == "" || claims.WorkerType != WorkerType || claims.RequestID == "" || claims.Principal == "" || claims.WorkspaceID == "" || claims.BridgeID == "" || claims.SessionID == "" || claims.ClientRequestID == "" || claims.Operation == "" || claims.URL == "" || claims.Method == "" || claims.PolicyID == "" || claims.ProfileID == "" || claims.ExpiresAt.IsZero() {
		return errors.New("network capability claims are incomplete")
	}
	if !claims.SingleUse {
		return errors.New("network capability must be single-use")
	}
	for _, digest := range []string{claims.HeadersSHA256, claims.BodySHA256, claims.PolicySHA256} {
		if !isSHA256(digest) {
			return errors.New("network capability digest is invalid")
		}
	}
	normalizedURL, err := NormalizeURL(claims.URL)
	if err != nil || normalizedURL != claims.URL {
		return errors.New("network capability URL is not normalized")
	}
	if err := validateOperationMethod(claims.Operation, claims.Method); err != nil {
		return err
	}
	return validateLimits(claims.Limits)
}

func claimsMatchScope(claims Claims, scope Scope) bool {
	return claims.TokenID == scope.TokenID &&
		claims.WorkerType == scope.WorkerType &&
		claims.RequestID == scope.RequestID &&
		claims.Principal == scope.Principal &&
		claims.WorkspaceID == scope.WorkspaceID &&
		claims.BridgeID == scope.BridgeID &&
		claims.SessionID == scope.SessionID &&
		claims.ClientRequestID == scope.ClientRequestID &&
		claims.Operation == scope.Operation &&
		claims.URL == scope.URL &&
		claims.Method == scope.Method &&
		claims.HeadersSHA256 == scope.HeadersSHA256 &&
		claims.BodySHA256 == scope.BodySHA256 &&
		claims.PolicyID == scope.PolicyID &&
		claims.ProfileID == scope.ProfileID &&
		claims.PolicySHA256 == scope.PolicySHA256 &&
		claims.Limits == scope.Limits
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64")
	}
	return decoded, nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
