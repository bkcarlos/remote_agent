package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

var ErrUnauthorized = errors.New("unauthorized")

// TokenValidator validates a bearer token and returns the stable principal to
// which MCP sessions and active requests are bound.
type TokenValidator interface {
	ValidateToken(context.Context, string) (string, error)
}

type TokenValidatorFunc func(context.Context, string) (string, error)

func (f TokenValidatorFunc) ValidateToken(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

// Authenticator allows deployments to replace HTTP authentication entirely.
// Bearer authentication through TokenValidator remains the default.
type Authenticator interface {
	Authenticate(*http.Request) (string, error)
}

type AuthenticatorFunc func(*http.Request) (string, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request) (string, error) { return f(r) }

type staticTokenValidator struct {
	token     string
	principal string
}

func (v staticTokenValidator) ValidateToken(_ context.Context, token string) (string, error) {
	if len(token) != len(v.token) || subtle.ConstantTimeCompare([]byte(token), []byte(v.token)) != 1 {
		return "", ErrUnauthorized
	}
	return v.principal, nil
}

func defaultPrincipal(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "bearer-sha256:" + hex.EncodeToString(sum[:8])
}

func (s *Server) authenticate(r *http.Request) (string, error) {
	if s.authenticator != nil {
		principal, err := s.authenticator.Authenticate(r)
		if err != nil || !validPrincipal(principal) {
			return "", ErrUnauthorized
		}
		return principal, nil
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", ErrUnauthorized
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.TrimSpace(token) != token {
		return "", ErrUnauthorized
	}
	principal, err := s.tokenValidator.ValidateToken(r.Context(), token)
	if err != nil || !validPrincipal(principal) {
		return "", ErrUnauthorized
	}
	return principal, nil
}

func validPrincipal(principal string) bool {
	if principal == "" || len(principal) > 1024 || strings.TrimSpace(principal) != principal {
		return false
	}
	for i := 0; i < len(principal); i++ {
		if principal[i] < ' ' || principal[i] == 0x7f {
			return false
		}
	}
	return true
}
