package requestmeta

import "context"

// Scope contains request identity and the policy decision that must follow an
// operation from the gateway to the isolated worker capability.
type Scope struct {
	RequestID        string
	BridgeID         string
	SessionID        string
	ClientRequestID  string
	AuthPrincipal    string
	RemoteIP         string
	PolicyID         string
	PolicyDecision   string
	ApprovalRequired bool
}

type contextKey struct{}

func WithScope(ctx context.Context, scope Scope) context.Context {
	return context.WithValue(ctx, contextKey{}, scope)
}

func FromContext(ctx context.Context) (Scope, bool) {
	if ctx == nil {
		return Scope{}, false
	}
	scope, ok := ctx.Value(contextKey{}).(Scope)
	return scope, ok
}
