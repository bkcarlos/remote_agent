package gateway

import (
	"context"
	"errors"
)

var errServerRevoked = errors.New("gateway server revoked")

// admit linearizes request admission with Revoke. A request is either tracked
// before revocation and receives cancellation, or is rejected after revocation.
func (s *Server) admit(parent context.Context) (context.Context, uint64, bool) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.revoked {
		return nil, 0, false
	}
	ctx, cancel := context.WithCancel(parent)
	s.nextRequest++
	number := s.nextRequest
	s.requests[number] = cancel
	return ctx, number, true
}

func (s *Server) finishRequest(number uint64) {
	s.lifecycleMu.Lock()
	cancel := s.requests[number]
	delete(s.requests, number)
	s.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// createSession prevents an initialize request admitted before revocation from
// publishing a session after the revocation linearization point.
func (s *Server) createSession(principal, protocolVersion string) (mcpSession, error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.revoked {
		return mcpSession{}, errServerRevoked
	}
	return s.sessions.create(principal, protocolVersion)
}

// Revoke permanently closes this workspace server. It rejects future requests,
// deletes every MCP session, and cancels all admitted and active requests.
// ProcessExecutor deliberately preserves an already-started approved commit;
// its independent hard timeout remains the final bound for that safety region.
func (s *Server) Revoke() {
	s.lifecycleMu.Lock()
	if s.revoked {
		s.lifecycleMu.Unlock()
		return
	}
	s.revoked = true
	sessions := s.sessions.snapshot()
	s.sessions.clear()
	requestCancels := make([]context.CancelFunc, 0, len(s.requests))
	for _, cancel := range s.requests {
		requestCancels = append(requestCancels, cancel)
	}
	s.lifecycleMu.Unlock()

	s.activeMu.Lock()
	activeCancels := make([]context.CancelFunc, 0, len(s.active))
	for _, cancel := range s.active {
		activeCancels = append(activeCancels, cancel)
	}
	s.activeMu.Unlock()

	s.revokeExecSessionsWithTimeout(sessions)
	if s.execCloser != nil {
		_ = s.execCloser.Close()
	}
	for _, cancel := range requestCancels {
		cancel()
	}
	for _, cancel := range activeCancels {
		cancel()
	}
}

// Close implements the conventional lifecycle shape for owners that use defer.
func (s *Server) Close() error {
	s.Revoke()
	return nil
}
