package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"
)

const (
	defaultSessionTTL  = 30 * time.Minute
	defaultMaxSessions = 4096
)

var (
	errSessionNotFound        = errors.New("MCP session not found or expired")
	errSessionProtocolVersion = errors.New("unsupported MCP protocol version")
)

type mcpSession struct {
	ID              string
	Principal       string
	ProtocolVersion string
	CreatedAt       time.Time
	LastSeen        time.Time
	Revoking        bool
}

type sessionStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	max      int
	now      func() time.Time
	onEvict  func([]mcpSession)
	sessions map[string]mcpSession
}

func newSessionStore(ttl time.Duration, max int, now func() time.Time) *sessionStore {
	return &sessionStore{ttl: ttl, max: max, now: now, sessions: make(map[string]mcpSession)}
}

func (s *sessionStore) create(principal, protocolVersion string) (mcpSession, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return mcpSession{}, err
	}
	now := s.now().UTC()
	session := mcpSession{
		ID: base64.RawURLEncoding.EncodeToString(value), Principal: principal,
		ProtocolVersion: protocolVersion, CreatedAt: now, LastSeen: now,
	}
	s.mu.Lock()
	evicted := s.removeExpiredLocked(now)
	for len(s.sessions) >= s.max {
		if removed, ok := s.evictOldestLocked(); ok {
			evicted = append(evicted, removed)
		}
	}
	s.sessions[session.ID] = session
	onEvict := s.onEvict
	s.mu.Unlock()
	if onEvict != nil && len(evicted) > 0 {
		onEvict(evicted)
	}
	return session, nil
}

func (s *sessionStore) validateAndTouch(id, principal, protocolVersion string) (mcpSession, error) {
	now := s.now().UTC()
	s.mu.Lock()
	session, found := s.sessions[id]
	if !found || session.Principal != principal || session.Revoking {
		s.mu.Unlock()
		return mcpSession{}, errSessionNotFound
	}
	if !now.Before(session.LastSeen.Add(s.ttl)) {
		delete(s.sessions, id)
		onEvict := s.onEvict
		s.mu.Unlock()
		if onEvict != nil {
			onEvict([]mcpSession{session})
		}
		return mcpSession{}, errSessionNotFound
	}
	if protocolVersion != session.ProtocolVersion {
		s.mu.Unlock()
		return mcpSession{}, errSessionProtocolVersion
	}
	session.LastSeen = now
	s.sessions[id] = session
	s.mu.Unlock()
	return session, nil
}

func (s *sessionStore) markRevoking(id, principal, protocolVersion string) (mcpSession, error) {
	now := s.now().UTC()
	s.mu.Lock()
	session, found := s.sessions[id]
	if !found || session.Principal != principal {
		s.mu.Unlock()
		return mcpSession{}, errSessionNotFound
	}
	if !now.Before(session.LastSeen.Add(s.ttl)) {
		delete(s.sessions, id)
		onEvict := s.onEvict
		s.mu.Unlock()
		if onEvict != nil {
			onEvict([]mcpSession{session})
		}
		return mcpSession{}, errSessionNotFound
	}
	if protocolVersion != session.ProtocolVersion {
		s.mu.Unlock()
		return mcpSession{}, errSessionProtocolVersion
	}
	session.Revoking = true
	s.sessions[id] = session
	s.mu.Unlock()
	return session, nil
}

func (s *sessionStore) deleteRevoked(id, principal string) {
	s.mu.Lock()
	if session, ok := s.sessions[id]; ok && session.Principal == principal && session.Revoking {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
}

func (s *sessionStore) clear() {
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
}

func (s *sessionStore) snapshot() []mcpSession {
	s.mu.Lock()
	now := s.now().UTC()
	evicted := s.removeExpiredLocked(now)
	result := make([]mcpSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		result = append(result, session)
	}
	onEvict := s.onEvict
	s.mu.Unlock()
	if onEvict != nil && len(evicted) > 0 {
		onEvict(evicted)
	}
	return result
}

func (s *sessionStore) removeExpiredLocked(now time.Time) []mcpSession {
	removed := make([]mcpSession, 0)
	for id, session := range s.sessions {
		if !now.Before(session.LastSeen.Add(s.ttl)) {
			delete(s.sessions, id)
			removed = append(removed, session)
		}
	}
	return removed
}

func (s *sessionStore) evictOldestLocked() (mcpSession, bool) {
	if len(s.sessions) == 0 {
		return mcpSession{}, false
	}
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	oldest := ids[0]
	for _, id := range ids[1:] {
		candidate := s.sessions[id]
		current := s.sessions[oldest]
		if candidate.LastSeen.Before(current.LastSeen) {
			oldest = id
		}
	}
	removed := s.sessions[oldest]
	delete(s.sessions, oldest)
	return removed, true
}
