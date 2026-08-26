package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/approvalview"
	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/replay"
	"github.com/bkcarlos/remote_agent/internal/requestmeta"
	"github.com/bkcarlos/remote_agent/internal/transportauth"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

const (
	headerBridgeID      = transportauth.HeaderBridgeID
	headerSessionID     = transportauth.HeaderSessionID
	headerClientRequest = transportauth.HeaderClientRequest

	defaultControlMaxConcurrency = 64
	defaultRateLimitBucketTTL    = 10 * time.Minute
	defaultRateLimitMaxBuckets   = 4096

	DefaultEndpoint = "/mcp"
	directBridgeID  = "streamable-http"

	ApprovalModeServerToken   = "server_token"
	ApprovalModeClientManaged = "client_managed"
)

var absolutePathRE = regexp.MustCompile(`(^|[\s:])(?:/[A-Za-z0-9._-]+){2,}`)

type Config struct {
	AuthToken                      string
	AuthPrincipal                  string
	TokenValidator                 TokenValidator
	Authenticator                  Authenticator
	ApprovalKey                    []byte
	ApprovalMode                   string
	NetworkExecutor                NetworkExecutor
	NetworkProfiles                map[string]networkworker.Profile
	RemoteExecutor                 RemoteExecutor
	ExecExecutor                   ExecExecutor
	ExecProfiles                   map[string]execworker.TaskProfile
	ExecSigner                     *execworker.CapabilitySigner
	ExecCloser                     ExecutorCloser
	MaxBodyBytes                   int64
	Transport                      string
	VerifyOptionalRequestSignature bool
	RequireRequestSignature        bool
	AllowLegacySignedSession       bool
	ReplayStore                    replay.ChallengeStore
	AllowedOrigins                 []string
	SessionTTL                     time.Duration
	MaxSessions                    int
	MaxConcurrency                 int
	ControlMaxConcurrency          int
	RateLimitPerSecond             float64
	RateLimitBurst                 int
	RateLimitBucketTTL             time.Duration
	RateLimitMaxBuckets            int
	ClientID                       string
	UserID                         string
	WorkspaceID                    string
	WorkspaceReadOnly              bool
	PolicyVersion                  string
	SecurityDegraded               bool
	SecurityDegradationReason      string
	SecurityDegradationFields      []string
	Now                            func() time.Time
}

type Server struct {
	cfg              Config
	fs               ContextExecutor
	policy           *policy.Engine
	audit            *audit.Logger
	signature        *transportauth.Verifier
	tokenValidator   TokenValidator
	authenticator    Authenticator
	approvals        *approval.Manager
	network          NetworkExecutor
	networkProfiles  map[string]networkworker.Profile
	remote           RemoteExecutor
	exec             ExecExecutor
	execWorkerID     string
	execProfiles     map[string]execworker.TaskProfile
	execSigner       *execworker.CapabilitySigner
	execCloser       ExecutorCloser
	sessions         *sessionStore
	toolsByName      map[string]toolSpec
	semaphore        chan struct{}
	controlSemaphore chan struct{}
	rate             *rateLimiter
	lifecycleMu      sync.Mutex
	revoked          bool
	nextRequest      uint64
	requests         map[uint64]context.CancelFunc
	activeMu         sync.Mutex
	active           map[activeRequestKey]context.CancelFunc
}

type activeRequestKey struct {
	AuthPrincipal   string
	BridgeID        string
	SessionID       string
	ClientRequestID string
}

func New(config Config, files any, policies *policy.Engine, logger *audit.Logger) (*Server, error) {
	if config.Authenticator != nil && config.TokenValidator != nil {
		return nil, errors.New("configure either authenticator or token validator, not both")
	}
	if config.Authenticator == nil && config.TokenValidator == nil && config.AuthToken == "" {
		return nil, errors.New("auth token is required when no authenticator or token validator is configured")
	}
	if policies == nil || logger == nil {
		return nil, errors.New("file executor, policy, and audit logger are required")
	}
	if (config.NetworkExecutor != nil && isNilInterface(config.NetworkExecutor)) ||
		(config.RemoteExecutor != nil && isNilInterface(config.RemoteExecutor)) ||
		(config.ExecExecutor != nil && isNilInterface(config.ExecExecutor)) ||
		(config.ExecCloser != nil && isNilInterface(config.ExecCloser)) {
		return nil, errors.New("configured executor must not be a typed nil")
	}
	executor, err := adaptExecutor(files)
	if err != nil {
		return nil, err
	}
	if config.ApprovalMode == "" {
		config.ApprovalMode = ApprovalModeServerToken
	}
	if config.ApprovalMode != ApprovalModeServerToken && config.ApprovalMode != ApprovalModeClientManaged {
		return nil, errors.New("approval mode must be server_token or client_managed")
	}
	if !isNilInterface(config.NetworkExecutor) && len(config.NetworkProfiles) == 0 {
		return nil, errors.New("network profiles are required when the network executor is configured")
	}
	if isNilInterface(config.NetworkExecutor) && len(config.NetworkProfiles) != 0 {
		return nil, errors.New("network executor is required when network profiles are configured")
	}
	execConfigured := !isNilInterface(config.ExecExecutor) || config.ExecSigner != nil || len(config.ExecProfiles) != 0 || !isNilInterface(config.ExecCloser)
	if execConfigured && (isNilInterface(config.ExecExecutor) || config.ExecSigner == nil || len(config.ExecProfiles) == 0) {
		return nil, errors.New("exec executor, signer, and profiles must be configured together")
	}
	if (!isNilInterface(config.NetworkExecutor) || !isNilInterface(config.RemoteExecutor) || !isNilInterface(config.ExecExecutor)) && config.WorkspaceID == "" {
		return nil, errors.New("workspace identity is required for external executors")
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 2 << 20
	}
	config.Transport = "streamable-http"
	if config.MaxConcurrency <= 0 {
		config.MaxConcurrency = 64
	}
	if config.ControlMaxConcurrency <= 0 {
		config.ControlMaxConcurrency = defaultControlMaxConcurrency
	}
	if config.RateLimitPerSecond < 0 {
		return nil, errors.New("rate limit must not be negative")
	}
	if config.RateLimitPerSecond > 0 && config.RateLimitBurst <= 0 {
		config.RateLimitBurst = 100
	}
	if config.RateLimitBucketTTL <= 0 {
		config.RateLimitBucketTTL = defaultRateLimitBucketTTL
	}
	if config.RateLimitMaxBuckets <= 0 {
		config.RateLimitMaxBuckets = defaultRateLimitMaxBuckets
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	for id, profile := range config.NetworkProfiles {
		if id == "" || id != profile.ID || networkworker.ValidateProfile(profile, config.Now().UTC()) != nil {
			return nil, errors.New("network profile map contains an invalid or expired profile")
		}
	}
	for id, profile := range config.ExecProfiles {
		if id == "" || id != profile.Name || profile.Validate() != nil {
			return nil, errors.New("exec profile map contains an invalid profile")
		}
		if config.WorkspaceReadOnly && profile.WorkspaceMode == execworker.WorkspaceReadWrite {
			return nil, errors.New("read-only workspace cannot configure a read-write exec profile")
		}
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = defaultSessionTTL
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	}
	for _, origin := range config.AllowedOrigins {
		if origin == "" || strings.Contains(origin, "*") {
			return nil, errors.New("allowed origins must be non-empty exact origins without wildcards")
		}
	}
	if config.AuthPrincipal == "" && config.AuthToken != "" {
		config.AuthPrincipal = defaultPrincipal(config.AuthToken)
	}
	replayStore := config.ReplayStore
	if replayStore == nil {
		replayStore = replay.NewMemory()
	}
	var approvals *approval.Manager
	if config.ApprovalMode == ApprovalModeServerToken && len(config.ApprovalKey) > 0 {
		approvals, err = approval.NewWithChallengeStore(config.ApprovalKey, replayStore)
		if err != nil {
			return nil, err
		}
	}
	var verifier *transportauth.Verifier
	if config.RequireRequestSignature || config.VerifyOptionalRequestSignature {
		verifier, err = transportauth.NewVerifierWithStore([]byte(config.AuthToken), time.Minute, replayStore)
		if err != nil {
			return nil, err
		}
	}
	tokenValidator := config.TokenValidator
	if tokenValidator == nil && config.Authenticator == nil {
		tokenValidator = staticTokenValidator{token: config.AuthToken, principal: config.AuthPrincipal}
	}
	byName := make(map[string]toolSpec)
	for _, spec := range registry() {
		if !workerConfigured(config, spec.Worker) {
			continue
		}
		if _, duplicate := byName[spec.Name]; duplicate {
			return nil, errors.New("duplicate tool registration")
		}
		byName[spec.Name] = spec
	}
	config.ApprovalKey = append([]byte(nil), config.ApprovalKey...)
	config.NetworkProfiles = cloneNetworkProfiles(config.NetworkProfiles)
	config.ExecProfiles = cloneExecProfiles(config.ExecProfiles)
	config.AllowedOrigins = append([]string(nil), config.AllowedOrigins...)
	config.SecurityDegradationFields = append([]string(nil), config.SecurityDegradationFields...)
	server := &Server{
		cfg: config, fs: executor, policy: policies, audit: logger, signature: verifier,
		tokenValidator: tokenValidator, authenticator: config.Authenticator, approvals: approvals,
		network: config.NetworkExecutor, networkProfiles: config.NetworkProfiles, remote: config.RemoteExecutor,
		exec: config.ExecExecutor, execWorkerID: configuredWorkerID("exec", !isNilInterface(config.ExecExecutor)),
		execProfiles: config.ExecProfiles, execSigner: config.ExecSigner, execCloser: config.ExecCloser,
		sessions:         newSessionStore(config.SessionTTL, config.MaxSessions, config.Now),
		toolsByName:      byName,
		semaphore:        make(chan struct{}, config.MaxConcurrency),
		controlSemaphore: make(chan struct{}, config.ControlMaxConcurrency),
		rate:             newRateLimiterWithLimits(config.RateLimitPerSecond, config.RateLimitBurst, config.Now, config.RateLimitBucketTTL, config.RateLimitMaxBuckets),
		requests:         make(map[uint64]context.CancelFunc),
		active:           make(map[activeRequestKey]context.CancelFunc),
	}
	server.sessions.onEvict = server.evictSessions
	return server, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, requestNumber, admitted := s.admit(r.Context())
	if !admitted {
		http.NotFound(w, r)
		return
	}
	defer s.finishRequest(requestNumber)
	r = r.WithContext(ctx)

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if !s.originAllowed(r.Header.Get("Origin")) {
		writeHTTPError(w, http.StatusForbidden, "origin is not allowed")
		return
	}
	if !acceptable(r.Header.Values("Accept")) {
		writeHTTPError(w, http.StatusNotAcceptable, "Accept must allow application/json or text/event-stream")
		return
	}
	principal, err := s.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeHTTPError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err := s.verifyNonPostRequest(w, r); err != nil {
			return
		}
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	case http.MethodPost:
		s.servePost(w, r, principal)
	case http.MethodDelete:
		s.serveDelete(w, r, principal)
	default:
		if err := s.verifyNonPostRequest(w, r); err != nil {
			return
		}
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) servePost(w http.ResponseWriter, r *http.Request, principal string) {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		writeRPC(w, http.StatusUnsupportedMediaType, protocol.Failure(nil, -32600, "Content-Type must be application/json", nil))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		writeRPC(w, http.StatusRequestEntityTooLarge, protocol.Failure(nil, -32700, "request body exceeds limit", nil))
		return
	}
	signatureVerified, err := s.verifyRequestSignature(r, body)
	if err != nil {
		writeRPC(w, http.StatusUnauthorized, protocol.Failure(nil, -32001, "request signature rejected", nil))
		return
	}
	var request protocol.Request
	if err := protocol.DecodeStrict(body, &request); err != nil {
		writeRPC(w, http.StatusBadRequest, protocol.Failure(nil, -32700, "invalid JSON-RPC request", nil))
		return
	}

	requestID := newID("req-")
	w.Header().Set("X-Request-ID", requestID)
	notification := request.IsNotification()
	if request.JSONRPC != protocol.Version || request.Method == "" {
		if notification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeRPC(w, http.StatusOK, protocol.Failure(request.ID, -32600, "invalid request", nil))
		return
	}

	legacySession := request.Method != "initialize" && s.cfg.AllowLegacySignedSession && signatureVerified && len(r.Header.Values(protocol.HeaderSessionID)) == 0 && r.Header.Get(headerSessionID) != ""
	var sessionID string
	if request.Method == "initialize" {
		if notification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if len(r.Header.Values(protocol.HeaderSessionID)) != 0 {
			writeRPC(w, http.StatusBadRequest, protocol.Failure(request.ID, -32600, "initialize must not include Mcp-Session-Id", nil))
			return
		}
		if !validInitializeProtocolHeader(r.Header.Values(protocol.HeaderProtocolVersion)) {
			writeRPC(w, http.StatusBadRequest, protocol.Failure(request.ID, -32600, "unsupported MCP protocol version", nil))
			return
		}
	} else if legacySession {
		sessionID = safeIdentity(r.Header.Get(headerSessionID))
		if sessionID == "" {
			writeRPC(w, http.StatusNotFound, protocol.Failure(request.ID, -32001, "legacy signed session is missing", nil))
			return
		}
	} else {
		sessionID = safeIdentity(r.Header.Get(protocol.HeaderSessionID))
		if sessionID == "" {
			writeRPC(w, http.StatusNotFound, protocol.Failure(request.ID, -32001, errSessionNotFound.Error(), nil))
			return
		}
		protocolVersion, present := explicitProtocolHeader(r.Header.Values(protocol.HeaderProtocolVersion))
		if !present {
			writeRPC(w, http.StatusBadRequest, protocol.Failure(request.ID, -32600, errSessionProtocolVersion.Error(), nil))
			return
		}
		_, sessionErr := s.sessions.validateAndTouch(sessionID, principal, protocolVersion)
		if errors.Is(sessionErr, errSessionProtocolVersion) {
			writeRPC(w, http.StatusBadRequest, protocol.Failure(request.ID, -32600, errSessionProtocolVersion.Error(), nil))
			return
		}
		if sessionErr != nil {
			writeRPC(w, http.StatusNotFound, protocol.Failure(request.ID, -32001, errSessionNotFound.Error(), nil))
			return
		}
	}

	remoteIP := clientIP(r.RemoteAddr)
	identity := requestmeta.Scope{
		RequestID: requestID, BridgeID: directBridgeID, SessionID: sessionID,
		ClientRequestID: rpcIDString(request.ID), AuthPrincipal: principal, RemoteIP: remoteIP,
	}
	if legacySession {
		identity.BridgeID = safeIdentity(r.Header.Get(headerBridgeID))
		if notification {
			identity.ClientRequestID = safeIdentity(r.Header.Get(headerClientRequest))
		} else {
			identity.ClientRequestID = rpcIDString(request.ID)
		}
	}
	if request.Method == "tools/call" {
		if message := invalidActiveIdentity(request, identity, notification); message != "" {
			if notification {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			writeRPC(w, http.StatusOK, protocol.Failure(request.ID, -32602, message, nil))
			return
		}
	}

	ctx := requestmeta.WithScope(r.Context(), identity)
	if notification && request.Method == "notifications/cancelled" {
		select {
		case s.controlSemaphore <- struct{}{}:
			defer func() { <-s.controlSemaphore }()
		default:
			writeHTTPError(w, http.StatusServiceUnavailable, "gateway control concurrency limit reached")
			return
		}
		s.dispatch(ctx, request)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	subject := principal + "|" + remoteIP
	if !s.rate.allow(subject) {
		w.Header().Set("Retry-After", "1")
		writeHTTPError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	default:
		writeHTTPError(w, http.StatusServiceUnavailable, "gateway concurrency limit reached")
		return
	}

	if request.Method == "initialize" {
		response := s.dispatch(ctx, request)
		if response.Error != nil {
			writeRPC(w, http.StatusOK, response)
			return
		}
		session, createErr := s.createSession(principal, protocol.ProtocolVersion20250326)
		if errors.Is(createErr, errServerRevoked) {
			http.NotFound(w, r)
			return
		}
		if createErr != nil {
			writeRPC(w, http.StatusInternalServerError, protocol.Failure(request.ID, -32603, "could not create MCP session", nil))
			return
		}
		w.Header().Set(protocol.HeaderSessionID, session.ID)
		writeRPC(w, http.StatusOK, response)
		return
	}
	if request.Method == "tools/call" && !notification {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		key := activeKey(identity)
		if !s.registerActive(key, cancel) {
			cancel()
			writeRPC(w, http.StatusOK, protocol.Failure(request.ID, -32600, "duplicate in-flight request id", nil))
			return
		}
		defer func() { s.removeActive(key); cancel() }()
	}
	response := s.dispatch(ctx, request)
	if notification {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeRPC(w, http.StatusOK, response)
}

func (s *Server) verifyNonPostRequest(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeHTTPError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
		return err
	}
	if _, err := s.verifyRequestSignature(r, body); err != nil {
		writeHTTPError(w, http.StatusUnauthorized, "request signature rejected")
		return err
	}
	return nil
}

func (s *Server) serveDelete(w http.ResponseWriter, r *http.Request, principal string) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeHTTPError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
		return
	}
	if _, err := s.verifyRequestSignature(r, body); err != nil {
		writeHTTPError(w, http.StatusUnauthorized, "request signature rejected")
		return
	}
	protocolVersion, present := explicitProtocolHeader(r.Header.Values(protocol.HeaderProtocolVersion))
	if !present {
		writeHTTPError(w, http.StatusBadRequest, errSessionProtocolVersion.Error())
		return
	}
	sessionID := safeIdentity(r.Header.Get(protocol.HeaderSessionID))
	if sessionID == "" {
		writeHTTPError(w, http.StatusNotFound, errSessionNotFound.Error())
		return
	}
	_, revokeErr := s.sessions.markRevoking(sessionID, principal, protocolVersion)
	if errors.Is(revokeErr, errSessionProtocolVersion) {
		writeHTTPError(w, http.StatusBadRequest, errSessionProtocolVersion.Error())
		return
	}
	if revokeErr != nil {
		writeHTTPError(w, http.StatusNotFound, errSessionNotFound.Error())
		return
	}
	s.terminateActive(principal, sessionID)
	if err := s.revokeExecSessionWithTimeout(principal, sessionID); err != nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "session revocation is temporarily unavailable")
		return
	}
	s.sessions.deleteRevoked(sessionID, principal)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) verifyRequestSignature(r *http.Request, body []byte) (bool, error) {
	headers := transportauth.Headers{
		Timestamp: r.Header.Get(transportauth.HeaderTimestamp),
		Nonce:     r.Header.Get(transportauth.HeaderNonce),
		Signature: r.Header.Get(transportauth.HeaderSignature),
	}
	present := headers.Timestamp != "" || headers.Nonce != "" || headers.Signature != ""
	if !present && !s.cfg.RequireRequestSignature {
		return false, nil
	}
	if s.signature == nil {
		return false, errors.New("request signature verification is not configured")
	}
	if err := s.signature.VerifyRequest(r, body, headers); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	for _, allowed := range s.cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func acceptable(values []string) bool {
	if len(values) == 0 {
		return true
	}
	type preference struct {
		quality     float64
		specificity int
		set         bool
	}
	preferences := map[string]preference{
		"application/json":  {},
		"text/event-stream": {},
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			mediaType = strings.ToLower(mediaType)
			if mediaType != "application/json" && mediaType != "text/event-stream" && mediaType != "*/*" {
				continue
			}
			quality := 1.0
			if raw, exists := params["q"]; exists {
				quality, err = strconv.ParseFloat(raw, 64)
				if err != nil || math.IsNaN(quality) || math.IsInf(quality, 0) || quality < 0 || quality > 1 {
					continue
				}
			}
			specificity := 1
			if mediaType == "*/*" {
				specificity = 0
			}
			for target, current := range preferences {
				if mediaType != "*/*" && mediaType != target {
					continue
				}
				if !current.set || specificity > current.specificity || (specificity == current.specificity && quality > current.quality) {
					preferences[target] = preference{quality: quality, specificity: specificity, set: true}
				}
			}
		}
	}
	return preferences["application/json"].quality > 0 || preferences["text/event-stream"].quality > 0
}

func validInitializeProtocolHeader(values []string) bool {
	if len(values) == 0 {
		return true
	}
	return len(values) == 1 && safeProtocolVersion(values[0])
}

func explicitProtocolHeader(values []string) (string, bool) {
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func safeProtocolVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for i := 0; i < len(version); i++ {
		char := version[i]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func writeHTTPError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func writeRPC(w http.ResponseWriter, status int, response protocol.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func newID(prefix string) string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
	}
	return prefix + hex.EncodeToString(value)
}

func (s *Server) dispatch(ctx context.Context, request protocol.Request) protocol.Response {
	switch request.Method {
	case "initialize":
		var params protocol.InitializeParams
		if protocol.DecodeStrict(request.Params, &params) != nil ||
			!safeProtocolVersion(params.ProtocolVersion) || params.Capabilities == nil ||
			strings.TrimSpace(params.ClientInfo.Name) == "" || strings.TrimSpace(params.ClientInfo.Version) == "" {
			return protocol.Failure(request.ID, -32602, "invalid initialize parameters", nil)
		}
		return protocol.Success(request.ID, map[string]any{"protocolVersion": protocol.ProtocolVersion20250326, "serverInfo": map[string]string{"name": "secure-remote-agent", "version": "0.2.0"}, "capabilities": map[string]any{"tools": map[string]any{}}})
	case "notifications/initialized":
		return protocol.Success(request.ID, map[string]any{})
	case "notifications/cancelled":
		s.cancelNotification(ctx, request.Params)
		return protocol.Success(request.ID, map[string]any{})
	case "tools/list":
		return protocol.Success(request.ID, map[string]any{"tools": s.tools()})
	case "tools/call":
		return s.call(ctx, request)
	default:
		return protocol.Failure(request.ID, -32601, "method not found", nil)
	}
}

func invalidActiveIdentity(request protocol.Request, identity requestmeta.Scope, notification bool) string {
	if identity.AuthPrincipal == "" {
		return "authenticated principal is required for tool calls"
	}
	if identity.BridgeID == "" {
		return "transport identity is required for tool calls"
	}
	if identity.SessionID == "" {
		return "MCP session is required for tool calls"
	}
	if identity.ClientRequestID == "" {
		return "JSON-RPC request id is required for tool calls"
	}
	if !notification {
		expected := rpcIDString(request.ID)
		if expected == "" || identity.ClientRequestID != expected {
			return "client request identity must match the JSON-RPC request id"
		}
	}
	return ""
}

func activeKey(identity requestmeta.Scope) activeRequestKey {
	return activeRequestKey{
		AuthPrincipal: identity.AuthPrincipal, BridgeID: identity.BridgeID,
		SessionID: identity.SessionID, ClientRequestID: identity.ClientRequestID,
	}
}

func (s *Server) registerActive(key activeRequestKey, cancel context.CancelFunc) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if _, exists := s.active[key]; exists {
		return false
	}
	s.active[key] = cancel
	return true
}

func (s *Server) removeActive(key activeRequestKey) {
	s.activeMu.Lock()
	delete(s.active, key)
	s.activeMu.Unlock()
}

func (s *Server) terminateActive(principal, sessionID string) {
	s.activeMu.Lock()
	cancels := make([]context.CancelFunc, 0)
	for key, cancel := range s.active {
		if key.AuthPrincipal == principal && key.SessionID == sessionID {
			cancels = append(cancels, cancel)
		}
	}
	s.activeMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (s *Server) cancelNotification(ctx context.Context, raw json.RawMessage) {
	meta, _ := requestmeta.FromContext(ctx)
	if meta.AuthPrincipal == "" || meta.BridgeID == "" || meta.SessionID == "" {
		return
	}
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if protocol.DecodeStrict(raw, &params) != nil || len(params.RequestID) == 0 {
		return
	}
	targetID := rpcIDString(params.RequestID)
	if targetID == "" {
		return
	}
	key := activeRequestKey{AuthPrincipal: meta.AuthPrincipal, BridgeID: meta.BridgeID, SessionID: meta.SessionID, ClientRequestID: targetID}
	s.activeMu.Lock()
	cancel := s.active[key]
	s.activeMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func rpcIDString(id json.RawMessage) string {
	decoder := json.NewDecoder(bytes.NewReader(id))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return ""
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ""
	}
	switch value.(type) {
	case string, json.Number, nil:
	default:
		return ""
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return safeIdentity(string(canonical))
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) call(ctx context.Context, request protocol.Request) protocol.Response {
	meta, _ := requestmeta.FromContext(ctx)
	if meta.SessionID == "" {
		return protocol.Failure(request.ID, -32602, "MCP session is required for tool calls", nil)
	}
	var params callParams
	if protocol.DecodeStrict(request.Params, &params) != nil || params.Name == "" || len(params.Name) > 64 {
		return protocol.Failure(request.ID, -32602, "invalid tool parameters", nil)
	}
	spec, registered := s.toolsByName[params.Name]
	if !registered {
		return protocol.Failure(request.ID, -32602, "unknown tool", nil)
	}
	if externalApprovalBlocked(s.cfg.ApprovalMode, spec) {
		return toolError(request.ID, externalServerApprovalError, "deny-external-server-approval-unimplemented")
	}
	arguments, err := spec.Decode(params.Arguments)
	if err != nil {
		return protocol.Failure(request.ID, -32602, "invalid tool arguments", nil)
	}
	if err := s.validateAndNormalize(spec, &arguments); err != nil {
		return protocol.Failure(request.ID, -32602, err.Error(), nil)
	}
	paths := argumentPaths(arguments)
	decision := s.policy.Evaluate(policyOperation(spec.Name), "policy-probe.txt")
	for _, path := range paths {
		decision = s.policy.Evaluate(policyOperation(spec.Name), path)
		if !decision.Allowed {
			break
		}
	}
	meta.PolicyID, meta.PolicyDecision = decision.PolicyID, mapDecision(decision)
	meta.ApprovalRequired = serverApprovalRequired(s.cfg.ApprovalMode, spec)
	ctx = requestmeta.WithScope(ctx, meta)
	summary, summaryErr := summarizeToolParameters(spec.Name, params.Arguments)
	if summaryErr != nil {
		return toolError(request.ID, "parameter audit summary failed", decision.PolicyID)
	}
	event := audit.Event{
		RequestID: meta.RequestID, ClientRequestID: meta.ClientRequestID,
		ClientID: s.cfg.ClientID, UserID: s.cfg.UserID, SessionID: meta.SessionID,
		AuthPrincipal: meta.AuthPrincipal, BridgeInstanceID: meta.BridgeID, RemoteIP: meta.RemoteIP,
		Transport: s.cfg.Transport, Tool: spec.Name, ParameterSummary: &summary,
		WorkspaceID: s.cfg.WorkspaceID, Path: auditPath(paths), PolicyID: decision.PolicyID,
		PolicyVersion: s.cfg.PolicyVersion, PolicyDecision: mapDecision(decision),
		Allowed: decision.Allowed, ApprovalRequired: serverApprovalRequired(s.cfg.ApprovalMode, spec),
		ApprovalMode: s.cfg.ApprovalMode, ApprovalVerified: false, ApprovalSource: approvalSource(s.cfg.ApprovalMode),
		StartedAt:                 s.cfg.Now().UTC(),
		SecurityDegraded:          s.cfg.SecurityDegraded,
		SecurityDegradationReason: s.cfg.SecurityDegradationReason,
		SecurityDegradationFields: append([]string(nil), s.cfg.SecurityDegradationFields...),
	}
	if !decision.Allowed {
		event.Status = "denied"
		_ = s.audit.Record(event)
		return toolError(request.ID, decision.Reason, decision.PolicyID)
	}
	ctx = withWorkerExecutionScope(ctx, WorkerExecutionScope{
		RequestID: meta.RequestID, Principal: meta.AuthPrincipal, WorkspaceID: s.cfg.WorkspaceID,
		BridgeID: meta.BridgeID, SessionID: meta.SessionID, ClientRequestID: meta.ClientRequestID,
		PolicyID: decision.PolicyID, AuditID: meta.RequestID, Worker: spec.Worker,
	})
	if spec.Worker != "file" {
		return s.callExternal(ctx, request.ID, spec, arguments, event)
	}
	if spec.Approval {
		return s.callWrite(ctx, request.ID, spec, arguments, event)
	}
	workerRequest := s.workerRequest(spec.Name, arguments)
	workerRequest.TokenID = newID("cap-")
	result, executeErr := s.fs.Execute(ctx, workerRequest)
	event.TokenID, event.WorkerID = result.TokenID, result.WorkerID
	if executeErr != nil {
		event.Status = statusForError(executeErr)
		_ = s.audit.Record(event)
		return toolError(request.ID, safeToolError(executeErr), decision.PolicyID)
	}
	if spec.Name == "read_image" {
		if err := validateImageResponse(result); err != nil {
			event.Status = "error"
			_ = s.audit.Record(event)
			return toolError(request.ID, "image worker returned an invalid response", decision.PolicyID)
		}
	}
	event.Status = "success"
	event.OutputBytes = responseBytes(result)
	_ = s.audit.Record(event)
	if spec.Name == "read_image" {
		return imageToolSuccess(request.ID, result)
	}
	return toolSuccess(request.ID, publicResult(spec.Name, result))
}

func (s *Server) callWrite(ctx context.Context, id json.RawMessage, spec toolSpec, arguments toolArguments, event audit.Event) protocol.Response {
	meta, _ := requestmeta.FromContext(ctx)
	if s.cfg.ApprovalMode == ApprovalModeServerToken && s.approvals == nil {
		event.Status = "error"
		_ = s.audit.Record(event)
		return toolError(id, "trusted approval service is not configured", event.PolicyID)
	}
	if spec.Name == "write_file" {
		return s.callLegacyWrite(ctx, id, spec.Risk, arguments, event)
	}
	preflight := s.workerRequest(spec.Name, arguments)
	preflight.Apply = false
	preflight.Targets = nil
	preflight.TokenID = newID("cap-")
	preview, err := s.fs.Execute(ctx, preflight)
	if err != nil {
		event.TokenID, event.WorkerID, event.Status = preview.TokenID, preview.WorkerID, statusForError(err)
		_ = s.audit.Record(event)
		return toolError(id, safeToolError(err), event.PolicyID)
	}
	targets := approvalTargets(preview.Files)
	if len(targets) == 0 {
		event.Status = "error"
		_ = s.audit.Record(event)
		return toolError(id, "edit preflight returned no targets", event.PolicyID)
	}
	if !arguments.Apply {
		claims := approval.Claims{ApprovalID: newID("approval-"), SessionID: meta.SessionID, Operation: spec.Name, Targets: targets, ExpiresAt: s.cfg.Now().UTC().Add(5 * time.Minute)}
		review, reviewSHA256, reviewErr := buildApprovalReview(claims, spec.Risk, preview.Files)
		if reviewErr != nil {
			event.TokenID, event.WorkerID, event.Status = preview.TokenID, preview.WorkerID, "error"
			_ = s.audit.Record(event)
			return toolError(id, safeToolError(reviewErr), event.PolicyID)
		}
		claims.ReviewSHA256 = reviewSHA256
		if s.cfg.ApprovalMode == ApprovalModeServerToken {
			if err := s.approvals.RegisterChallenge(claims); err != nil {
				event.Status = "error"
				_ = s.audit.Record(event)
				return toolError(id, "approval challenge storage unavailable", event.PolicyID)
			}
		}
		event.TokenID, event.WorkerID, event.Status = preview.TokenID, preview.WorkerID, "success"
		event.BeforeHash, event.AfterHash = aggregateApprovalHashes(targets)
		attachReviewDigest(&event, reviewSHA256)
		_ = s.audit.Record(event)
		return toolSuccess(id, map[string]any{"dry_run": true, "files": preview.Files, "approval_targets": targets, "approval_review": review, "review_sha256": reviewSHA256, "approval_required": s.cfg.ApprovalMode == ApprovalModeServerToken, "approval_mode": s.cfg.ApprovalMode, "approval_id": claims.ApprovalID, "challenge_id": claims.ApprovalID, "approval_expires_at": claims.ExpiresAt, "session_id": meta.SessionID, "operation": spec.Name, "token_id": preview.TokenID, "worker_id": preview.WorkerID})
	}
	if s.cfg.ApprovalMode == ApprovalModeClientManaged {
		return s.applyClientManagedEdit(ctx, id, spec, arguments, event, preview, targets)
	}
	untrusted, err := untrustedApprovalClaims(arguments.ApprovalToken)
	if err != nil {
		event.WorkerID, event.Status = preview.WorkerID, "denied"
		_ = s.audit.Record(event)
		return toolError(id, "valid trusted approval is required", event.PolicyID)
	}
	reviewClaims := approval.Claims{ApprovalID: untrusted.ApprovalID, ChallengeID: untrusted.ChallengeID, SessionID: meta.SessionID, Operation: spec.Name, Targets: targets, ExpiresAt: untrusted.ExpiresAt}
	_, reviewSHA256, reviewErr := buildApprovalReview(reviewClaims, spec.Risk, preview.Files)
	if reviewErr != nil {
		event.WorkerID, event.Status = preview.WorkerID, "error"
		_ = s.audit.Record(event)
		return toolError(id, safeToolError(reviewErr), event.PolicyID)
	}
	attachReviewDigest(&event, reviewSHA256)
	apply := s.workerRequest(spec.Name, arguments)
	apply.Apply = true
	apply.Targets = workerTargets(targets)
	apply.TokenID = newID("cap-")
	event.TokenID = apply.TokenID
	event.BeforeHash, event.AfterHash = aggregateApprovalHashes(targets)
	event.InputBytes = totalAfterBytes(preview.Files)
	scope := approval.Scope{SessionID: meta.SessionID, Operation: spec.Name, Targets: targets, ReviewSHA256: reviewSHA256}
	inspected, err := s.approvals.Inspect(arguments.ApprovalToken, scope)
	if err != nil {
		event.WorkerID, event.Status = preview.WorkerID, "denied"
		_ = s.audit.Record(event)
		return toolError(id, "valid trusted approval is required: "+safeToolError(err), event.PolicyID)
	}
	event.ApprovalID, event.Approver, event.Approved, event.ApprovalVerified = inspected.ApprovalID, inspected.Approver, true, true
	transaction, auditErr := s.audit.Prewrite(event)
	if auditErr != nil {
		return toolError(id, "audit unavailable; write denied", event.PolicyID)
	}
	approved, err := s.approvals.Verify(arguments.ApprovalToken, scope)
	if err != nil {
		finishErr := transaction.Complete("denied", func(done *audit.Event) {
			done.WorkerID = preview.WorkerID
		})
		if finishErr != nil {
			return toolError(id, "audit unavailable; approval denial cannot be confirmed", event.PolicyID)
		}
		return toolError(id, "valid trusted approval is required: "+safeToolError(err), event.PolicyID)
	}
	// Execute is synchronous. Commit executors honor cancellation before launch,
	// then run under their own hard bound; the gateway intentionally waits here
	// so audit completion and any returned result describe the final batch state.
	result, executeErr := s.fs.Execute(ctx, apply)
	status := "success"
	if executeErr != nil {
		status = statusForError(executeErr)
	}
	finishErr := transaction.Complete(status, func(done *audit.Event) {
		done.TokenID, done.WorkerID, done.OutputBytes = result.TokenID, result.WorkerID, responseBytes(result)
		done.ApprovalID, done.Approver, done.Approved, done.ApprovalVerified = approved.ApprovalID, approved.Approver, true, true
	})
	if executeErr != nil {
		return toolError(id, safeToolError(executeErr), event.PolicyID)
	}
	if finishErr != nil {
		return toolError(id, "audit unavailable; write result cannot be confirmed", event.PolicyID)
	}
	return toolSuccess(id, publicResult(spec.Name, result))
}

func (s *Server) callLegacyWrite(ctx context.Context, id json.RawMessage, risk string, arguments toolArguments, event audit.Event) protocol.Response {
	meta, _ := requestmeta.FromContext(ctx)
	after := digest([]byte(arguments.Content))
	checksumRequest := fileworker.Request{Operation: "checksum", Path: arguments.Path, TokenID: newID("cap-")}
	current, checksumErr := s.fs.Execute(ctx, checksumRequest)
	before := current.Checksum
	if checksumErr != nil {
		if !errors.Is(checksumErr, workspace.ErrNotFound) {
			event.Status = "error"
			_ = s.audit.Record(event)
			return toolError(id, safeToolError(checksumErr), event.PolicyID)
		}
		before = ""
	}
	target := approval.Target{Path: arguments.Path, BeforeSHA256: before, AfterSHA256: after}
	writePreview := writeReviewFile(arguments, target)
	if !arguments.Apply {
		claims := approval.Claims{ApprovalID: newID("approval-"), SessionID: meta.SessionID, Operation: "write_file", Targets: []approval.Target{target}, ExpiresAt: s.cfg.Now().UTC().Add(5 * time.Minute)}
		review, reviewSHA256, reviewErr := buildApprovalReview(claims, risk, []fileworker.FileResult{writePreview})
		if reviewErr != nil {
			event.Status = "error"
			_ = s.audit.Record(event)
			return toolError(id, safeToolError(reviewErr), event.PolicyID)
		}
		claims.ReviewSHA256 = reviewSHA256
		if s.cfg.ApprovalMode == ApprovalModeServerToken {
			if err := s.approvals.RegisterChallenge(claims); err != nil {
				event.Status = "error"
				_ = s.audit.Record(event)
				return toolError(id, "approval challenge storage unavailable", event.PolicyID)
			}
		}
		event.TokenID, event.WorkerID, event.BeforeHash, event.AfterHash, event.Status = current.TokenID, current.WorkerID, before, after, "success"
		attachReviewDigest(&event, reviewSHA256)
		_ = s.audit.Record(event)
		return toolSuccess(id, map[string]any{"dry_run": true, "path": arguments.Path, "before_sha256": before, "after_sha256": after, "content_sha256": after, "approval_targets": []approval.Target{target}, "approval_review": review, "review_sha256": reviewSHA256, "bytes": len(arguments.Content), "approval_required": s.cfg.ApprovalMode == ApprovalModeServerToken, "approval_mode": s.cfg.ApprovalMode, "approval_id": claims.ApprovalID, "challenge_id": claims.ApprovalID, "approval_expires_at": claims.ExpiresAt, "session_id": meta.SessionID, "operation": "write_file"})
	}
	if before != "" && arguments.ExpectedHash == "" {
		event.Status = "denied"
		_ = s.audit.Record(event)
		return toolError(id, "expected_hash is required when replacing an existing file", event.PolicyID)
	}
	if arguments.ExpectedHash != before {
		event.Status = "denied"
		_ = s.audit.Record(event)
		return toolError(id, "expected_hash does not match preflight", event.PolicyID)
	}
	if s.cfg.ApprovalMode == ApprovalModeClientManaged {
		return s.applyClientManagedWrite(ctx, id, arguments, event, before, after)
	}
	untrusted, err := untrustedApprovalClaims(arguments.ApprovalToken)
	if err != nil {
		event.WorkerID, event.Status = current.WorkerID, "denied"
		_ = s.audit.Record(event)
		return toolError(id, "valid trusted approval is required", event.PolicyID)
	}
	reviewClaims := approval.Claims{ApprovalID: untrusted.ApprovalID, ChallengeID: untrusted.ChallengeID, SessionID: meta.SessionID, Operation: "write_file", Targets: []approval.Target{target}, ExpiresAt: untrusted.ExpiresAt}
	_, reviewSHA256, reviewErr := buildApprovalReview(reviewClaims, risk, []fileworker.FileResult{writePreview})
	if reviewErr != nil {
		event.WorkerID, event.Status = current.WorkerID, "error"
		_ = s.audit.Record(event)
		return toolError(id, safeToolError(reviewErr), event.PolicyID)
	}
	attachReviewDigest(&event, reviewSHA256)
	request := fileworker.Request{Operation: "write_file", Path: arguments.Path, Data: []byte(arguments.Content), ExpectedHash: before, MaxBytes: s.policy.MaxWriteBytes(), TokenID: newID("cap-")}
	event.TokenID, event.BeforeHash, event.AfterHash, event.InputBytes = request.TokenID, before, after, int64(len(arguments.Content))
	scope := approval.Scope{SessionID: meta.SessionID, Operation: "write_file", Targets: []approval.Target{target}, ReviewSHA256: reviewSHA256}
	inspected, err := s.approvals.Inspect(arguments.ApprovalToken, scope)
	if err != nil {
		event.WorkerID, event.Status = current.WorkerID, "denied"
		_ = s.audit.Record(event)
		return toolError(id, "valid trusted approval is required: "+safeToolError(err), event.PolicyID)
	}
	event.ApprovalID, event.Approver, event.Approved, event.ApprovalVerified = inspected.ApprovalID, inspected.Approver, true, true
	transaction, auditErr := s.audit.Prewrite(event)
	if auditErr != nil {
		return toolError(id, "audit unavailable; write denied", event.PolicyID)
	}
	approved, err := s.approvals.Verify(arguments.ApprovalToken, scope)
	if err != nil {
		finishErr := transaction.Complete("denied", func(done *audit.Event) {
			done.WorkerID = current.WorkerID
		})
		if finishErr != nil {
			return toolError(id, "audit unavailable; approval denial cannot be confirmed", event.PolicyID)
		}
		return toolError(id, "valid trusted approval is required: "+safeToolError(err), event.PolicyID)
	}
	// As with batch edits, wait for an already-started bounded commit even if the
	// client disconnects; the response may be undeliverable, but audit completion
	// must reflect the final worker result.
	result, executeErr := s.fs.Execute(ctx, request)
	status := "success"
	if executeErr != nil {
		status = statusForError(executeErr)
	}
	finishErr := transaction.Complete(status, func(done *audit.Event) {
		done.TokenID, done.WorkerID, done.AfterHash = result.TokenID, result.WorkerID, result.Checksum
		done.ApprovalID, done.Approver, done.Approved, done.ApprovalVerified = approved.ApprovalID, approved.Approver, true, true
	})
	if executeErr != nil {
		return toolError(id, safeToolError(executeErr), event.PolicyID)
	}
	if finishErr != nil {
		return toolError(id, "audit unavailable; write result cannot be confirmed", event.PolicyID)
	}
	return toolSuccess(id, map[string]any{"written": true, "sha256": result.Checksum, "token_id": result.TokenID, "worker_id": result.WorkerID})
}

func (s *Server) validateAndNormalize(spec toolSpec, arguments *toolArguments) error {
	if spec.Worker != "file" {
		return s.validateExternalArguments(spec, arguments)
	}
	if arguments.Path == "" && spec.Name != "multi_read" && spec.Name != "multi_edit" {
		return errors.New("path must contain 1 to 4096 bytes")
	}
	if len(arguments.ApprovalToken) > 32768 || len(arguments.Pattern) > 1024 || len(arguments.Query) > 1024 {
		return errors.New("tool argument exceeds its length limit")
	}
	if (arguments.StartLine == 0) != (arguments.EndLine == 0) || arguments.StartLine < 0 || arguments.EndLine < 0 || arguments.StartLine > arguments.EndLine || (arguments.StartLine > 0 && arguments.EndLine-arguments.StartLine+1 > fileworker.MaxLineRange) {
		return errors.New("start_line and end_line must form a range of at most 10000 lines")
	}
	if spec.Name != "read_file" && (arguments.StartLine != 0 || arguments.EndLine != 0) {
		return errors.New("line range is only valid for read_file")
	}
	if spec.Name == "glob" && arguments.Pattern == "" {
		return errors.New("glob pattern is required")
	}
	if spec.Name == "grep" && arguments.Query == "" {
		return errors.New("grep query is required")
	}
	if arguments.ExpectedHash != "" && !validSHA256(arguments.ExpectedHash) {
		return errors.New("expected_hash must be a lowercase SHA-256 value")
	}
	if len(arguments.Content) > int(s.policy.MaxWriteBytes()) {
		return errors.New("content exceeds the configured limit")
	}
	if arguments.Path != "" {
		normalized, err := capability.NormalizePath(arguments.Path)
		if err != nil {
			return errors.New("path is invalid")
		}
		arguments.Path = normalized
	}
	if len(arguments.Paths) > 20 {
		return errors.New("maximum file count is 20")
	}
	seen := map[string]bool{}
	for i, path := range arguments.Paths {
		normalized, err := capability.NormalizePath(path)
		if err != nil || seen[normalized] {
			return errors.New("paths must be unique normalized workspace paths")
		}
		seen[normalized] = true
		arguments.Paths[i] = normalized
	}
	if len(arguments.Files) > 20 {
		return errors.New("maximum file count is 20")
	}
	var editBytes int64
	for i := range arguments.Files {
		normalized, err := capability.NormalizePath(arguments.Files[i].Path)
		if err != nil || seen[normalized] {
			return errors.New("edit paths must be unique normalized workspace paths")
		}
		seen[normalized] = true
		arguments.Files[i].Path = normalized
		if len(arguments.Files[i].Edits) == 0 || len(arguments.Files[i].Edits) > 128 {
			return errors.New("each file must contain between 1 and 128 edits")
		}
		for _, edit := range arguments.Files[i].Edits {
			if edit.Old == "" || (edit.Mode != "" && edit.Mode != "once" && edit.Mode != "all") {
				return errors.New("invalid exact edit")
			}
			editBytes += int64(len(edit.Old) + len(edit.New))
		}
	}
	if len(arguments.Edits) > 128 {
		return errors.New("maximum edit count is 128")
	}
	for _, edit := range arguments.Edits {
		if edit.Old == "" || (edit.Mode != "" && edit.Mode != "once" && edit.Mode != "all") {
			return errors.New("invalid exact edit")
		}
		editBytes += int64(len(edit.Old) + len(edit.New))
	}
	if editBytes > s.policy.MaxWriteBytes() {
		return errors.New("edit parameters exceed the configured write limit")
	}
	if spec.Name == "multi_read" && len(arguments.Paths) == 0 {
		return errors.New("paths must contain between 1 and 20 entries")
	}
	if spec.Name == "multi_edit" && len(arguments.Files) == 0 {
		return errors.New("files must contain between 1 and 20 entries")
	}
	if spec.Name == "edit" && len(arguments.Edits) == 0 {
		return errors.New("edits must contain between 1 and 128 entries")
	}
	return nil
}

func (s *Server) workerRequest(operation string, arguments toolArguments) fileworker.Request {
	request := fileworker.Request{Operation: operation, Path: arguments.Path, Paths: arguments.Paths, StartLine: arguments.StartLine, EndLine: arguments.EndLine, Pattern: arguments.Pattern, Query: arguments.Query, ExpectedHash: arguments.ExpectedHash, Edits: arguments.Edits, Files: arguments.Files, Apply: arguments.Apply}
	switch operation {
	case "read_file", "multi_read", "diff":
		request.MaxBytes = s.policy.MaxReadBytes()
	case "grep":
		request.MaxBytes = s.policy.MaxScanBytes()
	case "read_image":
		request.MaxBytes = min64(s.policy.MaxReadBytes(), fileworker.MaxImageBytes)
	case "edit", "multi_edit", "write_file":
		request.MaxBytes = s.policy.MaxWriteBytes()
	case "list_dir":
		request.MaxEntries = 10000
	case "glob":
		request.MaxFiles, request.MaxResults = 10000, 1000
	}
	if operation == "grep" {
		request.MaxFiles, request.MaxResults = 10000, 1000
	}
	if operation == "diff" {
		request.Data = []byte(arguments.Content)
	}
	return request
}

func argumentPaths(arguments toolArguments) []string {
	if arguments.Path != "" {
		return []string{arguments.Path}
	}
	if len(arguments.Paths) > 0 {
		return arguments.Paths
	}
	paths := make([]string, len(arguments.Files))
	for i := range arguments.Files {
		paths[i] = arguments.Files[i].Path
	}
	return paths
}

func (s *Server) tools() []map[string]any {
	registered := registry()
	available := make([]map[string]any, 0, len(registered))
	for _, spec := range registered {
		if _, configured := s.toolsByName[spec.Name]; !configured || externalApprovalBlocked(s.cfg.ApprovalMode, spec) || !s.policy.Evaluate(policyOperation(spec.Name), "policy-probe.txt").Allowed {
			continue
		}
		available = append(available, map[string]any{
			"name": spec.Name, "description": spec.Description, "inputSchema": spec.Schema,
			"annotations": map[string]any{
				"readOnlyHint": spec.ReadOnly, "destructiveHint": spec.Destructive,
				"idempotentHint": spec.Idempotent, "openWorldHint": spec.OpenWorld,
			},
			"risk": spec.Risk, "worker": spec.Worker,
			"approval_required": serverApprovalRequired(s.cfg.ApprovalMode, spec),
			"approval_mode":     s.cfg.ApprovalMode,
		})
	}
	return available
}

func publicResult(operation string, result fileworker.Response) any {
	identity := map[string]any{"token_id": result.TokenID, "worker_id": result.WorkerID}
	switch operation {
	case "read_file":
		identity["content"], identity["bytes"], identity["sha256"] = result.Content, result.Bytes, result.Checksum
		identity["start_line"], identity["end_line"], identity["total_lines"], identity["truncated"] = result.StartLine, result.EndLine, result.TotalLines, result.Truncated
		if result.Metadata != nil {
			identity["encoding"], identity["bom"], identity["newline"], identity["dominant_newline"], identity["confidence"] = result.Metadata.Encoding, result.Metadata.BOM, result.Metadata.Newline, result.Metadata.DominantNewline, result.Metadata.Confidence
		}
	case "read_image":
		identity["bytes"], identity["sha256"], identity["mime_type"] = result.Bytes, result.Checksum, result.MIMEType
		identity["width"], identity["height"] = result.Width, result.Height
	case "multi_read", "edit", "multi_edit":
		identity["files"] = result.Files
	case "list_dir":
		identity["entries"] = result.Entries
	case "checksum":
		identity["sha256"] = result.Checksum
	case "file_info":
		identity["info"] = result.Info
	case "glob":
		identity["paths"], identity["scan"] = result.Paths, result.Scan
	case "grep":
		identity["matches"], identity["scan"] = result.Matches, result.Scan
	case "diff":
		identity["diff"] = result.Diff
		identity["files"] = result.Files
	}
	return identity
}

func toolSuccess(id json.RawMessage, result any) protocol.Response {
	return protocol.Success(id, protocol.ToolResult{Content: []protocol.ToolContent{{Type: "text", Text: mustJSON(result)}}})
}
func imageToolSuccess(id json.RawMessage, result fileworker.Response) protocol.Response {
	metadata := publicResult("read_image", result)
	return protocol.Success(id, protocol.ToolResult{Content: []protocol.ToolContent{
		{Type: "image", Data: result.Base64, MIMEType: result.MIMEType},
		{Type: "text", Text: mustJSON(metadata)},
	}})
}
func toolError(id json.RawMessage, message, policyID string) protocol.Response {
	return protocol.Success(id, protocol.ToolResult{IsError: true, Content: []protocol.ToolContent{{Type: "text", Text: message}}, PolicyID: policyID})
}
func mustJSON(value any) string { encoded, _ := json.Marshal(value); return string(encoded) }
func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func digest(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func policyOperation(operation string) string {
	if operation == "read_image" {
		return "read_file"
	}
	return operation
}
func validateImageResponse(result fileworker.Response) error {
	raw, err := base64.StdEncoding.DecodeString(result.Base64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != result.Base64 {
		return errors.New("invalid image base64")
	}
	validated, err := fileworker.DecodeImage(raw)
	if err != nil || validated.Bytes != result.Bytes || validated.SHA256 != result.Checksum || validated.MIMEType != result.MIMEType || validated.Width != result.Width || validated.Height != result.Height {
		return errors.New("image metadata mismatch")
	}
	return nil
}
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func mapDecision(decision policy.Decision) string {
	if decision.Allowed {
		return "allow"
	}
	return "deny"
}
func auditPath(paths []string) string {
	if len(paths) == 1 {
		return paths[0]
	}
	return ""
}
func statusForError(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	return "error"
}
func safeToolError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "request cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	value := audit.RedactSensitiveValue(err.Error())
	value = absolutePathRE.ReplaceAllString(value, "$1[host-path]")
	if filepath.IsAbs(strings.Trim(value, `"'(),.`)) {
		return "file operation failed"
	}
	return value
}
func safeIdentity(value string) string {
	if len(value) > 256 || strings.TrimSpace(value) == "" {
		return ""
	}
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' || value[i] == 0x7f {
			return ""
		}
	}
	return value
}
func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return host
	}
	if net.ParseIP(remote) != nil {
		return remote
	}
	return "unknown"
}
func responseBytes(result fileworker.Response) int64 {
	if result.Bytes > 0 {
		return int64(result.Bytes)
	}
	encoded, _ := json.Marshal(result)
	return int64(len(encoded))
}
func buildApprovalReview(claims approval.Claims, risk string, files []fileworker.FileResult) (approvalview.View, string, error) {
	dryRun := approvalview.DryRun{Risk: approvalview.Risk(risk), Files: make([]approvalview.DryRunFile, len(files))}
	for i, file := range files {
		encoding, newline := "", ""
		if file.Metadata != nil {
			encoding, newline = file.Metadata.Encoding, file.Metadata.Newline
		}
		dryRun.Files[i] = approvalview.DryRunFile{
			Path: file.Path, BeforeSHA256: file.BeforeSHA256, AfterSHA256: file.AfterSHA256,
			Diff: file.Diff, Encoding: encoding, Newline: newline, Bytes: int64(file.Bytes),
		}
	}
	view, err := approvalview.New(claims, dryRun)
	if err != nil {
		return approvalview.View{}, "", err
	}
	reviewSHA256, err := view.ReviewDigest()
	if err != nil {
		return approvalview.View{}, "", err
	}
	return view, reviewSHA256, nil
}

func writeReviewFile(arguments toolArguments, target approval.Target) fileworker.FileResult {
	return fileworker.FileResult{
		Path: target.Path, Bytes: len(arguments.Content), BeforeSHA256: target.BeforeSHA256,
		AfterSHA256: target.AfterSHA256, Diff: "",
		Metadata: &fileworker.TextMetadata{Encoding: "utf-8", Newline: newlineStyle(arguments.Content)},
	}
}

func newlineStyle(content string) string {
	hasCRLF := strings.Contains(content, "\r\n")
	withoutCRLF := strings.ReplaceAll(content, "\r\n", "")
	hasLF := strings.Contains(withoutCRLF, "\n")
	hasCR := strings.Contains(withoutCRLF, "\r")
	styles := 0
	for _, present := range []bool{hasCRLF, hasLF, hasCR} {
		if present {
			styles++
		}
	}
	if styles > 1 {
		return "mixed"
	}
	if hasCRLF {
		return "crlf"
	}
	if hasLF {
		return "lf"
	}
	if hasCR {
		return "cr"
	}
	return "none"
}

// untrustedApprovalClaims extracts public fields needed to deterministically
// rebuild the review before Manager.Inspect authenticates and binds the token.
// Callers must never authorize from this result.
func untrustedApprovalClaims(token string) (approval.Claims, error) {
	var claims approval.Claims
	if len(token) == 0 || len(token) > 32<<10 {
		return claims, errors.New("invalid approval token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, errors.New("invalid approval token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] || protocol.DecodeStrict(payload, &claims) != nil {
		return approval.Claims{}, errors.New("invalid approval token")
	}
	return claims, nil
}

func attachReviewDigest(event *audit.Event, reviewSHA256 string) {
	if event == nil || event.ParameterSummary == nil || !validSHA256(reviewSHA256) {
		return
	}
	var normalized map[string]json.RawMessage
	if err := json.Unmarshal([]byte(event.ParameterSummary.Normalized), &normalized); err != nil {
		return
	}
	digestJSON, err := json.Marshal(reviewSHA256)
	if err != nil {
		return
	}
	normalized["review_sha256"] = digestJSON
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	summary := *event.ParameterSummary
	summary.Normalized = string(encoded)
	summary.SHA256 = audit.DigestBytes(encoded)
	event.ParameterSummary = &summary
}

func approvalTargets(files []fileworker.FileResult) []approval.Target {
	targets := make([]approval.Target, len(files))
	for i, file := range files {
		targets[i] = approval.Target{Path: file.Path, BeforeSHA256: file.BeforeSHA256, AfterSHA256: file.AfterSHA256}
	}
	return targets
}
func workerTargets(targets []approval.Target) []fileworker.Target {
	out := make([]fileworker.Target, len(targets))
	for i, target := range targets {
		out[i] = fileworker.Target{Path: target.Path, BeforeSHA256: target.BeforeSHA256, AfterSHA256: target.AfterSHA256}
	}
	return out
}
func aggregateApprovalHashes(targets []approval.Target) (string, string) {
	if len(targets) == 1 {
		return targets[0].BeforeSHA256, targets[0].AfterSHA256
	}
	type hashTarget struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	before := make([]hashTarget, len(targets))
	after := make([]hashTarget, len(targets))
	for i, target := range targets {
		before[i] = hashTarget{Path: target.Path, SHA256: target.BeforeSHA256}
		after[i] = hashTarget{Path: target.Path, SHA256: target.AfterSHA256}
	}
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	return digest(beforeJSON), digest(afterJSON)
}
func totalAfterBytes(files []fileworker.FileResult) int64 {
	var total int64
	for _, file := range files {
		total += int64(file.Bytes)
	}
	return total
}

type rateBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type rateLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	now        func() time.Time
	bucketTTL  time.Duration
	maxBuckets int
	buckets    map[string]rateBucket
}

func newRateLimiter(rate float64, burst int, now func() time.Time) *rateLimiter {
	return newRateLimiterWithLimits(rate, burst, now, defaultRateLimitBucketTTL, defaultRateLimitMaxBuckets)
}

func newRateLimiterWithLimits(rate float64, burst int, now func() time.Time, bucketTTL time.Duration, maxBuckets int) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	if bucketTTL <= 0 {
		bucketTTL = defaultRateLimitBucketTTL
	}
	if maxBuckets <= 0 {
		maxBuckets = defaultRateLimitMaxBuckets
	}
	return &rateLimiter{
		rate: rate, burst: float64(burst), now: now,
		bucketTTL: bucketTTL, maxBuckets: maxBuckets, buckets: map[string]rateBucket{},
	}
}

func (l *rateLimiter) allow(subject string) bool {
	if l.rate <= 0 {
		return true
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.removeExpired(now)
	bucket, exists := l.buckets[subject]
	if !exists {
		if len(l.buckets) >= l.maxBuckets {
			l.evictOldest()
		}
		bucket = rateBucket{tokens: l.burst, updated: now}
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * l.rate
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		bucket.updated = now
	}
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		l.buckets[subject] = bucket
		return false
	}
	bucket.tokens--
	l.buckets[subject] = bucket
	return true
}

func (l *rateLimiter) removeExpired(now time.Time) {
	for subject, bucket := range l.buckets {
		if !bucket.lastSeen.Add(l.bucketTTL).After(now) {
			delete(l.buckets, subject)
		}
	}
}

func (l *rateLimiter) evictOldest() {
	var oldestSubject string
	var oldest time.Time
	for subject, bucket := range l.buckets {
		if oldestSubject == "" || bucket.lastSeen.Before(oldest) || (bucket.lastSeen.Equal(oldest) && subject < oldestSubject) {
			oldestSubject, oldest = subject, bucket.lastSeen
		}
	}
	if oldestSubject != "" {
		delete(l.buckets, oldestSubject)
	}
}
