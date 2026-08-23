package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/transportauth"
)

const (
	headerBridgeID         = transportauth.HeaderBridgeID
	headerSessionID        = protocol.HeaderSessionID
	headerProtocolVersion  = protocol.HeaderProtocolVersion
	headerClientRequestID  = transportauth.HeaderClientRequest
	headerGatewayRequestID = "X-Request-ID"

	defaultMCPProtocolVersion = protocol.ProtocolVersion20250326
	maxControlPending         = 8
	overloadErrorCode         = -32000
	overloadMessage           = "bridge overloaded: too many pending requests"
)

var errRequestCancelled = errors.New("request cancelled")

type bridgeConfig struct {
	Endpoint         string
	Token            string
	Timeout          time.Duration
	MaxMessageBytes  int
	MaxResponseBytes int
	MaxConcurrency   int
	MaxPending       int
	AllowPrivateHTTP bool
	SignRequests     bool
	BridgeID         string
	SessionID        string
	Client           *http.Client
	Out              io.Writer
	ErrOut           io.Writer
	Now              func() time.Time
}

type bridge struct {
	endpoint         string
	token            []byte
	timeout          time.Duration
	maxMessageBytes  int
	maxResponseBytes int
	maxConcurrency   int
	maxPending       int
	signRequests     bool
	bridgeID         string
	client           *http.Client
	output           *protocolOutput
	logger           *log.Logger
	now              func() time.Time
	sequence         atomic.Uint64

	inflightMu sync.Mutex
	inflight   map[string]*inflightRequest

	sessionMu       sync.Mutex
	sessionState    sessionState
	sessionChanged  chan struct{}
	sessionID       string
	protocolVersion string
	initialization  *initializationState
	sessionErr      error
}

type inflightRequest struct {
	cancel          context.CancelCauseFunc
	cancelForwarded bool
}

type sessionState uint8

const (
	sessionUninitialized sessionState = iota
	sessionInitializing
	sessionWaitingInitialized
	sessionInitialized
	sessionFailed
)

type initializationState struct {
	clientProtocolVersion string
	initializedSeen       bool
}

type lifecycleJob uint8

const (
	lifecycleNone lifecycleJob = iota
	lifecycleInitialize
	lifecycleInitialized
)

type rpcMessage struct {
	jsonrpc      string
	method       string
	params       json.RawMessage
	id           json.RawMessage
	idPresent    bool
	notification bool
}

type bridgeJob struct {
	body            []byte
	message         rpcMessage
	ctx             context.Context
	cancel          context.CancelCauseFunc
	timeoutCancel   context.CancelFunc
	inflightKey     string
	inflightRequest *inflightRequest
	clientRequestID string
	initialization  *initializationState
	lifecycle       lifecycleJob
}

type protocolOutput struct {
	mu  sync.Mutex
	out *bufio.Writer
	err error
}

type jsonRPCErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Error   jsonRPCError    `json:"error"`
	ID      json.RawMessage `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type remoteRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func newBridge(cfg bridgeConfig) (*bridge, error) {
	if err := validateEndpoint(cfg.Endpoint, cfg.AllowPrivateHTTP); err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, errors.New("token is required")
	}
	if cfg.Timeout <= 0 || cfg.MaxMessageBytes <= 0 || cfg.MaxResponseBytes <= 0 || cfg.MaxConcurrency <= 0 || cfg.MaxPending <= 0 {
		return nil, errors.New("timeout, byte limits, concurrency, and pending limit must be positive")
	}
	if cfg.MaxPending > maxMaxPending {
		return nil, fmt.Errorf("pending limit must not exceed %d", maxMaxPending)
	}
	if cfg.Client == nil || cfg.Out == nil || cfg.ErrOut == nil {
		return nil, errors.New("HTTP client, stdout, and stderr are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SignRequests {
		if len(cfg.Token) < 32 {
			return nil, errors.New("request signing token must be at least 32 bytes")
		}
		if cfg.BridgeID == "" {
			cfg.BridgeID = newIdentifier("bridge")
		}
		if !safeHeaderValue(cfg.BridgeID) {
			return nil, errors.New("bridge ID is not safe for an HTTP header")
		}
	}
	if cfg.SessionID != "" && !safeSessionID(cfg.SessionID) {
		return nil, errors.New("MCP session ID is not safe for an HTTP header")
	}
	state := sessionUninitialized
	protocolVersion := ""
	if cfg.SessionID != "" {
		state = sessionInitialized
		protocolVersion = defaultMCPProtocolVersion
	}
	return &bridge{
		endpoint:         cfg.Endpoint,
		token:            []byte(cfg.Token),
		timeout:          cfg.Timeout,
		maxMessageBytes:  cfg.MaxMessageBytes,
		maxResponseBytes: cfg.MaxResponseBytes,
		maxConcurrency:   cfg.MaxConcurrency,
		maxPending:       cfg.MaxPending,
		signRequests:     cfg.SignRequests,
		bridgeID:         cfg.BridgeID,
		sessionState:     state,
		sessionChanged:   make(chan struct{}),
		sessionID:        cfg.SessionID,
		protocolVersion:  protocolVersion,
		client:           cfg.Client,
		output:           &protocolOutput{out: bufio.NewWriter(cfg.Out)},
		logger:           log.New(cfg.ErrOut, "stdio-bridge: ", 0),
		now:              cfg.Now,
		inflight:         make(map[string]*inflightRequest),
	}, nil
}

func (b *bridge) Run(ctx context.Context, in io.Reader) error {
	jobs := make(chan bridgeJob, b.maxPending)
	controlJobs := make(chan bridgeJob, maxControlPending)
	lifecycleJobs := make(chan bridgeJob, 1)

	var workers sync.WaitGroup
	workers.Add(b.maxConcurrency + 2)
	for range b.maxConcurrency {
		go func() {
			defer workers.Done()
			for job := range jobs {
				b.execute(job)
			}
		}()
	}
	go func() {
		defer workers.Done()
		for job := range controlJobs {
			b.execute(job)
		}
	}()
	go func() {
		defer workers.Done()
		for job := range lifecycleJobs {
			b.execute(job)
		}
	}()

	scanStopped := make(chan struct{})
	var interruptDone chan struct{}
	if closer, ok := in.(io.Closer); ok && ctx.Done() != nil {
		interruptDone = make(chan struct{})
		go func() {
			defer close(interruptDone)
			select {
			case <-ctx.Done():
				_ = closer.Close()
			case <-scanStopped:
			}
		}()
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64<<10), b.maxMessageBytes)
scanLoop:
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		body := append([]byte(nil), scanner.Bytes()...)
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		message, err := parseRPCMessage(body)
		if err != nil {
			if writeErr := b.output.writeError(nil, -32700, "invalid JSON-RPC message"); writeErr != nil {
				break
			}
			continue
		}
		if message.jsonrpc == "2.0" && message.method == "notifications/cancelled" {
			if cancelJob, forward := b.handleCancellation(ctx, body, message); forward {
				select {
				case controlJobs <- cancelJob:
				case <-ctx.Done():
					b.finish(cancelJob)
					break scanLoop
				default:
					b.logger.Print("dropped notifications/cancelled forwarding: control queue is full")
					b.finish(cancelJob)
				}
			}
			continue
		}

		job, duplicate := b.newJob(ctx, body, message)
		if duplicate {
			if err := b.output.writeError(message.id, -32600, "duplicate in-flight request id"); err != nil {
				break
			}
			continue
		}
		switch message.method {
		case "initialize":
			initialization, err := b.beginInitialization(message)
			if err != nil {
				b.finish(job)
				if writeErr := b.output.writeError(message.id, -32602, err.Error()); writeErr != nil {
					break scanLoop
				}
				continue
			}
			job.initialization = initialization
			job.lifecycle = lifecycleInitialize
		case "notifications/initialized":
			initialization, err := b.beginInitialized(message)
			if err != nil {
				b.finish(job)
				b.logger.Printf("notification %q failed: %s", message.method, err)
				continue
			}
			job.initialization = initialization
			job.lifecycle = lifecycleInitialized
			select {
			case lifecycleJobs <- job:
			case <-ctx.Done():
				b.failInitialized(job, "bridge shutting down before notifications/initialized was sent")
				b.finish(job)
				break scanLoop
			}
			continue
		}
		select {
		case jobs <- job:
		case <-ctx.Done():
			b.abortLifecycle(job, "bridge shutting down before initialize was sent")
			b.finish(job)
			break scanLoop
		default:
			if err := b.rejectOverloaded(job); err != nil {
				break scanLoop
			}
		}
	}

	scanErr := scanner.Err()
	close(scanStopped)
	if interruptDone != nil {
		<-interruptDone
	}
	if scanErr != nil && ctx.Err() == nil {
		b.cancelAll(scanErr)
	}
	close(jobs)
	close(controlJobs)
	close(lifecycleJobs)
	workers.Wait()
	if err := b.output.result(); err != nil {
		return fmt.Errorf("stdio write failed: %w", err)
	}
	if scanErr != nil && ctx.Err() == nil {
		return fmt.Errorf("stdio read failed: %w", scanErr)
	}
	return nil
}

func (b *bridge) newJob(parent context.Context, body []byte, message rpcMessage) (bridgeJob, bool) {
	timeoutCtx, timeoutCancel := context.WithTimeout(parent, b.timeout)
	requestCtx, cancel := context.WithCancelCause(timeoutCtx)
	job := bridgeJob{
		body:            body,
		message:         message,
		ctx:             requestCtx,
		cancel:          cancel,
		timeoutCancel:   timeoutCancel,
		clientRequestID: b.clientRequestID(message),
	}
	if !message.idPresent {
		return job, false
	}
	job.inflightKey = canonicalID(message.id)
	entry := &inflightRequest{cancel: cancel}
	b.inflightMu.Lock()
	if _, exists := b.inflight[job.inflightKey]; exists {
		b.inflightMu.Unlock()
		cancel(nil)
		timeoutCancel()
		return bridgeJob{}, true
	}
	b.inflight[job.inflightKey] = entry
	b.inflightMu.Unlock()
	job.inflightRequest = entry
	return job, false
}

func (b *bridge) execute(job bridgeJob) {
	lifecycleComplete := job.lifecycle == lifecycleNone
	defer func() {
		if !lifecycleComplete {
			b.abortLifecycle(job, "session initialization failed")
		}
		b.finish(job)
	}()

	sessionID, protocolVersion, err := b.requestIdentity(job)
	if err != nil {
		b.fail(job, -32098, err.Error())
		return
	}
	req, err := http.NewRequestWithContext(job.ctx, http.MethodPost, b.endpoint, bytes.NewReader(job.body))
	if err != nil {
		b.fail(job, -32098, "could not create HTTP request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(b.token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if protocolVersion != "" {
		req.Header.Set(headerProtocolVersion, protocolVersion)
	}
	if sessionID != "" {
		req.Header.Set(headerSessionID, sessionID)
	}
	if b.signRequests {
		req.Header.Set(headerBridgeID, b.bridgeID)
		req.Header.Set(headerClientRequestID, job.clientRequestID)
		signed, signErr := transportauth.SignRequest(b.token, req, job.body, b.now())
		if signErr != nil {
			b.fail(job, -32098, "request signing failed")
			return
		}
		req.Header.Set(transportauth.HeaderTimestamp, signed.Timestamp)
		req.Header.Set(transportauth.HeaderNonce, signed.Nonce)
		req.Header.Set(transportauth.HeaderSignature, signed.Signature)
	}

	// Exactly one RoundTrip is attempted. Redirects are disabled by the CLI client.
	resp, err := b.client.Do(req)
	if err != nil {
		cause := context.Cause(job.ctx)
		switch {
		case errors.Is(cause, errRequestCancelled):
			b.fail(job, -32800, "request cancelled")
		case errors.Is(cause, context.Canceled):
			// The bridge itself is shutting down; do not create new protocol traffic.
		case errors.Is(cause, context.DeadlineExceeded):
			b.fail(job, -32098, "remote request timed out")
		default:
			b.fail(job, -32098, "transport error: "+err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if gatewayRequestID := resp.Header.Get(headerGatewayRequestID); gatewayRequestID != "" {
		b.logger.Printf("gateway request id bridge=%q client=%q gateway=%q", b.bridgeID, job.clientRequestID, gatewayRequestID)
	}
	if job.lifecycle == lifecycleInitialized {
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
			b.fail(job, -32098, fmt.Sprintf("notifications/initialized remote HTTP status %d", resp.StatusCode))
			return
		}
		b.completeInitialized(job.initialization)
		lifecycleComplete = true
		return
	}
	if job.message.notification && (resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent) {
		return
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(b.maxResponseBytes)+1))
	if readErr != nil || len(body) > b.maxResponseBytes {
		b.fail(job, -32098, "invalid or oversized remote response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		b.fail(job, -32098, fmt.Sprintf("remote HTTP status %d", resp.StatusCode))
		return
	}
	if job.message.notification {
		return
	}
	if job.lifecycle == lifecycleInitialize {
		compact, negotiatedVersion, remoteError, validationMessage := validateInitializeResponse(body, job.message.id)
		if validationMessage != "" {
			b.fail(job, -32098, validationMessage)
			return
		}
		if remoteError {
			_ = b.output.writeLine(compact)
			b.failInitialization(job.initialization, "initialize returned a JSON-RPC error")
			lifecycleComplete = true
			return
		}
		responseSessionID, validSessionID := sessionIDFromResponse(resp.Header)
		if !validSessionID {
			b.fail(job, -32098, "initialize response missing or invalid Mcp-Session-Id")
			return
		}
		b.completeInitialization(job.initialization, responseSessionID, negotiatedVersion)
		lifecycleComplete = true
		_ = b.output.writeLine(compact)
		return
	}
	_ = b.output.writeRemote(body, job.message.id)
}

func (b *bridge) beginInitialization(message rpcMessage) (*initializationState, error) {
	if !message.idPresent {
		return nil, errors.New("initialize must be a JSON-RPC request")
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(message.params, &params); err != nil || !safeProtocolVersion(params.ProtocolVersion) {
		return nil, errors.New("initialize params must contain a safe protocolVersion")
	}

	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionState != sessionUninitialized {
		return nil, fmt.Errorf("initialize is not allowed while session is %s", b.sessionState)
	}
	initialization := &initializationState{clientProtocolVersion: params.ProtocolVersion}
	b.initialization = initialization
	b.sessionID = ""
	b.protocolVersion = ""
	b.sessionErr = nil
	b.transitionSessionLocked(sessionInitializing)
	return initialization, nil
}

func (b *bridge) beginInitialized(message rpcMessage) (*initializationState, error) {
	if !message.notification {
		return nil, errors.New("notifications/initialized must be a JSON-RPC notification")
	}
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	switch b.sessionState {
	case sessionInitializing, sessionWaitingInitialized:
		if b.initialization == nil {
			return nil, errors.New("MCP initialization state is inconsistent")
		}
		if b.initialization.initializedSeen {
			return nil, errors.New("notifications/initialized was already received")
		}
		b.initialization.initializedSeen = true
		return b.initialization, nil
	case sessionInitialized:
		return nil, nil
	case sessionFailed:
		return nil, fmt.Errorf("MCP session initialization failed: %v", b.sessionErr)
	default:
		b.sessionErr = errors.New("notifications/initialized arrived before initialize")
		b.transitionSessionLocked(sessionFailed)
		return nil, b.sessionErr
	}
}

func (b *bridge) requestIdentity(job bridgeJob) (string, string, error) {
	if job.lifecycle == lifecycleInitialize {
		// MCP protocol version is declared in initialize params, not its HTTP headers.
		return "", "", nil
	}
	for {
		b.sessionMu.Lock()
		state := b.sessionState
		changed := b.sessionChanged
		sessionID, protocolVersion := b.sessionID, b.protocolVersion
		sessionErr := b.sessionErr
		initialization := b.initialization
		b.sessionMu.Unlock()

		switch state {
		case sessionInitialized:
			return sessionID, protocolVersion, nil
		case sessionWaitingInitialized:
			if job.lifecycle == lifecycleInitialized && initialization == job.initialization {
				return sessionID, protocolVersion, nil
			}
		case sessionInitializing:
			// Both the initialized notification and ordinary requests wait for initialize.
		case sessionFailed:
			return "", "", fmt.Errorf("MCP session initialization failed: %v", sessionErr)
		default:
			return "", "", errors.New("MCP session is not initialized")
		}

		select {
		case <-changed:
		case <-job.ctx.Done():
			if state == sessionWaitingInitialized {
				return "", "", errors.New("timed out waiting for notifications/initialized barrier")
			}
			return "", "", errors.New("timed out waiting for MCP session initialization")
		}
	}
}

func (b *bridge) completeInitialization(initialization *initializationState, sessionID, protocolVersion string) {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionState != sessionInitializing || b.initialization != initialization {
		return
	}
	b.sessionID = sessionID
	b.protocolVersion = protocolVersion
	b.sessionErr = nil
	b.transitionSessionLocked(sessionWaitingInitialized)
}

func (b *bridge) failInitialization(initialization *initializationState, message string) {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionState != sessionInitializing || b.initialization != initialization {
		return
	}
	b.initialization = nil
	b.sessionID = ""
	b.protocolVersion = ""
	b.sessionErr = errors.New(message)
	b.transitionSessionLocked(sessionFailed)
}

func (b *bridge) completeInitialized(initialization *initializationState) {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if initialization == nil {
		return
	}
	if b.sessionState != sessionWaitingInitialized || b.initialization != initialization {
		return
	}
	b.initialization = nil
	b.sessionErr = nil
	b.transitionSessionLocked(sessionInitialized)
}

func (b *bridge) failInitialized(job bridgeJob, message string) {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionState == sessionFailed {
		return
	}
	if job.initialization != nil && b.initialization != job.initialization {
		return
	}
	b.initialization = nil
	b.sessionID = ""
	b.protocolVersion = ""
	b.sessionErr = errors.New(message)
	b.transitionSessionLocked(sessionFailed)
}

func (b *bridge) abortLifecycle(job bridgeJob, message string) {
	switch job.lifecycle {
	case lifecycleInitialize:
		b.failInitialization(job.initialization, message)
	case lifecycleInitialized:
		b.failInitialized(job, message)
	}
}

func (b *bridge) transitionSessionLocked(state sessionState) {
	close(b.sessionChanged)
	b.sessionChanged = make(chan struct{})
	b.sessionState = state
}

func (s sessionState) String() string {
	switch s {
	case sessionUninitialized:
		return "uninitialized"
	case sessionInitializing:
		return "initializing"
	case sessionWaitingInitialized:
		return "waiting-initialized"
	case sessionInitialized:
		return "initialized"
	case sessionFailed:
		return "failed"
	default:
		return "unknown"
	}
}

func (b *bridge) fail(job bridgeJob, code int, message string) {
	if job.message.notification {
		b.logger.Printf("notification %q failed: %s", job.message.method, message)
		return
	}
	_ = b.output.writeError(job.message.id, code, message)
}

func (b *bridge) rejectOverloaded(job bridgeJob) error {
	defer b.finish(job)
	b.abortLifecycle(job, overloadMessage)
	if !job.message.idPresent {
		b.logger.Printf("notification %q dropped: %s", job.message.method, overloadMessage)
		return nil
	}
	return b.output.writeError(job.message.id, overloadErrorCode, overloadMessage)
}

func (b *bridge) finish(job bridgeJob) {
	if job.inflightRequest != nil {
		b.inflightMu.Lock()
		if current := b.inflight[job.inflightKey]; current == job.inflightRequest {
			delete(b.inflight, job.inflightKey)
		}
		b.inflightMu.Unlock()
	}
	job.cancel(nil)
	job.timeoutCancel()
}

func (b *bridge) handleCancellation(parent context.Context, body []byte, message rpcMessage) (bridgeJob, bool) {
	var cancellation struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if err := json.Unmarshal(message.params, &cancellation); err != nil || len(cancellation.RequestID) == 0 {
		b.logger.Print("ignored notifications/cancelled with an invalid requestId")
		return bridgeJob{}, false
	}
	key := canonicalID(cancellation.RequestID)
	b.inflightMu.Lock()
	request := b.inflight[key]
	if request == nil || request.cancelForwarded {
		b.inflightMu.Unlock()
		return bridgeJob{}, false
	}
	request.cancelForwarded = true
	request.cancel(errRequestCancelled)
	b.inflightMu.Unlock()
	job, _ := b.newJob(parent, body, message)
	return job, true
}

func (b *bridge) cancelAll(cause error) {
	b.inflightMu.Lock()
	requests := make([]*inflightRequest, 0, len(b.inflight))
	for _, request := range b.inflight {
		requests = append(requests, request)
	}
	b.inflightMu.Unlock()
	for _, request := range requests {
		request.cancel(cause)
	}
}

func (b *bridge) clientRequestID(message rpcMessage) string {
	if message.idPresent {
		return headerID(message.id)
	}
	return fmt.Sprintf("%s-%d", b.bridgeID, b.sequence.Add(1))
}

func parseRPCMessage(body []byte) (rpcMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return rpcMessage{}, errors.New("message must be a JSON object")
	}
	var message rpcMessage
	if raw, ok := fields["jsonrpc"]; ok {
		_ = json.Unmarshal(raw, &message.jsonrpc)
	}
	if raw, ok := fields["method"]; ok {
		_ = json.Unmarshal(raw, &message.method)
	}
	message.params = fields["params"]
	message.id, message.idPresent = fields["id"]
	message.notification = !message.idPresent && message.jsonrpc == "2.0" && message.method != ""
	return message, nil
}

func canonicalID(id json.RawMessage) string {
	var compact bytes.Buffer
	if err := json.Compact(&compact, id); err == nil {
		return compact.String()
	}
	return string(id)
}

func headerID(id json.RawMessage) string {
	var text string
	if err := json.Unmarshal(id, &text); err != nil {
		text = canonicalID(id)
	}
	if safeHeaderValue(text) && len(text) <= 512 {
		return text
	}
	digest := sha256.Sum256(id)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (o *protocolOutput) writeError(id json.RawMessage, code int, message string) error {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(jsonRPCErrorResponse{
		JSONRPC: "2.0",
		Error:   jsonRPCError{Code: code, Message: message},
		ID:      id,
	})
	if err != nil {
		return err
	}
	return o.writeLine(body)
}

func (o *protocolOutput) writeRemote(body, id json.RawMessage) error {
	compact, validationMessage := validateRemoteResponse(body, id)
	if validationMessage != "" {
		return o.writeError(id, -32098, validationMessage)
	}
	return o.writeLine(compact)
}

func validateInitializeResponse(body, id json.RawMessage) ([]byte, string, bool, string) {
	var response remoteRPCResponse
	if err := protocol.DecodeStrict(body, &response); err != nil || response.JSONRPC != protocol.Version {
		return nil, "", false, "invalid initialize JSON-RPC response"
	}
	hasResult := len(response.Result) != 0
	hasError := len(response.Error) != 0
	if hasResult == hasError || len(response.ID) == 0 {
		return nil, "", false, "invalid initialize JSON-RPC response"
	}
	if canonicalID(response.ID) != canonicalID(id) {
		return nil, "", false, "remote response id mismatch"
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return nil, "", false, "invalid initialize JSON-RPC response"
	}
	if hasError {
		var rpcError protocol.Error
		if err := protocol.DecodeStrict(response.Error, &rpcError); err != nil {
			return nil, "", false, "invalid initialize JSON-RPC response"
		}
		return compact.Bytes(), "", true, ""
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil || !safeProtocolVersion(result.ProtocolVersion) {
		return nil, "", false, "initialize result must contain a safe non-empty protocolVersion"
	}
	return compact.Bytes(), result.ProtocolVersion, false, ""
}

func validateRemoteResponse(body, id json.RawMessage) ([]byte, string) {
	var response remoteRPCResponse
	if err := protocol.DecodeStrict(body, &response); err != nil || response.JSONRPC != protocol.Version {
		return nil, "invalid or oversized remote response"
	}
	hasResult := len(response.Result) != 0
	hasError := len(response.Error) != 0
	if hasResult == hasError {
		return nil, "invalid or oversized remote response"
	}
	if hasError {
		var rpcError protocol.Error
		if err := protocol.DecodeStrict(response.Error, &rpcError); err != nil {
			return nil, "invalid or oversized remote response"
		}
	}
	if len(response.ID) == 0 || canonicalID(response.ID) != canonicalID(id) {
		return nil, "remote response id mismatch"
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return nil, "invalid or oversized remote response"
	}
	return compact.Bytes(), ""
}

func (o *protocolOutput) writeLine(body []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return o.err
	}
	if _, err := o.out.Write(body); err != nil {
		o.err = err
		return err
	}
	if err := o.out.WriteByte('\n'); err != nil {
		o.err = err
		return err
	}
	if err := o.out.Flush(); err != nil {
		o.err = err
		return err
	}
	return nil
}

func (o *protocolOutput) result() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.err
}

func validateEndpoint(raw string, allowPrivateHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("endpoint must be an absolute HTTP(S) URL without user info")
	}
	if u.Fragment != "" {
		return errors.New("endpoint must not contain a fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if !allowPrivateHTTP {
			return errors.New("HTTP requires explicit --allow-private-http")
		}
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		ip := net.ParseIP(host)
		if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
			return errors.New("HTTP endpoint must use localhost or a private IP literal")
		}
		return nil
	default:
		return errors.New("endpoint scheme must be http or https")
	}
}

func newIdentifier(prefix string) string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err == nil {
		return prefix + "-" + hex.EncodeToString(value)
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func safeHeaderValue(value string) bool {
	if len(value) > 256 || strings.TrimSpace(value) == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func sessionIDFromResponse(header http.Header) (string, bool) {
	values := header.Values(headerSessionID)
	if len(values) != 1 || !safeSessionID(values[0]) {
		return "", false
	}
	return values[0], true
}

func safeSessionID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func safeProtocolVersion(value string) bool {
	return len(value) <= 256 && safeHeaderValue(value)
}
