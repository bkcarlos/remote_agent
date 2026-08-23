package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/gateway"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/transportauth"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

func TestMaxPendingFlagDefaultAndLimits(t *testing.T) {
	opts, err := parseFlags([]string{"--endpoint", "https://agent.example.com/mcp"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if opts.maxPending != defaultMaxPending {
		t.Fatalf("default max pending = %d, want %d", opts.maxPending, defaultMaxPending)
	}
	if opts.signRequests {
		t.Fatal("request signing must default to disabled")
	}
	signed, err := parseFlags([]string{"--endpoint", "https://agent.example.com/mcp", "--sign-requests"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.signRequests {
		t.Fatal("--sign-requests did not enable signing")
	}

	for _, value := range []string{"0", "-1", "1025"} {
		t.Run(value, func(t *testing.T) {
			_, err := parseFlags([]string{"--endpoint", "https://agent.example.com/mcp", "--max-pending", value}, io.Discard)
			if err == nil {
				t.Fatalf("--max-pending=%s was accepted", value)
			}
		})
	}
	if _, err := parseFlags([]string{"--endpoint", "https://agent.example.com/mcp", "--max-pending", "1024"}, io.Discard); err != nil {
		t.Fatalf("hard-limit value was rejected: %v", err)
	}
}

func TestBoundedPendingOverloadStillScansCancellation(t *testing.T) {
	const (
		pending = 4
		flood   = 1000
	)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	forwarded := make(chan struct{}, 1)
	var normalRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if message.Method == "notifications/cancelled" {
			forwarded <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		normalRequests.Add(1)
		if message.ID == 1 {
			close(started)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","result":{"ok":true},"id":%d}`, message.ID)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 1, &stdout, &stderr)
	b.maxPending = pending
	b.timeout = 10 * time.Second
	reader, writer := io.Pipe()
	runDone := make(chan error, 1)
	go func() { runDone <- b.Run(context.Background(), reader) }()

	if _, err := fmt.Fprintln(writer, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not occupy the worker")
	}
	for id := 2; id <= flood+1; id++ {
		if _, err := fmt.Fprintf(writer, `{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`+"\n", id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fmt.Fprintln(writer, `{"jsonrpc":"2.0","method":"notifications/progress","params":{"value":1}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(writer, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := fmt.Fprintln(writer, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel after overload flood did not reach the blocked request")
	}
	select {
	case <-forwarded:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel after overload flood was not forwarded")
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not drain bounded pending work")
	}

	if got, want := normalRequests.Load(), int32(1+pending); got != want {
		t.Fatalf("normal HTTP requests = %d, want exactly active + pending = %d", got, want)
	}
	var overloads, duplicates, cancellations, successes int
	for _, line := range nonemptyLines(stdout.String()) {
		var response struct {
			Result json.RawMessage `json:"result"`
			Error  *jsonRPCError   `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("invalid protocol output %q: %v", line, err)
		}
		if response.Error == nil {
			successes++
			continue
		}
		switch response.Error.Code {
		case overloadErrorCode:
			overloads++
			if response.Error.Message != overloadMessage {
				t.Fatalf("unclear overload message: %q", response.Error.Message)
			}
		case -32600:
			duplicates++
		case -32800:
			cancellations++
		default:
			t.Fatalf("unexpected response: %s", line)
		}
	}
	if overloads != flood-pending || successes != pending || duplicates != 1 || cancellations != 1 {
		t.Fatalf("responses: overload=%d success=%d duplicate=%d cancelled=%d", overloads, successes, duplicates, cancellations)
	}
	if !strings.Contains(stderr.String(), `notification "notifications/progress" dropped: `+overloadMessage) {
		t.Fatalf("overloaded notification was not diagnosed on stderr: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "notifications/progress") {
		t.Fatalf("overloaded notification polluted stdout: %q", stdout.String())
	}
	b.inflightMu.Lock()
	defer b.inflightMu.Unlock()
	if len(b.inflight) != 0 {
		t.Fatalf("inflight entries leaked after overload: %d", len(b.inflight))
	}
}

func TestCancellationCancelsMatchingHTTPRequestAndUsesStandardSession(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	forwarded := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(headerSessionID); got != "session-test" {
			t.Errorf("%s = %q, want session-test", headerSessionID, got)
		}
		if got := r.Header.Get(headerProtocolVersion); got != defaultMCPProtocolVersion {
			t.Errorf("%s = %q", headerProtocolVersion, got)
		}
		var message struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if message.Method == "notifications/cancelled" {
			forwarded <- struct{}{}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 1, &stdout, &stderr)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background(), reader) }()

	fmt.Fprintln(writer, `{"jsonrpc":"2.0","id":"request-1","method":"tools/list"}`)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("HTTP request did not start")
	}
	fmt.Fprintln(writer, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"request-1"}}`)
	writer.Close()

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach the HTTP request context")
	}
	select {
	case <-forwarded:
	case <-time.After(time.Second):
		t.Fatal("cancellation notification was not forwarded")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var response struct {
		ID    string `json:"id"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatalf("invalid stdout response %q: %v", stdout.String(), err)
	}
	if response.ID != "request-1" || response.Error.Code != -32800 {
		t.Fatalf("unexpected cancellation response: %+v", response)
	}
}

func TestInitializeEstablishesStandardSessionAndBlocksConcurrentMessages(t *testing.T) {
	const protocolVersion = "2025-06-18"
	initializeStarted := make(chan struct{})
	releaseInitialize := make(chan struct{})
	subsequent := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+strings.Repeat("t", 32) {
			t.Errorf("Authorization = %q", got)
		}
		for _, header := range []string{headerBridgeID, headerClientRequestID, transportauth.HeaderSessionID, transportauth.HeaderTimestamp, transportauth.HeaderNonce, transportauth.HeaderSignature} {
			if got := r.Header.Get(header); got != "" {
				t.Errorf("unsigned request unexpectedly included %s=%q", header, got)
			}
		}
		var message struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if message.Method == "initialize" {
			if got := r.Header.Get(headerProtocolVersion); got != "" {
				t.Errorf("initialize included %s=%q", headerProtocolVersion, got)
			}
			if got := r.Header.Get(headerSessionID); got != "" {
				t.Errorf("initialize included %s=%q", headerSessionID, got)
			}
			close(initializeStarted)
			<-releaseInitialize
			w.Header().Set(headerSessionID, "server-session")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"`+protocolVersion+`"}}`)
			return
		}
		if got := r.Header.Get(headerSessionID); got != "server-session" {
			t.Errorf("%s = %q, want server-session", headerSessionID, got)
		}
		if got := r.Header.Get(headerProtocolVersion); got != protocolVersion {
			t.Errorf("%s = %q, want %q", headerProtocolVersion, got, protocolVersion)
		}
		subsequent <- message.Method
		if message.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, message.ID)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 3, &stdout, &stderr)
	resetBridgeSession(b)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background(), reader) }()
	fmt.Fprintln(writer, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+protocolVersion+`"}}`)
	select {
	case <-initializeStarted:
	case <-time.After(time.Second):
		t.Fatal("initialize request did not start")
	}
	fmt.Fprintln(writer, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	fmt.Fprintln(writer, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	select {
	case method := <-subsequent:
		t.Fatalf("%s was sent before initialize completed", method)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseInitialize)
	writer.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for index, want := range []string{"notifications/initialized", "tools/list"} {
		select {
		case got := <-subsequent:
			if got != want {
				t.Fatalf("HTTP message %d = %q, want %q", index+1, got, want)
			}
		default:
			t.Fatalf("missing HTTP message %q", want)
		}
	}
	if got := len(nonemptyLines(stdout.String())); got != 2 {
		t.Fatalf("stdout lines = %d, want initialize and request responses: %q", got, stdout.String())
	}
	if strings.Contains(stdout.String(), "notifications/initialized") {
		t.Fatalf("notification polluted stdout: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "failed") {
		t.Fatalf("standard flow failed: %q", stderr.String())
	}
}

func TestInitializeRejectsMissingOrUnsafeSession(t *testing.T) {
	tests := []struct {
		name       string
		sessionIDs []string
	}{
		{name: "missing"},
		{name: "space", sessionIDs: []string{"unsafe session"}},
		{name: "too long", sessionIDs: []string{strings.Repeat("s", 257)}},
		{name: "non ASCII", sessionIDs: []string{"会话"}},
		{name: "duplicate", sessionIDs: []string{"session-one", "session-two"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, sessionID := range test.sessionIDs {
					w.Header().Add(headerSessionID, sessionID)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`)
			}))
			defer server.Close()

			var stdout, stderr bytes.Buffer
			b := testBridge(t, server, 1, &stdout, &stderr)
			resetBridgeSession(b)
			input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}` + "\n"
			if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
				t.Fatal(err)
			}
			var response jsonRPCErrorResponse
			if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
				t.Fatalf("invalid transport error %q: %v", stdout.String(), err)
			}
			if response.Error.Code != -32098 || !strings.Contains(response.Error.Message, "Mcp-Session-Id") {
				t.Fatalf("unsafe initialize session was not a protocol transport error: %+v", response)
			}
		})
	}
}

func TestInitializeResponseValidationNeverCommitsInvalidSession(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		wantRemoteRPCError bool
	}{
		{name: "JSON-RPC error with session", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"rejected"}}`, wantRemoteRPCError: true},
		{name: "missing result", body: `{"jsonrpc":"2.0","id":1}`},
		{name: "result and error", body: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"},"error":{"code":-32602,"message":"rejected"}}`},
		{name: "missing protocol version", body: `{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}`},
		{name: "unsafe protocol version", body: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"bad\nversion"}}`},
		{name: "duplicate protocol version", body: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","protocolVersion":"2025-06-18"}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set(headerSessionID, "must-not-be-committed")
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()

			var stdout, stderr bytes.Buffer
			b := testBridge(t, server, 4, &stdout, &stderr)
			resetBridgeSession(b)
			input := strings.Join([]string{
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
				`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
				`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			}, "\n") + "\n"
			if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
				t.Fatal(err)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("HTTP requests = %d, want only initialize", got)
			}
			if b.sessionState != sessionFailed || b.sessionID != "" || b.protocolVersion != "" {
				t.Fatalf("invalid initialize committed state=%s session=%q version=%q", b.sessionState, b.sessionID, b.protocolVersion)
			}
			lines := nonemptyLines(stdout.String())
			if len(lines) != 2 {
				t.Fatalf("stdout lines = %d, want initialize and blocked request errors: %q", len(lines), stdout.String())
			}
			if test.wantRemoteRPCError && !strings.Contains(lines[0], `"code":-32602`) {
				t.Fatalf("remote JSON-RPC error was not preserved: %q", lines[0])
			}
			if !strings.Contains(stdout.String(), "MCP session initialization failed") {
				t.Fatalf("subsequent request did not fail clearly: %q", stdout.String())
			}
		})
	}
}

func TestBridgeWithGatewayNegotiatesAndOrdersInitializedBarrier(t *testing.T) {
	const (
		token         = "tttttttttttttttttttttttttttttttt"
		clientVersion = "2025-06-18"
	)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer, err := gateway.New(
		gateway.Config{AuthToken: token, MaxConcurrency: 16},
		files,
		policy.New(policy.Config{}),
		audit.New(io.Discard),
	)
	if err != nil {
		t.Fatal(err)
	}

	type observedRequest struct {
		method          string
		protocolVersion string
		sessionID       string
	}
	var observedMu sync.Mutex
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read request: %v", readErr)
			return
		}
		var message struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(body, &message); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		observedMu.Lock()
		observed = append(observed, observedRequest{
			method:          message.Method,
			protocolVersion: r.Header.Get(headerProtocolVersion),
			sessionID:       r.Header.Get(headerSessionID),
		})
		observedMu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		gatewayServer.ServeHTTP(w, r)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b, err := newBridge(bridgeConfig{
		Endpoint:         server.URL + gateway.DefaultEndpoint,
		Token:            token,
		Timeout:          3 * time.Second,
		MaxMessageBytes:  defaultMaxBytes,
		MaxResponseBytes: defaultMaxBytes,
		MaxConcurrency:   8,
		MaxPending:       defaultMaxPending,
		AllowPrivateHTTP: true,
		Client:           server.Client(),
		Out:              &stdout,
		ErrOut:           &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	var input strings.Builder
	fmt.Fprintf(&input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"bridge-test","version":"1"}}}`+"\n", clientVersion)
	fmt.Fprintln(&input, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	fmt.Fprintln(&input, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	for id := 3; id <= 18; id++ {
		fmt.Fprintf(&input, `{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`+"\n", id)
	}
	if err := b.Run(context.Background(), strings.NewReader(input.String())); err != nil {
		t.Fatal(err)
	}

	observedMu.Lock()
	gotObserved := append([]observedRequest(nil), observed...)
	observedMu.Unlock()
	if len(gotObserved) != 19 {
		t.Fatalf("Gateway requests = %d, want 19: %+v", len(gotObserved), gotObserved)
	}
	if gotObserved[0].method != "initialize" || gotObserved[0].protocolVersion != "" || gotObserved[0].sessionID != "" {
		t.Fatalf("initialize transport headers = %+v", gotObserved[0])
	}
	if gotObserved[1].method != "notifications/initialized" {
		t.Fatalf("request crossed initialized barrier: second Gateway method = %q", gotObserved[1].method)
	}
	for _, request := range gotObserved[1:] {
		if request.protocolVersion != protocol.ProtocolVersion20250326 || request.sessionID == "" {
			t.Fatalf("post-initialize request used unnegotiated identity: %+v", request)
		}
	}
	if b.sessionState != sessionInitialized || b.protocolVersion != protocol.ProtocolVersion20250326 {
		t.Fatalf("bridge state=%s protocolVersion=%q", b.sessionState, b.protocolVersion)
	}
	var initializeResponse struct {
		ID     int `json:"id"`
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	foundInitialize := false
	for _, line := range nonemptyLines(stdout.String()) {
		if err := json.Unmarshal([]byte(line), &initializeResponse); err == nil && initializeResponse.ID == 1 {
			foundInitialize = true
			break
		}
	}
	if !foundInitialize || initializeResponse.Result.ProtocolVersion != protocol.ProtocolVersion20250326 {
		t.Fatalf("missing negotiated initialize response: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "failed") {
		t.Fatalf("Gateway integration failed: %q", stderr.String())
	}
}

func TestBridgeRejectsRealGatewaySessionAttachedToInitializeError(t *testing.T) {
	const token = "tttttttttttttttttttttttttttttttt"
	root := t.TempDir()
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer, err := gateway.New(
		gateway.Config{AuthToken: token},
		files,
		policy.New(policy.Config{}),
		audit.New(io.Discard),
	)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var issuedSession string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read request: %v", readErr)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		gatewayServer.ServeHTTP(recorder, r)
		issuedSession = recorder.Header().Get(headerSessionID)
		if issuedSession == "" || recorder.Code != http.StatusOK {
			t.Errorf("real Gateway did not establish test session: status=%d session=%q body=%q", recorder.Code, issuedSession, recorder.Body.String())
			return
		}
		w.Header().Set(headerSessionID, issuedSession)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"synthetic rejection after Gateway allocation"}}`)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b, err := newBridge(bridgeConfig{
		Endpoint:         server.URL + gateway.DefaultEndpoint,
		Token:            token,
		Timeout:          2 * time.Second,
		MaxMessageBytes:  defaultMaxBytes,
		MaxResponseBytes: defaultMaxBytes,
		MaxConcurrency:   4,
		MaxPending:       defaultMaxPending,
		AllowPrivateHTTP: true,
		Client:           server.Client(),
		Out:              &stdout,
		ErrOut:           &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bridge-test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n") + "\n"
	if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("HTTP requests = %d, want only initialize", requests.Load())
	}
	if issuedSession == "" || b.sessionState != sessionFailed || b.sessionID != "" {
		t.Fatalf("attached Gateway session was committed: issued=%q state=%s committed=%q", issuedSession, b.sessionState, b.sessionID)
	}
	if !strings.Contains(stdout.String(), `"code":-32602`) || !strings.Contains(stdout.String(), "MCP session initialization failed") {
		t.Fatalf("initialize or subsequent failure missing from stdout: %q", stdout.String())
	}
}

func TestInitializedBarrierRequires202Or204(t *testing.T) {
	var methodsMu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		methodsMu.Lock()
		methods = append(methods, message.Method)
		methodsMu.Unlock()
		if message.Method == "initialize" {
			w.Header().Set(headerSessionID, "server-session")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 4, &stdout, &stderr)
	resetBridgeSession(b)
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n") + "\n"
	if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	methodsMu.Lock()
	gotMethods := append([]string(nil), methods...)
	methodsMu.Unlock()
	if strings.Join(gotMethods, ",") != "initialize,notifications/initialized" {
		t.Fatalf("ordinary request crossed failed initialized barrier: %v", gotMethods)
	}
	if b.sessionState != sessionFailed || b.sessionID != "" || !strings.Contains(stdout.String(), "MCP session initialization failed") {
		t.Fatalf("initialized rejection did not fail session: state=%s session=%q stdout=%q stderr=%q", b.sessionState, b.sessionID, stdout.String(), stderr.String())
	}
}

func TestConfiguredSessionIsExplicitAndNeverSynthesized(t *testing.T) {
	if got := configuredSessionID(func(string) string { return "" }); got != "" {
		t.Fatalf("empty environment synthesized session %q", got)
	}
	if got := configuredSessionID(func(key string) string {
		if key == "REMOTE_AGENT_SESSION_ID" {
			return "existing-standard-session"
		}
		return ""
	}); got != "existing-standard-session" {
		t.Fatalf("configured session = %q", got)
	}
}

func TestNotificationIsForwardedWithoutStdoutResponse(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			received := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- struct{}{}
				w.WriteHeader(status)
			}))
			defer server.Close()

			var stdout, stderr bytes.Buffer
			b := testBridge(t, server, 2, &stdout, &stderr)
			input := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
			if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-received:
			default:
				t.Fatal("notification was not forwarded")
			}
			if stdout.Len() != 0 {
				t.Fatalf("notification polluted stdout: %q", stdout.String())
			}
			if strings.Contains(stderr.String(), "failed") {
				t.Fatalf("%d notification was recorded as a failure: %q", status, stderr.String())
			}
		})
	}
}

func TestOptionalSignedNotificationUsesStandardEnvelopeAndAccepts204(t *testing.T) {
	key := []byte(strings.Repeat("t", 32))
	verifier, err := transportauth.NewVerifier(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read request: %v", readErr)
			return
		}
		if got := r.Header.Get(headerSessionID); got != "session-test" {
			t.Errorf("%s = %q", headerSessionID, got)
		}
		if got := r.Header.Get(transportauth.HeaderSessionID); got != "" {
			t.Errorf("legacy %s must not be sent, got %q", transportauth.HeaderSessionID, got)
		}
		if got := r.Header.Get(headerProtocolVersion); got != defaultMCPProtocolVersion {
			t.Errorf("%s = %q", headerProtocolVersion, got)
		}
		headers := transportauth.Headers{
			Timestamp: r.Header.Get(transportauth.HeaderTimestamp),
			Nonce:     r.Header.Get(transportauth.HeaderNonce),
			Signature: r.Header.Get(transportauth.HeaderSignature),
		}
		if verifyErr := verifier.VerifyRequest(r, body, headers); verifyErr != nil {
			t.Errorf("request signature: %v", verifyErr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 1, &stdout, &stderr)
	b.signRequests = true
	if err := b.Run(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), "failed") {
		t.Fatalf("signed notification produced protocol output or failure: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestFullWorkerPoolStillReadsCancelsAndForwardsSignedNotification(t *testing.T) {
	key := []byte(strings.Repeat("t", 32))
	verifier, err := transportauth.NewVerifier(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	cancelled := make(chan struct{})
	forwarded := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
			return
		}
		headers := transportauth.Headers{
			Timestamp: r.Header.Get(transportauth.HeaderTimestamp),
			Nonce:     r.Header.Get(transportauth.HeaderNonce),
			Signature: r.Header.Get(transportauth.HeaderSignature),
		}
		if verifyErr := verifier.VerifyRequest(r, body, headers); verifyErr != nil {
			t.Errorf("request signature: %v", verifyErr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var message struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(body, &message); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if message.Method == "notifications/cancelled" {
			forwarded <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if canonicalID(message.ID) == "1" {
			close(started)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","result":{},"id":%s}`, message.ID)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 1, &stdout, &stderr)
	b.signRequests = true
	reader, writer := io.Pipe()
	runDone := make(chan error, 1)
	go func() { runDone <- b.Run(context.Background(), reader) }()
	if _, err := fmt.Fprintln(writer, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not occupy the worker")
	}
	writeDone := make(chan error, 1)
	go func() {
		for _, line := range []string{
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
			`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		} {
			if _, err := fmt.Fprintln(writer, line); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- writer.Close()
	}()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("full worker pool prevented local cancellation")
	}
	select {
	case <-forwarded:
	case <-time.After(time.Second):
		t.Fatal("signed cancellation notification was not forwarded")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"code":-32800`) {
		t.Fatalf("missing local cancellation response: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "notification \"notifications/cancelled\" failed") {
		t.Fatalf("forwarded 204 was recorded as a failure: %q", stderr.String())
	}
}

func TestContextCancellationInterruptsScannerWithoutLeakingHelper(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 1, &stdout, &stderr)
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx, reader) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation left Scanner permanently blocked")
	}
	if _, err := writer.Write([]byte("after cancellation\n")); err == nil {
		t.Fatal("input reader was not closed on context cancellation")
	}
	_ = writer.Close()
}

func TestWriteRemoteStrictResponseValidation(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		valid        bool
		errorMessage string
	}{
		{name: "result", body: ` {"jsonrpc":"2.0","id":"request","result":{"extension":{"value":true}}} `, valid: true},
		{name: "null result", body: `{"jsonrpc":"2.0","id":"request","result":null}`, valid: true},
		{name: "error", body: `{"jsonrpc":"2.0","id":"request","error":{"code":-32601,"message":"missing","data":{"detail":1}}}`, valid: true},
		{name: "duplicate id", body: `{"jsonrpc":"2.0","id":"request","id":"other","result":{}}`, errorMessage: "invalid or oversized remote response"},
		{name: "unknown response field", body: `{"jsonrpc":"2.0","id":"request","result":{},"extra":true}`, errorMessage: "invalid or oversized remote response"},
		{name: "trailing value", body: `{"jsonrpc":"2.0","id":"request","result":{}} {}`, errorMessage: "invalid or oversized remote response"},
		{name: "result and error", body: `{"jsonrpc":"2.0","id":"request","result":{},"error":{"code":-32601,"message":"missing"}}`, errorMessage: "invalid or oversized remote response"},
		{name: "neither result nor error", body: `{"jsonrpc":"2.0","id":"request"}`, errorMessage: "invalid or oversized remote response"},
		{name: "unknown error field", body: `{"jsonrpc":"2.0","id":"request","error":{"code":-32601,"message":"missing","extra":true}}`, errorMessage: "invalid or oversized remote response"},
		{name: "duplicate nested result field", body: `{"jsonrpc":"2.0","id":"request","result":{"value":1,"value":2}}`, errorMessage: "invalid or oversized remote response"},
		{name: "strict id representation", body: `{"jsonrpc":"2.0","id":"\\u0072equest","result":{}}`, errorMessage: "remote response id mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			output := &protocolOutput{out: bufio.NewWriter(&stdout)}
			if err := output.writeRemote([]byte(test.body), json.RawMessage(`"request"`)); err != nil {
				t.Fatal(err)
			}
			if test.valid {
				var compact bytes.Buffer
				if err := json.Compact(&compact, []byte(test.body)); err != nil {
					t.Fatal(err)
				}
				if got, want := stdout.String(), compact.String()+"\n"; got != want {
					t.Fatalf("stdout = %q, want %q", got, want)
				}
				return
			}
			var response struct {
				ID    string `json:"id"`
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
				t.Fatalf("invalid generated error %q: %v", stdout.String(), err)
			}
			if response.ID != "request" || response.Error.Code != -32098 || response.Error.Message != test.errorMessage {
				t.Fatalf("unexpected generated error: %+v", response)
			}
		})
	}
}

func TestRemoteResponseIDMustMatchRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","result":{"ok":true},"id":"different"}`)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 1, &stdout, &stderr)
	input := `{"jsonrpc":"2.0","id":"expected","method":"tools/list"}` + "\n"
	if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	var response struct {
		ID    string `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != "expected" || response.Error.Code != -32098 || !strings.Contains(response.Error.Message, "id mismatch") {
		t.Fatalf("mismatched response ID was accepted: %+v", response)
	}
}

func TestConcurrencyLimitAndCompletionOrder(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		var request struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if request.ID == 1 {
			time.Sleep(100 * time.Millisecond)
		} else {
			time.Sleep(15 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","result":{"id":%d},"id":%d}`, request.ID, request.ID)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 2, &stdout, &stderr)
	var input strings.Builder
	for id := 1; id <= 6; id++ {
		fmt.Fprintf(&input, `{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`+"\n", id)
	}
	if err := b.Run(context.Background(), strings.NewReader(input.String())); err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got > 2 {
		t.Fatalf("maximum concurrency = %d, want <= 2", got)
	}
	lines := nonemptyLines(stdout.String())
	if len(lines) != 6 {
		t.Fatalf("got %d responses: %q", len(lines), stdout.String())
	}
	var first struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.ID != 2 {
		t.Fatalf("responses were not emitted in completion order; first id = %d", first.ID)
	}
}

func TestEndpointPolicy(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		allow bool
		ok    bool
	}{
		{name: "https public", url: "https://agent.example.com/mcp", ok: true},
		{name: "http needs opt in", url: "http://127.0.0.1:8080/mcp", ok: false},
		{name: "loopback literal", url: "http://127.0.0.1:8080/mcp", allow: true, ok: true},
		{name: "localhost", url: "http://localhost:8080/mcp", allow: true, ok: true},
		{name: "private literal", url: "http://10.2.3.4/mcp", allow: true, ok: true},
		{name: "private hostname rejected", url: "http://gateway.internal/mcp", allow: true, ok: false},
		{name: "public literal rejected", url: "http://203.0.113.10/mcp", allow: true, ok: false},
		{name: "userinfo rejected", url: "https://user@example.com/mcp", ok: false},
		{name: "fragment rejected", url: "https://example.com/mcp#fragment", ok: false},
		{name: "wrong scheme", url: "ftp://127.0.0.1/mcp", allow: true, ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateEndpoint(test.url, test.allow)
			if (err == nil) != test.ok {
				t.Fatalf("validateEndpoint() error = %v, want success %v", err, test.ok)
			}
		})
	}
}

func TestStdoutContainsOnlyProtocolAndCorrelationHeadersArePropagated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(headerBridgeID); got != "bridge-test" {
			t.Errorf("%s = %q", headerBridgeID, got)
		}
		if got := r.Header.Get(headerSessionID); got != "session-test" {
			t.Errorf("%s = %q", headerSessionID, got)
		}
		if got := r.Header.Get(headerClientRequestID); got != "client-7" {
			t.Errorf("%s = %q", headerClientRequestID, got)
		}
		for _, header := range []string{transportauth.HeaderTimestamp, transportauth.HeaderNonce, transportauth.HeaderSignature} {
			if r.Header.Get(header) == "" {
				t.Errorf("missing signed header %s", header)
			}
		}
		w.Header().Set(headerGatewayRequestID, "gateway-9")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{ "jsonrpc": "2.0", "result": {"ok": true}, "id": "client-7" }`)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	b := testBridge(t, server, 2, &stdout, &stderr)
	b.signRequests = true
	input := `{"jsonrpc":"2.0","id":"client-7","method":"tools/list"}` + "\n"
	if err := b.Run(context.Background(), strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	want := `{"jsonrpc":"2.0","result":{"ok":true},"id":"client-7"}` + "\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if strings.Contains(stdout.String(), "gateway-9") || strings.Contains(stdout.String(), "stdio-bridge") {
		t.Fatalf("diagnostic data leaked to stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "gateway-9") {
		t.Fatalf("gateway request ID was not recorded on stderr: %q", stderr.String())
	}
}

func testBridge(t *testing.T, server *httptest.Server, concurrency int, stdout, stderr io.Writer) *bridge {
	t.Helper()
	b, err := newBridge(bridgeConfig{
		Endpoint:         server.URL,
		Token:            strings.Repeat("t", 32),
		Timeout:          2 * time.Second,
		MaxMessageBytes:  defaultMaxBytes,
		MaxResponseBytes: defaultMaxBytes,
		MaxConcurrency:   concurrency,
		MaxPending:       defaultMaxPending,
		AllowPrivateHTTP: true,
		BridgeID:         "bridge-test",
		SessionID:        "session-test",
		Client:           server.Client(),
		Out:              stdout,
		ErrOut:           stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func resetBridgeSession(b *bridge) {
	b.sessionState = sessionUninitialized
	b.sessionID = ""
	b.protocolVersion = ""
	b.initialization = nil
	b.sessionErr = nil
}

func nonemptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
