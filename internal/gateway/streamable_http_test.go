package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/transportauth"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

const standardTestToken = "tttttttttttttttttttttttttttttttt"

type streamableClient struct {
	t       *testing.T
	client  *http.Client
	url     string
	token   string
	session string
}

func (c *streamableClient) post(body string) (*http.Response, protocol.Response) {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.url+DefaultEndpoint, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.session != "" {
		req.Header.Set(protocol.HeaderSessionID, c.session)
		req.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	}
	response, err := c.client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	var rpc protocol.Response
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &rpc); err != nil {
			c.t.Fatalf("decode response %q: %v", payload, err)
		}
	}
	return response, rpc
}

func newStandardTestServer(t *testing.T, config Config) (*Server, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	if config.AuthToken == "" && config.TokenValidator == nil && config.Authenticator == nil {
		config.AuthToken = standardTestToken
	}
	var logs bytes.Buffer
	s, err := New(config, files, policy.New(policy.Config{}), audit.New(&logs))
	if err != nil {
		t.Fatal(err)
	}
	return s, &logs
}

func initializeStandardClient(t *testing.T, client *streamableClient) protocol.Response {
	t.Helper()
	response, rpc := client.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"standard-test","version":"1.0"}}}`)
	if response.StatusCode != http.StatusOK || rpc.Error != nil {
		t.Fatalf("initialize: status=%d response=%+v", response.StatusCode, rpc)
	}
	client.session = response.Header.Get(protocol.HeaderSessionID)
	decoded, err := base64.RawURLEncoding.DecodeString(client.session)
	if err != nil || len(decoded) < 16 {
		t.Fatalf("session ID is not at least 128 random bits: %q (%v)", client.session, err)
	}
	result := resultMap(t, rpc)
	if result["protocolVersion"] != protocol.ProtocolVersion20250326 {
		t.Fatalf("negotiated protocol version = %v", result["protocolVersion"])
	}
	return rpc
}

func TestStreamableHTTPStandardClientEndToEnd(t *testing.T) {
	s, logs := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	mux := http.NewServeMux()
	mux.Handle(DefaultEndpoint, s)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	client := &streamableClient{t: t, client: httpServer.Client(), url: httpServer.URL, token: standardTestToken}
	initializeStandardClient(t, client)

	response, rpc := client.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if response.StatusCode != http.StatusAccepted || response.ContentLength > 0 || rpc.JSONRPC != "" || response.Header.Get("Content-Type") != "" {
		t.Fatalf("initialized notification: status=%d length=%d type=%q response=%+v", response.StatusCode, response.ContentLength, response.Header.Get("Content-Type"), rpc)
	}
	response, rpc = client.post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if response.StatusCode != http.StatusOK || rpc.Error != nil || rpc.Result == nil || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("tools/list: status=%d type=%q response=%+v", response.StatusCode, response.Header.Get("Content-Type"), rpc)
	}
	response, rpc = client.post(call(3, "read_file", `{"path":"a.txt"}`))
	if response.StatusCode != http.StatusOK || rpc.Error != nil || resultMap(t, rpc)["isError"] == true {
		t.Fatalf("tools/call: status=%d response=%+v", response.StatusCode, rpc)
	}
	if !strings.Contains(logs.String(), `"transport":"streamable-http"`) || !strings.Contains(logs.String(), `"session_id":"`+client.session+`"`) {
		t.Fatalf("audit did not record standard transport/session: %s", logs.String())
	}
}

func TestStreamableHTTPSessionBindingExpiryAndBoundedEviction(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	validator := TokenValidatorFunc(func(_ context.Context, token string) (string, error) {
		switch token {
		case "token-a":
			return "principal-a", nil
		case "token-b":
			return "principal-b", nil
		default:
			return "", ErrUnauthorized
		}
	})
	s, _ := newStandardTestServer(t, Config{TokenValidator: validator, SessionTTL: time.Minute, MaxSessions: 2, Now: func() time.Time { return now }})
	httpServer := httptest.NewServer(s)
	defer httpServer.Close()
	clientA := &streamableClient{t: t, client: httpServer.Client(), url: httpServer.URL, token: "token-a"}
	initializeStandardClient(t, clientA)

	clientA.session = "forged-session"
	response, _ := clientA.post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("forged session status = %d", response.StatusCode)
	}
	clientA.session = ""
	response, _ = clientA.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("missing session status = %d", response.StatusCode)
	}

	clientA.session = initializeSession(t, httpServer, "token-a", 4)
	clientB := &streamableClient{t: t, client: httpServer.Client(), url: httpServer.URL, token: "token-b", session: clientA.session}
	response, _ = clientB.post(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-principal session status = %d", response.StatusCode)
	}

	now = now.Add(time.Minute)
	response, _ = clientA.post(`{"jsonrpc":"2.0","id":6,"method":"tools/list"}`)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expired session status = %d", response.StatusCode)
	}

	now = now.Add(time.Second)
	first := initializeSession(t, httpServer, "token-a", 7)
	now = now.Add(time.Second)
	_ = initializeSession(t, httpServer, "token-a", 8)
	now = now.Add(time.Second)
	_ = initializeSession(t, httpServer, "token-a", 9)
	clientA.session = first
	response, _ = clientA.post(`{"jsonrpc":"2.0","id":10,"method":"tools/list"}`)
	if response.StatusCode != http.StatusNotFound || len(s.sessions.sessions) > 2 {
		t.Fatalf("bounded eviction: status=%d sessions=%d", response.StatusCode, len(s.sessions.sessions))
	}
}

func initializeSession(t *testing.T, server *httptest.Server, token string, id int) string {
	t.Helper()
	client := &streamableClient{t: t, client: server.Client(), url: server.URL, token: token}
	response, rpc := client.post(`{"jsonrpc":"2.0","id":` + jsonNumber(id) + `,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"session-test","version":"1"}}}`)
	if response.StatusCode != http.StatusOK || rpc.Error != nil {
		t.Fatalf("initialize session: status=%d response=%+v", response.StatusCode, rpc)
	}
	return response.Header.Get(protocol.HeaderSessionID)
}

func TestStreamableHTTPDeleteGetOriginAndHeaders(t *testing.T) {
	s, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken, AllowedOrigins: []string{"https://client.example"}})
	httpServer := httptest.NewServer(s)
	defer httpServer.Close()
	client := &streamableClient{t: t, client: httpServer.Client(), url: httpServer.URL, token: standardTestToken}
	initializeStandardClient(t, client)

	get, err := http.NewRequest(http.MethodGet, httpServer.URL+DefaultEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("Authorization", "Bearer "+standardTestToken)
	response, err := httpServer.Client().Do(get)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != "POST, DELETE" {
		t.Fatalf("GET status=%d Allow=%q", response.StatusCode, response.Header.Get("Allow"))
	}

	originRequest, _ := http.NewRequest(http.MethodPost, httpServer.URL+DefaultEndpoint, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	originRequest.Header.Set("Authorization", "Bearer "+standardTestToken)
	originRequest.Header.Set("Content-Type", "application/json")
	originRequest.Header.Set("Origin", "https://evil.example")
	originResponse, err := httpServer.Client().Do(originRequest)
	if err != nil {
		t.Fatal(err)
	}
	originResponse.Body.Close()
	if originResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted Origin status = %d", originResponse.StatusCode)
	}
	originRequest.Header.Set("Origin", "https://client.example")
	originRequest.Body = io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	originRequest.Header.Set(protocol.HeaderSessionID, client.session)
	originRequest.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	originResponse, err = httpServer.Client().Do(originRequest)
	if err != nil {
		t.Fatal(err)
	}
	originResponse.Body.Close()
	if originResponse.StatusCode != http.StatusOK {
		t.Fatalf("allowed Origin status = %d", originResponse.StatusCode)
	}

	badAccept, _ := http.NewRequest(http.MethodPost, httpServer.URL+DefaultEndpoint, strings.NewReader(`{}`))
	badAccept.Header.Set("Authorization", "Bearer "+standardTestToken)
	badAccept.Header.Set("Content-Type", "application/json")
	badAccept.Header.Set("Accept", "text/plain")
	badAcceptResponse, err := httpServer.Client().Do(badAccept)
	if err != nil {
		t.Fatal(err)
	}
	badAcceptResponse.Body.Close()
	if badAcceptResponse.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("bad Accept status = %d", badAcceptResponse.StatusCode)
	}

	badType, _ := http.NewRequest(http.MethodPost, httpServer.URL+DefaultEndpoint, strings.NewReader(`{}`))
	badType.Header.Set("Authorization", "Bearer "+standardTestToken)
	badType.Header.Set("Content-Type", "text/plain")
	badTypeResponse, err := httpServer.Client().Do(badType)
	if err != nil {
		t.Fatal(err)
	}
	badTypeResponse.Body.Close()
	if badTypeResponse.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("bad Content-Type status = %d", badTypeResponse.StatusCode)
	}

	unauthorized, _ := http.NewRequest(http.MethodGet, httpServer.URL+DefaultEndpoint, nil)
	unauthorizedResponse, err := httpServer.Client().Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedResponse.Body.Close()
	if unauthorizedResponse.StatusCode != http.StatusUnauthorized || unauthorizedResponse.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthorized status=%d challenge=%q", unauthorizedResponse.StatusCode, unauthorizedResponse.Header.Get("WWW-Authenticate"))
	}

	deleteRequest, _ := http.NewRequest(http.MethodDelete, httpServer.URL+DefaultEndpoint, nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+standardTestToken)
	deleteRequest.Header.Set(protocol.HeaderSessionID, client.session)
	deleteRequest.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	deleteResponse, err := httpServer.Client().Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	deleteResponse.Body.Close()
	if deleteResponse.StatusCode != http.StatusNoContent || deleteResponse.ContentLength > 0 {
		t.Fatalf("DELETE status=%d length=%d", deleteResponse.StatusCode, deleteResponse.ContentLength)
	}
	response, _ = client.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted session status = %d", response.StatusCode)
	}

	if _, err := New(Config{AuthToken: standardTestToken, AllowedOrigins: []string{"https://*.example"}}, s.fs, policy.New(policy.Config{}), audit.New(io.Discard)); err == nil {
		t.Fatal("wildcard AllowedOrigins was accepted")
	}
}

func TestStreamableHTTPOptionalRequestSignature(t *testing.T) {
	s, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken, VerifyOptionalRequestSignature: true})
	unsignedBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"unsigned-test","version":"1"}}}`
	code, header, rpc := rawRequest(s, unsignedBody, standardTestToken, "")
	if code != http.StatusOK || rpc.Error != nil || header.Get(protocol.HeaderSessionID) == "" {
		t.Fatalf("unsigned bearer initialize failed: status=%d response=%+v", code, rpc)
	}

	partial := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(unsignedBody))
	partial.Header.Set("Authorization", "Bearer "+standardTestToken)
	partial.Header.Set("Content-Type", "application/json")
	partial.Header.Set(transportauth.HeaderTimestamp, "1")
	partialRecorder := httptest.NewRecorder()
	s.ServeHTTP(partialRecorder, partial)
	if partialRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("partial signature status = %d", partialRecorder.Code)
	}

	signedBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"signed-test","version":"1"}}}`)
	signed := httptest.NewRequest(http.MethodPost, DefaultEndpoint, bytes.NewReader(signedBody))
	signed.Header.Set("Authorization", "Bearer "+standardTestToken)
	signed.Header.Set("Content-Type", "application/json")
	signature, err := transportauth.SignRequest([]byte(standardTestToken), signed, signedBody, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signed.Header.Set(transportauth.HeaderTimestamp, signature.Timestamp)
	signed.Header.Set(transportauth.HeaderNonce, signature.Nonce)
	signed.Header.Set(transportauth.HeaderSignature, signature.Signature)
	signedRecorder := httptest.NewRecorder()
	s.ServeHTTP(signedRecorder, signed)
	if signedRecorder.Code != http.StatusOK || signedRecorder.Header().Get(protocol.HeaderSessionID) == "" {
		t.Fatalf("valid optional signature status=%d body=%s", signedRecorder.Code, signedRecorder.Body.String())
	}
}

func TestStreamableHTTPInitializeStrictValidationAndNegotiation(t *testing.T) {
	s, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken})
	invalid := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025 03 26","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":null,"clientInfo":{"name":"client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":[],"clientInfo":{"name":"client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":" "}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1","extra":true}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1"},"extra":true}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1"}}} true`,
	}
	for _, body := range invalid {
		code, header, response := rawRequest(s, body, standardTestToken, "")
		if response.Error == nil || header.Get(protocol.HeaderSessionID) != "" || len(s.sessions.sessions) != 0 {
			t.Fatalf("invalid initialize created a session: status=%d body=%s header=%q response=%+v sessions=%d", code, body, header.Get(protocol.HeaderSessionID), response, len(s.sessions.sessions))
		}
	}

	headerBody := `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"header-test","version":"1"}}}`
	for _, test := range []struct {
		name      string
		configure func(http.Header)
	}{
		{name: "unsafe protocol header", configure: func(header http.Header) { header.Set(protocol.HeaderProtocolVersion, "unsafe version") }},
		{name: "duplicate protocol header", configure: func(header http.Header) {
			header.Add(protocol.HeaderProtocolVersion, "2025-03-26")
			header.Add(protocol.HeaderProtocolVersion, "2025-06-18")
		}},
		{name: "session header", configure: func(header http.Header) { header.Set(protocol.HeaderSessionID, "existing-session") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(headerBody))
			request.Header.Set("Authorization", "Bearer "+standardTestToken)
			request.Header.Set("Content-Type", "application/json")
			test.configure(request.Header)
			recorder := httptest.NewRecorder()
			s.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || recorder.Header().Get(protocol.HeaderSessionID) != "" || len(s.sessions.sessions) != 0 {
				t.Fatalf("invalid initialize headers created a session: status=%d headers=%v body=%s", recorder.Code, request.Header, recorder.Body.String())
			}
		})
	}

	body := `{"jsonrpc":"2.0","id":"newer","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{}},"clientInfo":{"name":"new-client","version":"2"}}}`
	request := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+standardTestToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(protocol.HeaderProtocolVersion, "2024-11-05")
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, request)
	var response protocol.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || response.Error != nil || recorder.Header().Get(protocol.HeaderSessionID) == "" {
		t.Fatalf("safe newer initialize failed: status=%d response=%+v", recorder.Code, response)
	}
	if got := resultMap(t, response)["protocolVersion"]; got != protocol.ProtocolVersion20250326 {
		t.Fatalf("negotiated protocol version = %v, want %s", got, protocol.ProtocolVersion20250326)
	}
}

func TestStreamableHTTPSessionVersionMustBeExplicitAndDoesNotTouchOnMismatch(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	s, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken, SessionTTL: time.Minute, Now: func() time.Time { return now }})
	httpServer := httptest.NewServer(s)
	defer httpServer.Close()
	sessionID := initializeSession(t, httpServer, standardTestToken, 1)
	created := s.sessions.sessions[sessionID].LastSeen

	post := func(version *string) int {
		request, _ := http.NewRequest(http.MethodPost, httpServer.URL+DefaultEndpoint, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
		request.Header.Set("Authorization", "Bearer "+standardTestToken)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(protocol.HeaderSessionID, sessionID)
		if version != nil {
			request.Header.Set(protocol.HeaderProtocolVersion, *version)
		}
		response, err := httpServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	now = now.Add(30 * time.Second)
	wrong := "2025-06-18"
	if code := post(&wrong); code != http.StatusBadRequest {
		t.Fatalf("wrong POST protocol version status = %d", code)
	}
	if got := s.sessions.sessions[sessionID].LastSeen; !got.Equal(created) {
		t.Fatalf("wrong protocol version touched session: got %s want %s", got, created)
	}
	now = now.Add(10 * time.Second)
	if code := post(nil); code != http.StatusBadRequest {
		t.Fatalf("missing POST protocol version status = %d", code)
	}
	if got := s.sessions.sessions[sessionID].LastSeen; !got.Equal(created) {
		t.Fatalf("missing protocol version touched session: got %s want %s", got, created)
	}
	now = created.Add(time.Minute)
	correct := protocol.ProtocolVersion20250326
	if code := post(&correct); code != http.StatusNotFound {
		t.Fatalf("invalid versions extended session lifetime: status=%d", code)
	}

	sessionID = initializeSession(t, httpServer, standardTestToken, 3)
	deleteSession := func(version *string) int {
		request, _ := http.NewRequest(http.MethodDelete, httpServer.URL+DefaultEndpoint, nil)
		request.Header.Set("Authorization", "Bearer "+standardTestToken)
		request.Header.Set(protocol.HeaderSessionID, sessionID)
		if version != nil {
			request.Header.Set(protocol.HeaderProtocolVersion, *version)
		}
		response, err := httpServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if code := deleteSession(nil); code != http.StatusBadRequest {
		t.Fatalf("missing DELETE protocol version status = %d", code)
	}
	if code := deleteSession(&wrong); code != http.StatusBadRequest {
		t.Fatalf("wrong DELETE protocol version status = %d", code)
	}
	if _, exists := s.sessions.sessions[sessionID]; !exists {
		t.Fatal("wrong DELETE protocol version removed the session")
	}
	if code := deleteSession(&correct); code != http.StatusNoContent {
		t.Fatalf("correct DELETE protocol version status = %d", code)
	}
}

func TestAcceptCompatibilityAndQualityValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "missing", want: true},
		{name: "json", values: []string{"application/json"}, want: true},
		{name: "event stream", values: []string{"text/event-stream"}, want: true},
		{name: "standard combined", values: []string{"application/json, text/event-stream"}, want: true},
		{name: "wildcard", values: []string{"*/*"}, want: true},
		{name: "json disabled", values: []string{"application/json;q=0"}, want: false},
		{name: "event disabled decimal", values: []string{"text/event-stream;q=0.0"}, want: false},
		{name: "wildcard disabled", values: []string{"*/*;q=0"}, want: false},
		{name: "all supported disabled", values: []string{"application/json;q=0, text/event-stream;q=0, */*;q=1"}, want: false},
		{name: "one supported", values: []string{"application/json;q=0, text/event-stream;q=0.5"}, want: true},
		{name: "unsupported", values: []string{"text/plain"}, want: false},
		{name: "invalid quality", values: []string{"application/json;q=bogus"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := acceptable(test.values); got != test.want {
				t.Fatalf("acceptable(%q) = %v, want %v", test.values, got, test.want)
			}
		})
	}
}
