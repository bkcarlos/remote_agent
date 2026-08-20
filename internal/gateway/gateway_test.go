package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/transportauth"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

func server(t *testing.T, write bool) (*Server, string, *bytes.Buffer) {
	t.Helper()
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("hello"), 0644)
	fs, e := workspace.New(d)
	if e != nil {
		t.Fatal(e)
	}
	var log bytes.Buffer
	s, e := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32)), Transport: "http"}, fs, policy.New(policy.Config{AllowWrite: write}), audit.New(&log))
	if e != nil {
		t.Fatal(e)
	}
	return s, d, &log
}
func request(t *testing.T, s *Server, body, token, approval string) (int, http.Header, protocol.Response) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("X-Session-ID", "test-session")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var out protocol.Response
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, w.Header(), out
}
func call(id int, name, args string) string {
	return `{"jsonrpc":"2.0","id":` + jsonNumber(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}
func jsonNumber(i int) string { b, _ := json.Marshal(i); return string(b) }
func resultMap(t *testing.T, r protocol.Response) map[string]any {
	t.Helper()
	m, ok := r.Result.(map[string]any)
	if !ok {
		b, _ := json.Marshal(r.Result)
		json.Unmarshal(b, &m)
	}
	return m
}
func TestAuthenticationAndValidation(t *testing.T) {
	s, _, _ := server(t, false)
	if code, _, _ := request(t, s, `{}`, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("status %d", code)
	}
	tok := strings.Repeat("t", 32)
	if code, _, r := request(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","extra":1}`, tok, ""); code != 400 || r.Error == nil {
		t.Fatalf("expected parse error: %d %+v", code, r)
	}
	if _, _, r := request(t, s, `{"jsonrpc":"1.0","id":1,"method":"initialize"}`, tok, ""); r.Error == nil {
		t.Fatal("accepted wrong JSON-RPC version")
	}
}
func TestInitializeAndTools(t *testing.T) {
	s, _, _ := server(t, false)
	tok := strings.Repeat("t", 32)
	_, h, r := request(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, tok, "")
	if r.Error != nil || h.Get("X-Request-ID") == "" {
		t.Fatalf("bad response %+v", r)
	}
	_, _, r = request(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, tok, "")
	if r.Error != nil || r.Result == nil {
		t.Fatalf("bad tools response %+v", r)
	}
	listed, _ := json.Marshal(r.Result)
	if strings.Contains(string(listed), `"write_file"`) {
		t.Fatal("disabled write tool was exposed")
	}
	writeServer, _, _ := server(t, true)
	_, _, r = request(t, writeServer, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, tok, "")
	listed, _ = json.Marshal(r.Result)
	if !strings.Contains(string(listed), `"write_file"`) {
		t.Fatal("enabled write tool was not exposed")
	}
}
func TestReadDeniedPathAndAudit(t *testing.T) {
	s, d, logs := server(t, false)
	os.WriteFile(filepath.Join(d, ".env"), []byte("SECRET=x"), 0600)
	tok := strings.Repeat("t", 32)
	_, _, r := request(t, s, call(1, "read_file", `{"path":"a.txt"}`), tok, "")
	m := resultMap(t, r)
	if m["isError"] == true {
		t.Fatalf("read failed: %+v", m)
	}
	_, _, r = request(t, s, call(2, "read_file", `{"path":".env"}`), tok, "")
	m = resultMap(t, r)
	if m["isError"] != true {
		t.Fatal("sensitive file allowed")
	}
	if !strings.Contains(logs.String(), "deny-sensitive-path") || !strings.Contains(logs.String(), "allow-workspace-read") {
		t.Fatalf("missing audit: %s", logs.String())
	}
}
func TestToolArgumentsAreStrict(t *testing.T) {
	s, _, _ := server(t, true)
	tok := strings.Repeat("t", 32)
	cases := []string{
		call(10, "read_file", `{"path":"a.txt","unknown":true}`),
		call(11, "read_file", `{"path":"a.txt","path":"other.txt"}`),
		call(12, "read_file", `{}`),
		call(13, "write_file", `{"path":"a.txt","content":"x","expected_hash":"NOT-A-HASH"}`),
		call(14, "glob", `{"path":".","pattern":""}`),
		call(15, "grep", `{"path":".","query":""}`),
	}
	for _, body := range cases {
		_, _, response := request(t, s, body, tok, "")
		if response.Error == nil {
			t.Fatalf("invalid arguments accepted: %s -> %+v", body, response)
		}
	}
}

func TestMetadataGlobAndGrep(t *testing.T) {
	s, d, _ := server(t, false)
	os.MkdirAll(filepath.Join(d, "src"), 0755)
	os.WriteFile(filepath.Join(d, "src", "main.go"), []byte("package main\n// target\n"), 0644)
	tok := strings.Repeat("t", 32)
	for id, tc := range []struct{ name, args string }{
		{"file_info", `{"path":"src/main.go"}`},
		{"glob", `{"path":"src","pattern":"*.go"}`},
		{"grep", `{"path":"src","query":"target"}`},
	} {
		_, _, r := request(t, s, call(20+id, tc.name, tc.args), tok, "")
		if m := resultMap(t, r); m["isError"] == true {
			t.Fatalf("%s failed: %+v", tc.name, m)
		}
	}
}

func TestWriteDryRunApprovalAndHash(t *testing.T) {
	s, d, _ := server(t, true)
	tok := strings.Repeat("t", 32)
	_, _, r := request(t, s, call(1, "write_file", `{"path":"a.txt","content":"new"}`), tok, "")
	if resultMap(t, r)["isError"] == true {
		t.Fatal("dry run failed")
	}
	_, _, r = request(t, s, call(2, "write_file", `{"path":"a.txt","content":"new","apply":true}`), tok, "")
	if resultMap(t, r)["isError"] != true {
		t.Fatal("write without approval accepted")
	}
	badApproval := approvalToken(t, s, "wrong", "new")
	_, _, r = request(t, s, call(3, "write_file", `{"path":"a.txt","content":"new","expected_hash":"wrong","approval_token":"`+badApproval+`","apply":true}`), tok, "")
	if r.Error == nil && resultMap(t, r)["isError"] != true {
		t.Fatal("bad expected hash accepted")
	}
	goodHash := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	goodApproval := approvalToken(t, s, goodHash, "new")
	_, _, r = request(t, s, call(4, "write_file", `{"path":"a.txt","content":"new","expected_hash":"`+goodHash+`","approval_token":"`+goodApproval+`","apply":true}`), tok, "")
	if resultMap(t, r)["isError"] == true {
		t.Fatal("approved write failed")
	}
	b, _ := os.ReadFile(filepath.Join(d, "a.txt"))
	if string(b) != "new" {
		t.Fatalf("got %q", b)
	}
	_, _, r = request(t, s, call(5, "write_file", `{"path":"a.txt","content":"new","expected_hash":"`+goodHash+`","approval_token":"`+goodApproval+`","apply":true}`), tok, "")
	if m := resultMap(t, r); m["isError"] != true {
		t.Fatal("approval token replay was accepted")
	}
}
func approvalToken(t *testing.T, s *Server, expected, content string) string {
	t.Helper()
	m, _ := approval.New([]byte(strings.Repeat("a", 32)))
	digest := sha256.Sum256([]byte(content))
	claims := approval.Claims{ApprovalID: newID(), SessionID: "test-session", Operation: "write_file", Path: "a.txt", ContentSHA256: hex.EncodeToString(digest[:]), ExpectedHash: expected, ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.approvals.RegisterChallenge(claims); err != nil {
		t.Fatal(err)
	}
	token, err := m.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestRequiredRequestSignature(t *testing.T) {
	s, _, _ := server(t, false)
	s.cfg.RequireRequestSignature = true
	verifier, err := transportauth.NewVerifier([]byte(strings.Repeat("t", 32)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.signature = verifier
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	unsigned := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	unsigned.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, unsigned)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status %d", w.Code)
	}
	h, _ := transportauth.Sign([]byte(strings.Repeat("t", 32)), body, time.Now())
	signed := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	signed.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	signed.Header.Set(transportauth.HeaderTimestamp, h.Timestamp)
	signed.Header.Set(transportauth.HeaderNonce, h.Nonce)
	signed.Header.Set(transportauth.HeaderSignature, h.Signature)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, signed)
	if w.Code != http.StatusOK {
		t.Fatalf("signed status %d: %s", w.Code, w.Body.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("audit storage unavailable") }

func TestWriteDeniedBeforeExecutionWhenAuditUnavailable(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("hello"), 0644)
	fs, _ := workspace.New(d)
	s, err := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32))}, fs, policy.New(policy.Config{AllowWrite: true}), audit.New(failingWriter{}))
	if err != nil {
		t.Fatal(err)
	}
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	token := approvalToken(t, s, expected, "new")
	body := call(90, "write_file", `{"path":"a.txt","content":"new","expected_hash":"`+expected+`","approval_token":"`+token+`","apply":true}`)
	_, _, response := request(t, s, body, strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] != true {
		t.Fatal("write proceeded without audit")
	}
	got, _ := os.ReadFile(filepath.Join(d, "a.txt"))
	if string(got) != "hello" {
		t.Fatalf("file changed despite audit failure: %q", got)
	}
}

func TestBodyLimitAndMethod(t *testing.T) {
	s, _, _ := server(t, false)
	s.cfg.MaxBodyBytes = 20
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100)))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", w.Code)
	}
}
