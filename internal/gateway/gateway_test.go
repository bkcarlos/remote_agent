package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/approvalview"
	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/replay"
	"github.com/bkcarlos/remote_agent/internal/requestmeta"
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

var testSessions sync.Map

func request(t *testing.T, s *Server, body, token, approval string) (int, http.Header, protocol.Response) {
	t.Helper()
	var envelope protocol.Request
	_ = json.Unmarshal([]byte(body), &envelope)
	sessionID := ""
	if envelope.Method != "" && envelope.Method != "initialize" && token != "" {
		sessionID = testSession(t, s, token)
	}
	code, header, out := rawRequest(s, body, token, sessionID)
	if envelope.Method == "initialize" && code == http.StatusOK {
		if initialized := header.Get(protocol.HeaderSessionID); initialized != "" {
			testSessions.Store(s, initialized)
		}
	}
	return code, header, out
}

func rawRequest(s *Server, body, token, sessionID string) (int, http.Header, protocol.Response) {
	r := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		r.Header.Set(protocol.HeaderSessionID, sessionID)
		r.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var out protocol.Response
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, w.Header(), out
}

func testSession(t *testing.T, s *Server, token string) string {
	t.Helper()
	if value, ok := testSessions.Load(s); ok {
		return value.(string)
	}
	code, header, response := rawRequest(s, `{"jsonrpc":"2.0","id":"test-initialize","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gateway-test","version":"1"}}}`, token, "")
	if code != http.StatusOK || response.Error != nil || header.Get(protocol.HeaderSessionID) == "" {
		t.Fatalf("initialize test session: status=%d response=%+v", code, response)
	}
	sessionID := header.Get(protocol.HeaderSessionID)
	testSessions.Store(s, sessionID)
	return sessionID
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
	_, h, r := request(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gateway-test","version":"1"}}}`, tok, "")
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
func TestNotificationsContentTypeAndDynamicRegistry(t *testing.T) {
	s, _, _ := server(t, true)
	token := strings.Repeat("t", 32)
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
	} {
		code, _, response := request(t, s, body, token, "")
		if code != http.StatusAccepted || response.JSONRPC != "" {
			t.Fatalf("notification produced a response: code=%d response=%+v", code, response)
		}
	}
	missingType := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	missingType.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, missingType)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing Content-Type status = %d", w.Code)
	}
	_, _, listed := request(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, token, "")
	encoded, _ := json.Marshal(listed.Result)
	for _, required := range []string{`"read_image"`, `"multi_read"`, `"multi_edit"`, `"risk"`, `"worker"`, `"approval_required"`} {
		if !strings.Contains(string(encoded), required) {
			t.Fatalf("dynamic registry metadata %s missing from %s", required, encoded)
		}
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
func TestReadFileRangeSchemaAndResult(t *testing.T) {
	s, root, _ := server(t, false)
	original := "one\n二\r\nthree\nfour"
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, response := request(t, s, call(3, "read_file", `{"path":"a.txt","start_line":2,"end_line":3}`), strings.Repeat("t", 32), "")
	var payload struct {
		Content    string  `json:"content"`
		Bytes      int     `json:"bytes"`
		SHA256     string  `json:"sha256"`
		StartLine  int     `json:"start_line"`
		EndLine    int     `json:"end_line"`
		TotalLines int     `json:"total_lines"`
		Truncated  bool    `json:"truncated"`
		Encoding   string  `json:"encoding"`
		BOM        string  `json:"bom"`
		Newline    string  `json:"newline"`
		Confidence float64 `json:"confidence"`
	}
	toolPayload(t, response, &payload)
	if payload.Content != "二\r\nthree\n" || payload.Bytes != len([]byte(original)) || payload.SHA256 != digest([]byte(original)) || payload.StartLine != 2 || payload.EndLine != 3 || payload.TotalLines != 4 || !payload.Truncated {
		t.Fatalf("ranged read payload = %+v", payload)
	}
	if payload.Encoding != "utf-8" || payload.BOM != "none" || payload.Newline != "mixed" || payload.Confidence <= 0 {
		t.Fatalf("ranged read metadata = %+v", payload)
	}

	var readSpec toolSpec
	for _, spec := range registry() {
		if spec.Name == "read_file" {
			readSpec = spec
			break
		}
	}
	arguments, err := readSpec.Decode(json.RawMessage(`{"path":"a.txt","start_line":10,"end_line":12}`))
	if err != nil {
		t.Fatal(err)
	}
	workerRequest := s.workerRequest("read_file", arguments)
	if workerRequest.StartLine != 10 || workerRequest.EndLine != 12 {
		t.Fatalf("line range was not passed to worker: %+v", workerRequest)
	}
}

func TestReadImageUsesMCPImageContentAndSafeAudit(t *testing.T) {
	s, root, logs := server(t, false)
	value := image.NewNRGBA(image.Rect(0, 0, 2, 1))
	value.SetNRGBA(1, 0, color.NRGBA{R: 1, G: 2, B: 3, A: 255})
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, value); err != nil {
		t.Fatal(err)
	}
	raw := encoded.Bytes()
	if err := os.WriteFile(filepath.Join(root, "image.txt"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, response := request(t, s, call(4, "read_image", `{"path":"image.txt"}`), strings.Repeat("t", 32), "")
	marshaled, _ := json.Marshal(response.Result)
	var result protocol.ToolResult
	if err := json.Unmarshal(marshaled, &result); err != nil || len(result.Content) != 2 {
		t.Fatalf("image tool result = %s, %v", marshaled, err)
	}
	wantData := base64.StdEncoding.EncodeToString(raw)
	if result.Content[0].Type != "image" || result.Content[0].Data != wantData || result.Content[0].MIMEType != "image/png" {
		t.Fatalf("MCP image item = %+v", result.Content[0])
	}
	if result.Content[1].Type != "text" || strings.Contains(result.Content[1].Text, wantData) {
		t.Fatalf("metadata item embedded image data: %+v", result.Content[1])
	}
	var metadata struct {
		Bytes    int    `json:"bytes"`
		SHA256   string `json:"sha256"`
		MIMEType string `json:"mime_type"`
		Width    int    `json:"width"`
		Height   int    `json:"height"`
	}
	if err := json.Unmarshal([]byte(result.Content[1].Text), &metadata); err != nil || metadata.Bytes != len(raw) || metadata.SHA256 != digest(raw) || metadata.MIMEType != "image/png" || metadata.Width != 2 || metadata.Height != 1 {
		t.Fatalf("image metadata = %+v, %v", metadata, err)
	}
	if strings.Contains(logs.String(), wantData) {
		t.Fatal("audit log contains image content")
	}
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &event); err != nil || event.Tool != "read_image" || event.OutputBytes != int64(len(raw)) {
		t.Fatalf("image audit event = %+v, %v; raw=%s", event, err, logs.String())
	}
}

func TestReadImageLimitUsesDefaultAndAdministratorUpperBound(t *testing.T) {
	s, _, _ := server(t, false)
	if got := s.workerRequest("read_image", toolArguments{Path: "image.png"}).MaxBytes; got != s.policy.MaxReadBytes() {
		t.Fatalf("administrator image limit = %d, want %d", got, s.policy.MaxReadBytes())
	}
	root := t.TempDir()
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	largePolicyServer, err := New(Config{AuthToken: strings.Repeat("t", 32)}, files, policy.New(policy.Config{MaxReadBytes: 20 << 20}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := largePolicyServer.workerRequest("read_image", toolArguments{Path: "image.png"}).MaxBytes; got != fileworker.MaxImageBytes {
		t.Fatalf("default image limit = %d, want %d", got, fileworker.MaxImageBytes)
	}
}

func TestToolArgumentsAreStrict(t *testing.T) {
	s, _, _ := server(t, true)
	tok := strings.Repeat("t", 32)
	cases := []string{
		call(10, "read_file", `{"path":"a.txt","unknown":true}`),
		call(11, "read_file", `{"path":"a.txt","path":"other.txt"}`),
		call(12, "read_file", `{}`),
		call(16, "read_file", `{"path":"a.txt","start_line":1}`),
		call(17, "read_file", `{"path":"a.txt","start_line":2,"end_line":1}`),
		call(18, "read_file", `{"path":"a.txt","start_line":1,"end_line":10001}`),
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

func TestEditSchemaDecodesAndPassesAdaptIndentation(t *testing.T) {
	var editSpec, multiEditSpec toolSpec
	for _, spec := range registry() {
		switch spec.Name {
		case "edit":
			editSpec = spec
		case "multi_edit":
			multiEditSpec = spec
		}
	}
	encoded, _ := json.Marshal([]map[string]any{editSpec.Schema, multiEditSpec.Schema})
	if strings.Count(string(encoded), `"adapt_indentation"`) != 2 {
		t.Fatalf("edit schemas do not expose adapt_indentation: %s", encoded)
	}

	arguments, err := editSpec.Decode(json.RawMessage(`{"path":"a.txt","edits":[{"old":"a","new":"a\n  b","adapt_indentation":true}]}`))
	if err != nil || len(arguments.Edits) != 1 || !arguments.Edits[0].AdaptIndentation {
		t.Fatalf("edit adapt_indentation was not decoded: %+v, %v", arguments, err)
	}
	server, _, _ := server(t, true)
	request := server.workerRequest("edit", arguments)
	if len(request.Edits) != 1 || !request.Edits[0].AdaptIndentation {
		t.Fatalf("edit adapt_indentation was not passed to worker: %+v", request.Edits)
	}

	arguments, err = multiEditSpec.Decode(json.RawMessage(`{"files":[{"path":"a.txt","edits":[{"old":"a","new":"a\n\tb","adapt_indentation":true}]}]}`))
	if err != nil || len(arguments.Files) != 1 || len(arguments.Files[0].Edits) != 1 || !arguments.Files[0].Edits[0].AdaptIndentation {
		t.Fatalf("multi_edit adapt_indentation was not decoded: %+v, %v", arguments, err)
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
		if tc.name == "glob" || tc.name == "grep" {
			var payload struct {
				Scan *workspace.ScanStats `json:"scan"`
			}
			toolPayload(t, r, &payload)
			if payload.Scan == nil || !payload.Scan.Complete || payload.Scan.LimitReason != "" || payload.Scan.FilesScanned != 1 {
				t.Fatalf("%s scan metadata = %+v", tc.name, payload.Scan)
			}
		}
	}
}

type checksumFailureExecutor struct {
	writeCalls int
}

func (e *checksumFailureExecutor) Execute(_ context.Context, request fileworker.Request) (fileworker.Response, error) {
	response := fileworker.Response{TokenID: request.TokenID, WorkerID: "checksum-failure-worker"}
	if request.Operation == "checksum" {
		response.Error = "workspace checksum: workspace resource limit exceeded"
		response.ErrorKind = fileworker.ErrorKindLimitExceeded
		return response, &fileworker.RemoteError{Kind: response.ErrorKind, Message: response.Error}
	}
	if request.Operation == "write_file" {
		e.writeCalls++
	}
	return response, nil
}

func TestWriteRejectsEveryChecksumErrorExceptNotFound(t *testing.T) {
	executor := &checksumFailureExecutor{}
	s, err := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32))}, executor, policy.New(policy.Config{AllowWrite: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	for id, args := range []string{
		`{"path":"large.bin","content":"new"}`,
		`{"path":"large.bin","content":"new","apply":true}`,
	} {
		_, _, response := request(t, s, call(30+id, "write_file", args), token, "")
		if resultMap(t, response)["isError"] != true {
			t.Fatalf("checksum failure was treated as not found for %s", args)
		}
	}
	if executor.writeCalls != 0 {
		t.Fatalf("write worker called %d times after checksum failure", executor.writeCalls)
	}
}

func TestWriteAllowsMissingTargetCreatePreflight(t *testing.T) {
	s, _, _ := server(t, true)
	_, _, response := request(t, s, call(38, "write_file", `{"path":"new.txt","content":"new"}`), strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] == true {
		t.Fatalf("missing target was not accepted as a create preflight: %+v", response.Result)
	}
}

func TestWriteRejectsOversizedExistingFileWithoutChangingIt(t *testing.T) {
	s, root, _ := server(t, true)
	name := filepath.Join(root, "large.bin")
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	const size = int64(64<<20) + 1
	if err := file.Truncate(size); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("marker"), size-6); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	_, _, response := request(t, s, call(39, "write_file", `{"path":"large.bin","content":"new"}`), strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] != true {
		t.Fatal("oversized checksum failure was treated as a create preflight")
	}
	info, err := os.Stat(name)
	if err != nil || info.Size() != size {
		t.Fatalf("large file changed: size=%d err=%v", info.Size(), err)
	}
}

func TestWriteDryRunApprovalAndHash(t *testing.T) {
	s, d, logs := server(t, true)
	tok := strings.Repeat("t", 32)
	_, _, r := request(t, s, call(1, "write_file", `{"path":"a.txt","content":"new"}`), tok, "")
	if resultMap(t, r)["isError"] == true {
		t.Fatal("dry run failed")
	}
	var dry struct {
		ApprovalReview approvalview.View `json:"approval_review"`
		ReviewSHA256   string            `json:"review_sha256"`
	}
	toolPayload(t, r, &dry)
	if dry.ReviewSHA256 == "" || dry.ApprovalReview.Operation != "write_file" || dry.ApprovalReview.Targets[0].Diff != "" || dry.ApprovalReview.Targets[0].Encoding != "utf-8" || dry.ApprovalReview.Targets[0].Bytes != 3 {
		t.Fatalf("unsafe or incomplete write review: %+v", dry)
	}
	if digest, err := dry.ApprovalReview.ReviewDigest(); err != nil || digest != dry.ReviewSHA256 {
		t.Fatalf("write review digest = %q, %v; want %q", digest, err, dry.ReviewSHA256)
	}
	if !strings.Contains(logs.String(), dry.ReviewSHA256) {
		t.Fatalf("dry-run audit missing review digest: %s", logs.String())
	}
	_, _, r = request(t, s, call(2, "write_file", `{"path":"a.txt","content":"new","apply":true}`), tok, "")
	if resultMap(t, r)["isError"] != true {
		t.Fatal("write without approval accepted")
	}
	badApproval := approvalToken(t, s, strings.Repeat("a", 64), "new")
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
func TestGatewayRejectsLegacyWriteApprovalWithoutReview(t *testing.T) {
	s, dir, _ := server(t, true)
	before := digest([]byte("hello"))
	after := digest([]byte("new"))
	claims := approval.Claims{
		ApprovalID: "legacy-without-review", Approver: "legacy-reviewer", SessionID: testSession(t, s, strings.Repeat("t", 32)), Operation: "write_file",
		Targets: []approval.Target{{Path: "a.txt", BeforeSHA256: before, AfterSHA256: after}}, ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := s.approvals.RegisterChallenge(claims); err != nil {
		t.Fatal(err)
	}
	signer, _ := approval.New([]byte(strings.Repeat("a", 32)))
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	arguments, _ := json.Marshal(map[string]any{"path": "a.txt", "content": "new", "expected_hash": before, "approval_token": token, "apply": true})
	_, _, response := request(t, s, call(6, "write_file", string(arguments)), strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] != true {
		t.Fatal("Gateway accepted a write approval without review_sha256")
	}
	if content, err := os.ReadFile(filepath.Join(dir, "a.txt")); err != nil || string(content) != "hello" {
		t.Fatalf("legacy approval modified file: %q, %v", content, err)
	}
}

func approvalToken(t *testing.T, s *Server, expected, content string) string {
	t.Helper()
	m, _ := approval.New([]byte(strings.Repeat("a", 32)))
	digest := sha256.Sum256([]byte(content))
	claims := approval.Claims{ApprovalID: newID("approval-"), Approver: "test-approver", SessionID: testSession(t, s, strings.Repeat("t", 32)), Operation: "write_file", Path: "a.txt", ContentSHA256: hex.EncodeToString(digest[:]), ExpectedHash: expected, ExpiresAt: time.Now().Add(time.Minute)}
	bindWriteReview(t, &claims, content)
	if err := s.approvals.RegisterChallenge(claims); err != nil {
		t.Fatal(err)
	}
	token, err := m.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func bindWriteReview(t *testing.T, claims *approval.Claims, content string) {
	t.Helper()
	target := approval.Target{Path: claims.Path, BeforeSHA256: claims.ExpectedHash, AfterSHA256: claims.ContentSHA256}
	if len(claims.Targets) == 1 {
		target = claims.Targets[0]
	}
	reviewClaims := *claims
	reviewClaims.Approver = ""
	_, reviewSHA256, err := buildApprovalReview(reviewClaims, "L2", []fileworker.FileResult{writeReviewFile(toolArguments{Path: target.Path, Content: content}, target)})
	if err != nil {
		t.Fatal(err)
	}
	claims.ReviewSHA256 = reviewSHA256
}

func TestRequiredRequestSignatureAndIdentityTampering(t *testing.T) {
	s, _, _ := server(t, false)
	s.cfg.RequireRequestSignature = true
	verifier, err := transportauth.NewVerifier([]byte(strings.Repeat("t", 32)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.signature = verifier
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"signed-test","version":"1"}}}`)
	unsigned := httptest.NewRequest(http.MethodPost, "/mcp?mode=stdio", bytes.NewReader(body))
	unsigned.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	unsigned.Header.Set("Content-Type", "application/json")
	unsigned.Header.Set(headerBridgeID, "signed-bridge")
	unsigned.Header.Set(headerSessionID, "signed-session")
	unsigned.Header.Set(headerClientRequest, "1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, unsigned)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status %d", w.Code)
	}

	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "bridge", mutate: func(r *http.Request) { r.Header.Set(headerBridgeID, "other-bridge") }},
		{name: "session", mutate: func(r *http.Request) { r.Header.Set(headerSessionID, "other-session") }},
		{name: "client request", mutate: func(r *http.Request) { r.Header.Set(headerClientRequest, "other-request") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			signed := gatewaySignedRequest(t, body, "/mcp?mode=stdio")
			test.mutate(signed)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, signed)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("tampered status %d: %s", w.Code, w.Body.String())
			}
		})
	}

	signed := gatewaySignedRequest(t, body, "/mcp?mode=stdio")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, signed)
	if w.Code != http.StatusOK {
		t.Fatalf("signed status %d: %s", w.Code, w.Body.String())
	}
}

func gatewaySignedRequest(t *testing.T, body []byte, target string) *http.Request {
	t.Helper()
	return signedGatewayRequest(t, body, target, "signed-bridge", "signed-session", "1")
}

func signedGatewayRequest(t *testing.T, body []byte, target, bridgeID, sessionID, clientRequestID string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(headerBridgeID, bridgeID)
	request.Header.Set(headerSessionID, sessionID)
	if clientRequestID != "" {
		request.Header.Set(headerClientRequest, clientRequestID)
	}
	headers, err := transportauth.SignRequest([]byte(strings.Repeat("t", 32)), request, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(transportauth.HeaderTimestamp, headers.Timestamp)
	request.Header.Set(transportauth.HeaderNonce, headers.Nonce)
	request.Header.Set(transportauth.HeaderSignature, headers.Signature)
	return request
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

	var recoveredAudit bytes.Buffer
	s.audit = audit.New(&recoveredAudit)
	_, _, response = request(t, s, body, strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] == true {
		t.Fatalf("approval token was not retryable after audit recovery: %+v", response.Result)
	}
	got, _ = os.ReadFile(filepath.Join(d, "a.txt"))
	if string(got) != "new" {
		t.Fatalf("retry did not apply approved write: %q", got)
	}
	lines := bytes.Split(bytes.TrimSpace(recoveredAudit.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("approved retry wrote %d audit records, want transaction pair: %s", len(lines), recoveredAudit.String())
	}
	var started audit.Event
	if err := json.Unmarshal(lines[0], &started); err != nil {
		t.Fatal(err)
	}
	if started.Status != "started" || started.ApprovalID == "" || started.Approver != "test-approver" || !started.Approved {
		t.Fatalf("durable started event lacks approval identity: %+v", started)
	}
}

func TestApprovalInspectFailureRecordsOrdinaryDenial(t *testing.T) {
	s, _, logs := server(t, true)
	body := call(91, "write_file", `{"path":"a.txt","content":"new","expected_hash":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","approval_token":"invalid","apply":true}`)
	_, _, response := request(t, s, body, strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] != true {
		t.Fatal("invalid approval was accepted")
	}
	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("approval inspection denial wrote %d audit records, want one ordinary denial: %s", len(lines), logs.String())
	}
	var denied audit.Event
	if err := json.Unmarshal(lines[0], &denied); err != nil {
		t.Fatal(err)
	}
	if denied.Status != "denied" || denied.Stage != "completed" || denied.Approved || denied.ApprovalID != "" || denied.Approver != "" {
		t.Fatalf("invalid approval audit event = %+v", denied)
	}
}

type consumeOnFirstAuditWrite struct {
	bytes.Buffer
	once       sync.Once
	consume    func() error
	consumeErr error
	syncs      int
}

func (w *consumeOnFirstAuditWrite) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if err == nil {
		w.once.Do(func() { w.consumeErr = w.consume() })
	}
	return n, err
}

func (w *consumeOnFirstAuditWrite) Sync() error {
	w.syncs++
	return nil
}

func TestApprovalConsumeRaceFinishesTransactionDeniedWithoutExecuting(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	store := replay.NewMemory()
	writer := &consumeOnFirstAuditWrite{}
	s, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32)), ReplayStore: store,
	}, files, policy.New(policy.Config{AllowWrite: true}), audit.New(writer))
	if err != nil {
		t.Fatal(err)
	}
	before := digest([]byte("hello"))
	after := digest([]byte("new"))
	claims := approval.Claims{
		ApprovalID: "race-approval", Approver: "race-winner", SessionID: testSession(t, s, strings.Repeat("t", 32)), Operation: "write_file",
		Targets: []approval.Target{{Path: "a.txt", BeforeSHA256: before, AfterSHA256: after}}, ExpiresAt: time.Now().Add(time.Minute),
	}
	bindWriteReview(t, &claims, "new")
	if err := s.approvals.RegisterChallenge(claims); err != nil {
		t.Fatal(err)
	}
	competitor, err := approval.NewWithChallengeStore([]byte(strings.Repeat("a", 32)), store)
	if err != nil {
		t.Fatal(err)
	}
	token, err := competitor.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	scope := approval.Scope{SessionID: claims.SessionID, Operation: claims.Operation, Targets: claims.Targets, ReviewSHA256: claims.ReviewSHA256}
	writer.consume = func() error {
		_, err := competitor.Verify(token, scope)
		return err
	}
	body := call(92, "write_file", `{"path":"a.txt","content":"new","expected_hash":"`+before+`","approval_token":"`+token+`","apply":true}`)
	_, _, response := request(t, s, body, strings.Repeat("t", 32), "")
	if writer.consumeErr != nil {
		t.Fatalf("competing consumer did not win: %v", writer.consumeErr)
	}
	if resultMap(t, response)["isError"] != true {
		t.Fatal("gateway executed after losing the approval consume race")
	}
	if got, err := os.ReadFile(filepath.Join(root, "a.txt")); err != nil || string(got) != "hello" {
		t.Fatalf("file changed after consume race: %q, %v", got, err)
	}
	lines := bytes.Split(bytes.TrimSpace(writer.Bytes()), []byte{'\n'})
	if len(lines) != 2 || writer.syncs != 2 {
		t.Fatalf("consume race audit records=%d syncs=%d: %s", len(lines), writer.syncs, writer.String())
	}
	var started, denied audit.Event
	if err := json.Unmarshal(lines[0], &started); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &denied); err != nil {
		t.Fatal(err)
	}
	if started.Status != "started" || started.ApprovalID != claims.ApprovalID || started.Approver != claims.Approver || !started.Approved ||
		denied.Status != "denied" || denied.RequestID != started.RequestID {
		t.Fatalf("consume race transaction = started:%+v denied:%+v", started, denied)
	}
}

type crashAuditBuffer struct {
	bytes.Buffer
	syncs int
}

func (b *crashAuditBuffer) Sync() error {
	b.syncs++
	return nil
}

type panicApplyExecutor struct{ base ContextExecutor }

func (e panicApplyExecutor) Execute(ctx context.Context, request fileworker.Request) (fileworker.Response, error) {
	if request.Operation == "write_file" {
		panic("simulated process crash after approval consumption")
	}
	return e.base.Execute(ctx, request)
}

func TestCrashAfterApprovalConsumeLeavesAttributedDurableStart(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	store := replay.NewMemory()
	writer := &crashAuditBuffer{}
	s, err := New(Config{
		AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32)), ReplayStore: store,
	}, panicApplyExecutor{base: legacyExecutor{fs: files}}, policy.New(policy.Config{AllowWrite: true}), audit.New(writer))
	if err != nil {
		t.Fatal(err)
	}
	before := digest([]byte("hello"))
	claims := approval.Claims{
		ApprovalID: "crash-approval", Approver: "crash-reviewer", SessionID: testSession(t, s, strings.Repeat("t", 32)), Operation: "write_file",
		Targets: []approval.Target{{Path: "a.txt", BeforeSHA256: before, AfterSHA256: digest([]byte("new"))}}, ExpiresAt: time.Now().Add(time.Minute),
	}
	bindWriteReview(t, &claims, "new")
	if err := s.approvals.RegisterChallenge(claims); err != nil {
		t.Fatal(err)
	}
	signer, err := approval.New([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	body := call(93, "write_file", `{"path":"a.txt","content":"new","expected_hash":"`+before+`","approval_token":"`+token+`","apply":true}`)
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_, _, _ = request(t, s, body, strings.Repeat("t", 32), "")
	}()
	if !panicked {
		t.Fatal("simulated crash did not occur")
	}
	if writer.syncs != 1 {
		t.Fatalf("durable start sync count = %d, want 1", writer.syncs)
	}
	lines := bytes.Split(bytes.TrimSpace(writer.Bytes()), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("crash left %d audit records, want only durable start: %s", len(lines), writer.String())
	}
	var started audit.Event
	if err := json.Unmarshal(lines[0], &started); err != nil {
		t.Fatal(err)
	}
	if started.Status != "started" || started.ApprovalID != claims.ApprovalID || started.Approver != claims.Approver || !started.Approved {
		t.Fatalf("crash start lacks approval identity: %+v", started)
	}
	if _, err := s.approvals.Inspect(token, approval.Scope{SessionID: claims.SessionID, Operation: claims.Operation, Targets: claims.Targets, ReviewSHA256: claims.ReviewSHA256}); err == nil {
		t.Fatal("approval was not consumed before worker launch")
	}
	if got, err := os.ReadFile(filepath.Join(root, "a.txt")); err != nil || string(got) != "hello" {
		t.Fatalf("simulated crash changed file: %q, %v", got, err)
	}
}

type captureExecutor struct {
	started chan struct{}
	seen    chan requestmeta.Scope
}

func (e *captureExecutor) Execute(ctx context.Context, request fileworker.Request) (fileworker.Response, error) {
	if e.seen != nil {
		meta, _ := requestmeta.FromContext(ctx)
		e.seen <- meta
	}
	if e.started != nil {
		close(e.started)
		<-ctx.Done()
		return fileworker.Response{TokenID: request.TokenID, WorkerID: "worker-cancel"}, ctx.Err()
	}
	return fileworker.Response{TokenID: request.TokenID, WorkerID: "worker-capture", Content: "ok", Bytes: 2, Checksum: digest([]byte("ok")), Metadata: &fileworker.TextMetadata{Encoding: "utf-8", BOM: "none", Newline: "none", Confidence: .99}}, nil
}

func TestRequestIdentityPolicyAndCancellationReachExecutor(t *testing.T) {
	logs := &bytes.Buffer{}
	executor := &captureExecutor{seen: make(chan requestmeta.Scope, 1)}
	s, err := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32))}, executor, policy.New(policy.Config{}), audit.New(logs))
	if err != nil {
		t.Fatal(err)
	}
	body := call(70, "read_file", `{"path":"a.txt"}`)
	sessionID := testSession(t, s, strings.Repeat("t", 32))
	_, responseHeader, response := rawRequest(s, body, strings.Repeat("t", 32), sessionID)
	if response.Error != nil {
		t.Fatalf("tool call failed: %+v", response)
	}
	meta := <-executor.seen
	if meta.RequestID == "" || meta.RequestID != responseHeader.Get("X-Request-ID") || meta.BridgeID != directBridgeID || meta.SessionID != sessionID || meta.ClientRequestID != "70" || meta.PolicyID != "allow-workspace-read" || meta.PolicyDecision != "allow" {
		t.Fatalf("identity/policy scope was not preserved: %+v", meta)
	}
	for _, field := range []string{directBridgeID, sessionID, `"client_request_id":"70"`, "worker-capture", "cap-"} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("audit missing %q: %s", field, logs.String())
		}
	}

	cancelExecutor := &captureExecutor{started: make(chan struct{})}
	cancelServer, err := New(Config{AuthToken: strings.Repeat("t", 32)}, cancelExecutor, policy.New(policy.Config{}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelSession := testSession(t, cancelServer, strings.Repeat("t", 32))
	cancelRequest := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(body)).WithContext(ctx)
	cancelRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	cancelRequest.Header.Set("Content-Type", "application/json")
	cancelRequest.Header.Set(protocol.HeaderSessionID, cancelSession)
	cancelRequest.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	done := make(chan struct{})
	go func() { cancelServer.ServeHTTP(httptest.NewRecorder(), cancelRequest); close(done) }()
	<-cancelExecutor.started
	cancelNotification := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":70}}`))
	cancelNotification.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	cancelNotification.Header.Set("Content-Type", "application/json")
	cancelNotification.Header.Set(protocol.HeaderSessionID, cancelSession)
	cancelNotification.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	cancelRecorder := httptest.NewRecorder()
	cancelServer.ServeHTTP(cancelRecorder, cancelNotification)
	if cancelRecorder.Code != http.StatusAccepted {
		t.Fatalf("cancellation notification status = %d", cancelRecorder.Code)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("notifications/cancelled did not terminate executor")
	}
	cancel()
}

func TestGatewayAuditIncludesTrustedIdentityAndSecurityFields(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s, err := New(Config{
		AuthToken: strings.Repeat("t", 32), Transport: "https",
		ClientID: "trusted-client", UserID: "trusted-user", WorkspaceID: "workspace-random-id",
		PolicyVersion: "effective-v1", SecurityDegraded: true,
		SecurityDegradationReason: "Landlock unavailable; cgroup memory controls unavailable",
		SecurityDegradationFields: []string{"landlock", "cgroup"},
	}, files, policy.New(policy.Config{}), audit.New(&logs))
	if err != nil {
		t.Fatal(err)
	}
	_, _, response := request(t, s, call(75, "read_file", `{"path":"a.txt"}`), strings.Repeat("t", 32), "")
	if resultMap(t, response)["isError"] == true {
		t.Fatalf("read failed: %+v", response.Result)
	}
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &event); err != nil {
		t.Fatalf("decode gateway audit event: %v: %s", err, logs.String())
	}
	if event.ClientID != "trusted-client" || event.ClientRequestID != "75" || event.UserID != "trusted-user" ||
		event.WorkspaceID != "workspace-random-id" || event.PolicyVersion != "effective-v1" ||
		!event.SecurityDegraded || event.SecurityDegradationReason == "" || len(event.SecurityDegradationFields) != 2 {
		t.Fatalf("gateway audit fields are incomplete or inconsistent: %+v", event)
	}
	if event.ClientID == event.ClientRequestID {
		t.Fatalf("client request ID was incorrectly used as client identity: %+v", event)
	}
	if event.WorkspacePath != "" || strings.Contains(logs.String(), root) {
		t.Fatalf("audit leaked the absolute workspace path: %s", logs.String())
	}
}

func TestToolCallsRejectMissingOrLegacyUnsignedSessionIdentity(t *testing.T) {
	s, _, _ := server(t, false)
	body := call(72, "read_file", `{"path":"a.txt"}`)
	for _, test := range []struct {
		name      string
		bridgeID  string
		sessionID string
	}{
		{name: "missing bridge", sessionID: "session"},
		{name: "missing session", bridgeID: "bridge"},
		{name: "unsafe bridge", bridgeID: strings.Repeat("b", 257), sessionID: "session"},
		{name: "unsafe session", bridgeID: "bridge", sessionID: "\t"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
			request.Header.Set("Content-Type", "application/json")
			if test.bridgeID != "" {
				request.Header.Set(headerBridgeID, test.bridgeID)
			}
			if test.sessionID != "" {
				request.Header.Set(headerSessionID, test.sessionID)
			}
			recorder := httptest.NewRecorder()
			s.ServeHTTP(recorder, request)
			var response protocol.Response
			_ = json.Unmarshal(recorder.Body.Bytes(), &response)
			if recorder.Code != http.StatusNotFound || response.Error == nil {
				t.Fatalf("invalid standard session accepted: status=%d response=%+v", recorder.Code, response)
			}
		})
	}
}

func TestCancellationIsIsolatedAcrossSessions(t *testing.T) {
	executor := &captureExecutor{started: make(chan struct{})}
	s, err := New(Config{AuthToken: strings.Repeat("t", 32)}, executor, policy.New(policy.Config{}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	sessionA := testSession(t, s, token)
	_, header, initialized := rawRequest(s, `{"jsonrpc":"2.0","id":"second","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"second-test","version":"1"}}}`, token, "")
	if initialized.Error != nil {
		t.Fatalf("second initialize failed: %+v", initialized)
	}
	sessionB := header.Get(protocol.HeaderSessionID)
	body := call(71, "read_file", `{"path":"a.txt"}`)
	toolRequest := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(body))
	toolRequest.Header.Set("Authorization", "Bearer "+token)
	toolRequest.Header.Set("Content-Type", "application/json")
	toolRequest.Header.Set(protocol.HeaderSessionID, sessionA)
	toolRequest.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	done := make(chan struct{})
	go func() {
		s.ServeHTTP(httptest.NewRecorder(), toolRequest)
		close(done)
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("tool call did not start")
	}

	sendCancel := func(sessionID string) int {
		cancelBody := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":71}}`
		request := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(cancelBody))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(protocol.HeaderSessionID, sessionID)
		request.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
		recorder := httptest.NewRecorder()
		s.ServeHTTP(recorder, request)
		return recorder.Code
	}
	if code := sendCancel(sessionB); code != http.StatusAccepted {
		t.Fatalf("cross-session cancellation status = %d", code)
	}
	select {
	case <-done:
		t.Fatal("different session cancelled the active request")
	case <-time.After(100 * time.Millisecond):
	}
	if code := sendCancel(sessionA); code != http.StatusAccepted {
		t.Fatalf("matching cancellation status = %d", code)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("matching principal/session/request did not cancel the active request")
	}
}

func TestSignedCancellationBypassesFullDataLaneAndOrdinaryRateBucket(t *testing.T) {
	executor := &captureExecutor{started: make(chan struct{})}
	s, err := New(Config{
		AuthToken: strings.Repeat("t", 32), RequireRequestSignature: true, AllowLegacySignedSession: true,
		MaxConcurrency: 1, RateLimitPerSecond: 1, RateLimitBurst: 2,
	}, executor, policy.New(policy.Config{}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(call(73, "read_file", `{"path":"a.txt"}`))
	dataRequest := signedGatewayRequest(t, body, "/mcp", "control-bridge", "control-session", "73")
	dataDone := make(chan struct{})
	go func() {
		s.ServeHTTP(httptest.NewRecorder(), dataRequest)
		close(dataDone)
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("data request did not fill the only concurrency slot")
	}

	cancelBody := []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":73}}`)
	cancelRequest := signedGatewayRequest(t, cancelBody, "/mcp", "control-bridge", "control-session", "")
	cancelRecorder := httptest.NewRecorder()
	s.ServeHTTP(cancelRecorder, cancelRequest)
	if cancelRecorder.Code != http.StatusAccepted {
		t.Fatalf("signed cancellation status = %d: %s", cancelRecorder.Code, cancelRecorder.Body.String())
	}
	select {
	case <-dataDone:
	case <-time.After(time.Second):
		t.Fatal("signed cancellation could not run while all data slots were full")
	}

	initializeBody := []byte(`{"jsonrpc":"2.0","id":74,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"control-test","version":"1"}}}`)
	initializeRequest := signedGatewayRequest(t, initializeBody, "/mcp", "control-bridge", "control-session", "74")
	initializeRecorder := httptest.NewRecorder()
	s.ServeHTTP(initializeRecorder, initializeRequest)
	if initializeRecorder.Code != http.StatusOK {
		t.Fatalf("cancellation consumed the remaining ordinary rate token: status=%d body=%s", initializeRecorder.Code, initializeRecorder.Body.String())
	}
}

func TestRateLimitUsesDeterministicPrincipalIPBucket(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600)
	files, _ := workspace.New(dir)
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s, err := New(Config{AuthToken: strings.Repeat("t", 32), RateLimitPerSecond: 1, RateLimitBurst: 1, Now: func() time.Time { return now }}, files, policy.New(policy.Config{}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"rate-test","version":"1"}}}`
	if code, _, _ := request(t, s, body, strings.Repeat("t", 32), ""); code != http.StatusOK {
		t.Fatalf("first request status = %d", code)
	}
	if code, _, _ := request(t, s, body, strings.Repeat("t", 32), ""); code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d", code)
	}
	now = now.Add(time.Second)
	if code, _, _ := request(t, s, body, strings.Repeat("t", 32), ""); code != http.StatusOK {
		t.Fatalf("refilled request status = %d", code)
	}
}

func TestRateLimiterExpiresBucketsAndEvictsOldestDeterministically(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	limiter := newRateLimiterWithLimits(1, 1, func() time.Time { return now }, time.Minute, 2)
	limiter.allow("oldest")
	now = now.Add(time.Second)
	limiter.allow("newest")
	now = now.Add(time.Second)
	limiter.allow("incoming")
	if len(limiter.buckets) != 2 {
		t.Fatalf("bucket count = %d, want hard limit 2", len(limiter.buckets))
	}
	if _, exists := limiter.buckets["oldest"]; exists {
		t.Fatal("oldest rate bucket was not evicted")
	}

	now = now.Add(time.Minute)
	limiter.allow("after-ttl")
	if len(limiter.buckets) != 1 {
		t.Fatalf("expired buckets were not cleaned up: %+v", limiter.buckets)
	}
	if _, exists := limiter.buckets["after-ttl"]; !exists {
		t.Fatal("new bucket missing after TTL cleanup")
	}

	now = time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	tied := newRateLimiterWithLimits(1, 1, func() time.Time { return now }, time.Hour, 2)
	tied.allow("b")
	tied.allow("a")
	tied.allow("c")
	if _, exists := tied.buckets["a"]; exists {
		t.Fatalf("equal-age eviction was not deterministic: %+v", tied.buckets)
	}
}

func TestMalformedRequestDoesNotConsumeOrdinaryRateBucket(t *testing.T) {
	s, _, _ := server(t, false)
	s.rate = newRateLimiterWithLimits(1, 1, time.Now, time.Minute, 8)
	token := strings.Repeat("t", 32)
	if code, _, _ := request(t, s, `{"jsonrpc":`, token, ""); code != http.StatusBadRequest {
		t.Fatalf("malformed request status = %d", code)
	}
	if code, _, _ := request(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"rate-test","version":"1"}}}`, token, ""); code != http.StatusOK {
		t.Fatalf("malformed request consumed rate bucket: status=%d", code)
	}
}

func toolPayload(t *testing.T, response protocol.Response, target any) {
	t.Helper()
	encoded, _ := json.Marshal(response.Result)
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil || len(envelope.Content) != 1 {
		t.Fatalf("invalid tool envelope: %s (%v)", encoded, err)
	}
	if err := json.Unmarshal([]byte(envelope.Content[0].Text), target); err != nil {
		t.Fatalf("invalid tool payload %q: %v", envelope.Content[0].Text, err)
	}
}

type blockingCommitFS struct {
	FileExecutor
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (f *blockingCommitFS) WriteFile(path string, data []byte, expected string, max int64) (string, error) {
	first := false
	f.once.Do(func() { first = true })
	sum, err := f.FileExecutor.WriteFile(path, data, expected, max)
	if first && err == nil {
		close(f.started)
		<-f.release
	}
	return sum, err
}

type failPathFS struct {
	FileExecutor
	path string
}

func (f failPathFS) WriteFile(path string, data []byte, expected string, max int64) (string, error) {
	if path == f.path {
		return "", errors.New("injected write failure")
	}
	return f.FileExecutor.WriteFile(path, data, expected, max)
}

func TestLegacyBatchCommitCancellationWaitsForConsistentResult(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("beta"), 0o640); err != nil {
		t.Fatal(err)
	}
	base, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingCommitFS{FileExecutor: base, started: make(chan struct{}), release: make(chan struct{})}
	s, err := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32))}, blocking, policy.New(policy.Config{AllowWrite: true}), audit.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	files := []map[string]any{
		{"path": "a.txt", "edits": []map[string]string{{"old": "alpha", "new": "ALPHA"}}},
		{"path": "b.txt", "edits": []map[string]string{{"old": "beta", "new": "BETA"}}},
	}
	dryArguments, _ := json.Marshal(map[string]any{"files": files})
	_, _, dryResponse := request(t, s, call(300, "multi_edit", string(dryArguments)), token, "")
	var dry struct {
		ApprovalID     string                  `json:"approval_id"`
		Files          []fileworker.FileResult `json:"files"`
		ReviewSHA256   string                  `json:"review_sha256"`
		ApprovalReview approvalview.View       `json:"approval_review"`
	}
	toolPayload(t, dryResponse, &dry)
	if dry.ApprovalID == "" || len(dry.Files) != 2 || dry.ReviewSHA256 == "" {
		t.Fatalf("bad multi-edit preflight: %+v", dry)
	}
	if digest, err := dry.ApprovalReview.ReviewDigest(); err != nil || digest != dry.ReviewSHA256 {
		t.Fatalf("multi-edit review digest = %q, %v; want %q", digest, err, dry.ReviewSHA256)
	}
	targets := make([]approval.Target, len(dry.Files))
	for i := range dry.Files {
		targets[i] = approval.Target{Path: dry.Files[i].Path, BeforeSHA256: dry.Files[i].BeforeSHA256, AfterSHA256: dry.Files[i].AfterSHA256}
	}
	manager, _ := approval.New([]byte(strings.Repeat("a", 32)))
	sessionID := testSession(t, s, token)
	expiresAt, err := time.Parse(time.RFC3339Nano, dry.ApprovalReview.Expiry)
	if err != nil {
		t.Fatal(err)
	}
	claims := approval.Claims{ApprovalID: dry.ApprovalID, Approver: "batch-approver", SessionID: sessionID, Operation: "multi_edit", Targets: targets, ReviewSHA256: dry.ReviewSHA256, ExpiresAt: expiresAt}
	approvalToken, err := manager.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	applyArguments, _ := json.Marshal(map[string]any{"files": files, "apply": true, "approval_token": approvalToken})
	body := call(301, "multi_edit", string(applyArguments))
	applyRequest := httptest.NewRequest(http.MethodPost, DefaultEndpoint, strings.NewReader(body))
	applyRequest.Header.Set("Authorization", "Bearer "+token)
	applyRequest.Header.Set("Content-Type", "application/json")
	applyRequest.Header.Set(protocol.HeaderSessionID, sessionID)
	applyRequest.Header.Set(protocol.HeaderProtocolVersion, protocol.ProtocolVersion20250326)
	applyRecorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.ServeHTTP(applyRecorder, applyRequest)
		close(done)
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("batch commit did not write its first file")
	}
	if got, _ := os.ReadFile(filepath.Join(root, "a.txt")); string(got) != "ALPHA" {
		t.Fatalf("first file was not in the in-progress commit: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "b.txt")); string(got) != "beta" {
		t.Fatalf("second file changed before commit resumed: %q", got)
	}
	cancelBody := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":301}}`
	if code, _, _ := request(t, s, cancelBody, token, ""); code != http.StatusAccepted {
		t.Fatalf("cancel notification status = %d", code)
	}
	select {
	case <-done:
		t.Fatal("gateway returned before the in-progress commit finished")
	case <-time.After(100 * time.Millisecond):
	}
	close(blocking.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not wait for commit completion")
	}
	var applyResponse protocol.Response
	if err := json.Unmarshal(applyRecorder.Body.Bytes(), &applyResponse); err != nil {
		t.Fatal(err)
	}
	if resultMap(t, applyResponse)["isError"] == true {
		t.Fatalf("completed commit reported an error: %s", applyRecorder.Body.String())
	}
	for path, want := range map[string]string{"a.txt": "ALPHA", "b.txt": "BETA"} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
}

func TestLegacyBatchOrdinaryErrorRollsBackCompletedWrites(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("beta"), 0o640); err != nil {
		t.Fatal(err)
	}
	base, err := workspace.New(root)
	if err != nil {
		t.Fatal(err)
	}
	executor := legacyExecutor{fs: failPathFS{FileExecutor: base, path: "b.txt"}}
	files := []fileworker.EditFile{
		{Path: "a.txt", Edits: []fileworker.Edit{{Old: "alpha", New: "ALPHA"}}},
		{Path: "b.txt", Edits: []fileworker.Edit{{Old: "beta", New: "BETA"}}},
	}
	preview, err := executor.Execute(context.Background(), fileworker.Request{Operation: "multi_edit", Files: files, MaxBytes: 1024})
	if err != nil || len(preview.Files) != 2 {
		t.Fatalf("preview = %+v, %v", preview, err)
	}
	targets := make([]fileworker.Target, len(preview.Files))
	for i := range preview.Files {
		targets[i] = fileworker.Target{Path: preview.Files[i].Path, BeforeSHA256: preview.Files[i].BeforeSHA256, AfterSHA256: preview.Files[i].AfterSHA256}
	}
	result, err := executor.Execute(context.Background(), fileworker.Request{Operation: "multi_edit", Files: files, MaxBytes: 1024, Apply: true, Targets: targets})
	if err == nil || !result.RolledBack {
		t.Fatalf("failed batch result = %+v, %v", result, err)
	}
	for path, want := range map[string]string{"a.txt": "alpha", "b.txt": "beta"} {
		got, readErr := os.ReadFile(filepath.Join(root, path))
		if readErr != nil || string(got) != want {
			t.Fatalf("%s after rollback = %q, %v; want %q", path, got, readErr, want)
		}
	}
}

func TestEditDryRunApprovalAndApply(t *testing.T) {
	s, dir, logs := server(t, true)
	token := strings.Repeat("t", 32)
	dryArgs := `{"path":"a.txt","edits":[{"old":"hello","new":"hello world","mode":"once"}]}`
	_, _, dryResponse := request(t, s, call(80, "edit", dryArgs), token, "")
	var dry struct {
		ApprovalID      string                  `json:"approval_id"`
		Files           []fileworker.FileResult `json:"files"`
		ApprovalTargets []approval.Target       `json:"approval_targets"`
		ApprovalReview  approvalview.View       `json:"approval_review"`
		ReviewSHA256    string                  `json:"review_sha256"`
	}
	toolPayload(t, dryResponse, &dry)
	if dry.ApprovalID == "" || len(dry.Files) != 1 || dry.Files[0].Diff == "" || len(dry.ApprovalTargets) != 1 {
		t.Fatalf("bad edit dry-run: %+v", dry)
	}
	if dry.ApprovalTargets[0].Path != dry.Files[0].Path || dry.ApprovalTargets[0].BeforeSHA256 != dry.Files[0].BeforeSHA256 || dry.ApprovalTargets[0].AfterSHA256 != dry.Files[0].AfterSHA256 {
		t.Fatalf("approval_targets do not match preflight files: %+v", dry)
	}
	manager, _ := approval.New([]byte(strings.Repeat("a", 32)))
	expiresAt, err := time.Parse(time.RFC3339Nano, dry.ApprovalReview.Expiry)
	if err != nil {
		t.Fatal(err)
	}
	claims := approval.Claims{ApprovalID: dry.ApprovalID, Approver: "edit-approver", SessionID: testSession(t, s, token), Operation: "edit", Targets: []approval.Target{{Path: dry.Files[0].Path, BeforeSHA256: dry.Files[0].BeforeSHA256, AfterSHA256: dry.Files[0].AfterSHA256}}, ReviewSHA256: dry.ReviewSHA256, ExpiresAt: expiresAt}
	approvalToken, err := manager.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	applyArguments, _ := json.Marshal(map[string]any{"path": "a.txt", "edits": []map[string]string{{"old": "hello", "new": "hello world", "mode": "once"}}, "apply": true, "approval_token": approvalToken})
	_, _, applyResponse := request(t, s, call(81, "edit", string(applyArguments)), token, "")
	if resultMap(t, applyResponse)["isError"] == true {
		t.Fatalf("approved edit failed: %+v", applyResponse.Result)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "a.txt"))
	if string(got) != "hello world" {
		t.Fatalf("edited content = %q", got)
	}
	for _, field := range []string{dry.Files[0].BeforeSHA256, dry.Files[0].AfterSHA256, dry.ReviewSHA256, "edit-approver", "worker_id", "duration_ms", "parameter_summary"} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("write audit missing %q: %s", field, logs.String())
		}
	}
}

type changingReviewExecutor struct {
	base       ContextExecutor
	preflights int
	applies    int
	mutate     func(*fileworker.FileResult)
}

func (e *changingReviewExecutor) Execute(ctx context.Context, request fileworker.Request) (fileworker.Response, error) {
	response, err := e.base.Execute(ctx, request)
	if request.Operation == "edit" {
		if request.Apply {
			e.applies++
		} else {
			e.preflights++
			if e.preflights == 2 && err == nil && len(response.Files) == 1 {
				e.mutate(&response.Files[0])
			}
		}
	}
	return response, err
}

func TestApplyRejectsAnyRebuiltReviewChangeBeforeCommit(t *testing.T) {
	mutations := map[string]func(*fileworker.FileResult){
		"diff":     func(file *fileworker.FileResult) { file.Diff += "changed\n" },
		"encoding": func(file *fileworker.FileResult) { file.Metadata.Encoding = "utf-16le" },
		"hash":     func(file *fileworker.FileResult) { file.AfterSHA256 = strings.Repeat("9", 64) },
		"path":     func(file *fileworker.FileResult) { file.Path = "other.txt" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
				t.Fatal(err)
			}
			files, err := workspace.New(root)
			if err != nil {
				t.Fatal(err)
			}
			executor := &changingReviewExecutor{base: legacyExecutor{fs: files}, mutate: mutate}
			s, err := New(Config{AuthToken: strings.Repeat("t", 32), ApprovalKey: []byte(strings.Repeat("a", 32))}, executor, policy.New(policy.Config{AllowWrite: true}), audit.New(&bytes.Buffer{}))
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("t", 32)
			dryArgs := `{"path":"a.txt","edits":[{"old":"hello","new":"hello world"}]}`
			_, _, dryResponse := request(t, s, call(400, "edit", dryArgs), token, "")
			var dry struct {
				ApprovalID      string            `json:"approval_id"`
				ApprovalTargets []approval.Target `json:"approval_targets"`
				ApprovalReview  approvalview.View `json:"approval_review"`
				ReviewSHA256    string            `json:"review_sha256"`
			}
			toolPayload(t, dryResponse, &dry)
			expiresAt, err := time.Parse(time.RFC3339Nano, dry.ApprovalReview.Expiry)
			if err != nil {
				t.Fatal(err)
			}
			signer, _ := approval.New([]byte(strings.Repeat("a", 32)))
			approvalToken, err := signer.Sign(approval.Claims{
				ApprovalID: dry.ApprovalID, Approver: "reviewer", SessionID: testSession(t, s, token), Operation: "edit",
				Targets: dry.ApprovalTargets, ReviewSHA256: dry.ReviewSHA256, ExpiresAt: expiresAt,
			})
			if err != nil {
				t.Fatal(err)
			}
			applyArguments, _ := json.Marshal(map[string]any{
				"path": "a.txt", "edits": []map[string]string{{"old": "hello", "new": "hello world"}},
				"apply": true, "approval_token": approvalToken,
			})
			_, _, applyResponse := request(t, s, call(401, "edit", string(applyArguments)), token, "")
			if resultMap(t, applyResponse)["isError"] != true {
				t.Fatal("apply accepted a changed review")
			}
			if executor.applies != 0 {
				t.Fatalf("changed review reached commit executor %d times", executor.applies)
			}
			if content, err := os.ReadFile(filepath.Join(root, "a.txt")); err != nil || string(content) != "hello" {
				t.Fatalf("changed review modified file: %q, %v", content, err)
			}
		})
	}
}

func TestBodyLimitAndMethod(t *testing.T) {
	s, _, _ := server(t, false)
	s.cfg.MaxBodyBytes = 20
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100)))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", w.Code)
	}
}

func TestRPCIDStringCanonicalTypeAndCancellationIsolation(t *testing.T) {
	numberID := rpcIDString(json.RawMessage(`1`))
	stringID := rpcIDString(json.RawMessage(`"1"`))
	if numberID != "1" || stringID != `"1"` || numberID == stringID {
		t.Fatalf("canonical IDs did not preserve type: number=%q string=%q", numberID, stringID)
	}
	if escaped := rpcIDString(json.RawMessage(`"\u0031"`)); escaped != stringID {
		t.Fatalf("equivalent JSON strings were not canonicalized: escaped=%q plain=%q", escaped, stringID)
	}

	numberContext, cancelNumber := context.WithCancel(context.Background())
	defer cancelNumber()
	stringContext, cancelString := context.WithCancel(context.Background())
	defer cancelString()
	identity := requestmeta.Scope{AuthPrincipal: "principal", BridgeID: "bridge", SessionID: "session"}
	s := &Server{active: map[activeRequestKey]context.CancelFunc{
		{AuthPrincipal: identity.AuthPrincipal, BridgeID: identity.BridgeID, SessionID: identity.SessionID, ClientRequestID: numberID}: cancelNumber,
		{AuthPrincipal: identity.AuthPrincipal, BridgeID: identity.BridgeID, SessionID: identity.SessionID, ClientRequestID: stringID}: cancelString,
	}}
	ctx := requestmeta.WithScope(context.Background(), identity)
	s.cancelNotification(ctx, json.RawMessage(`{"requestId":1}`))
	if numberContext.Err() == nil {
		t.Fatal("numeric cancellation did not cancel numeric request ID")
	}
	if stringContext.Err() != nil {
		t.Fatal("numeric cancellation collided with string request ID")
	}
	s.cancelNotification(ctx, json.RawMessage(`{"requestId":"1"}`))
	if stringContext.Err() == nil {
		t.Fatal("string cancellation did not cancel string request ID")
	}
}

func TestLegacySignedSessionRequiresExplicitConfig(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	defaultServer, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken, RequireRequestSignature: true})
	request := signedGatewayRequest(t, body, DefaultEndpoint, "legacy-bridge", "legacy-session", "1")
	recorder := httptest.NewRecorder()
	defaultServer.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("legacy signed session enabled by default: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	legacyServer, _ := newStandardTestServer(t, Config{AuthToken: standardTestToken, RequireRequestSignature: true, AllowLegacySignedSession: true})
	request = signedGatewayRequest(t, body, DefaultEndpoint, "legacy-bridge", "legacy-session", "1")
	recorder = httptest.NewRecorder()
	legacyServer.ServeHTTP(recorder, request)
	var response protocol.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || response.Error != nil {
		t.Fatalf("explicit legacy signed session failed: status=%d response=%+v", recorder.Code, response)
	}
}
