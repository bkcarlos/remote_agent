package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/replay"
	"github.com/bkcarlos/remote_agent/internal/transportauth"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

type Config struct {
	AuthToken               string
	ApprovalKey             []byte
	MaxBodyBytes            int64
	Transport               string
	RequireRequestSignature bool
	ReplayStore             replay.ChallengeStore
}
type FileExecutor interface {
	ReadFile(path string, max int64) ([]byte, error)
	List(path string, max int) ([]string, error)
	Checksum(path string) (string, error)
	Info(path string) (workspace.FileInfo, error)
	Glob(path, pattern string, maxFiles, maxResults int) ([]string, error)
	Grep(path, query string, maxFiles, maxResults int, maxBytes int64) ([]workspace.Match, error)
	WriteFile(path string, data []byte, expected string, max int64) (string, error)
}

type Server struct {
	cfg       Config
	fs        FileExecutor
	policy    *policy.Engine
	audit     *audit.Logger
	signature *transportauth.Verifier
	approvals *approval.Manager
}

func New(c Config, fs FileExecutor, p *policy.Engine, a *audit.Logger) (*Server, error) {
	if c.AuthToken == "" {
		return nil, errors.New("auth token is required")
	}
	if fs == nil || p == nil || a == nil {
		return nil, errors.New("file executor, policy, and audit logger are required")
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 2 << 20
	}
	if c.Transport == "" {
		c.Transport = "http"
	}
	replayStore := c.ReplayStore
	if replayStore == nil {
		replayStore = replay.NewMemory()
	}
	var approvals *approval.Manager
	if len(c.ApprovalKey) > 0 {
		var err error
		approvals, err = approval.NewWithChallengeStore(c.ApprovalKey, replayStore)
		if err != nil {
			return nil, err
		}
	}
	var verifier *transportauth.Verifier
	if c.RequireRequestSignature {
		var err error
		verifier, err = transportauth.NewVerifierWithStore([]byte(c.AuthToken), time.Minute, replayStore)
		if err != nil {
			return nil, err
		}
	}
	return &Server{cfg: c, fs: fs, policy: p, audit: a, signature: verifier, approvals: approvals}, nil
}
func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !equal(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), s.cfg.AuthToken) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(protocol.Failure(nil, -32700, "request body exceeds limit", nil))
		return
	}
	if s.signature != nil {
		err := s.signature.Verify(body, transportauth.Headers{Timestamp: r.Header.Get(transportauth.HeaderTimestamp), Nonce: r.Header.Get(transportauth.HeaderNonce), Signature: r.Header.Get(transportauth.HeaderSignature)})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(protocol.Failure(nil, -32001, "request signature rejected", nil))
			return
		}
	}
	var req protocol.Request
	if err := protocol.DecodeStrict(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(protocol.Failure(nil, -32700, "invalid JSON-RPC request", nil))
		return
	}
	if req.JSONRPC != protocol.Version || req.Method == "" {
		json.NewEncoder(w).Encode(protocol.Failure(req.ID, -32600, "invalid request", nil))
		return
	}
	requestID := newID()
	w.Header().Set("X-Request-ID", requestID)
	resp := s.dispatch(req, requestID, r.Header.Get("X-Session-ID"))
	json.NewEncoder(w).Encode(resp)
}
func newID() string {
	b := make([]byte, 12)
	if _, e := rand.Read(b); e != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req-" + hex.EncodeToString(b)
}
func (s *Server) dispatch(req protocol.Request, rid, sid string) protocol.Response {
	switch req.Method {
	case "initialize":
		return protocol.Success(req.ID, map[string]any{"protocolVersion": "2025-03-26", "serverInfo": map[string]string{"name": "secure-remote-agent", "version": "0.1.0"}, "capabilities": map[string]any{"tools": map[string]any{}}})
	case "notifications/initialized":
		return protocol.Success(req.ID, map[string]any{})
	case "tools/list":
		return protocol.Success(req.ID, map[string]any{"tools": s.tools()})
	case "tools/call":
		return s.call(req, rid, sid)
	default:
		return protocol.Failure(req.ID, -32601, "method not found", nil)
	}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}
type args struct {
	Path          string `json:"path"`
	Content       string `json:"content"`
	ExpectedHash  string `json:"expected_hash"`
	Apply         bool   `json:"apply"`
	ApprovalToken string `json:"approval_token"`
	Pattern       string `json:"pattern"`
	Query         string `json:"query"`
}

func (s *Server) call(req protocol.Request, rid, sid string) protocol.Response {
	var cp callParams
	if protocol.DecodeStrict(req.Params, &cp) != nil || cp.Name == "" || len(cp.Name) > 64 {
		return protocol.Failure(req.ID, -32602, "invalid tool parameters", nil)
	}
	var a args
	if len(cp.Arguments) == 0 || protocol.DecodeStrict(cp.Arguments, &a) != nil {
		return protocol.Failure(req.ID, -32602, "invalid tool arguments", nil)
	}
	if a.Path == "" || len(a.Path) > 4096 {
		return protocol.Failure(req.ID, -32602, "path must contain 1 to 4096 bytes", nil)
	}
	if a.ExpectedHash != "" && !validSHA256(a.ExpectedHash) {
		return protocol.Failure(req.ID, -32602, "expected_hash must be a lowercase SHA-256 value", nil)
	}
	if len(a.ApprovalToken) > 8192 || len(a.Pattern) > 1024 || len(a.Query) > 1024 {
		return protocol.Failure(req.ID, -32602, "tool argument exceeds its length limit", nil)
	}
	if cp.Name == "write_file" && int64(len(a.Content)) > s.policy.MaxWriteBytes() {
		return protocol.Failure(req.ID, -32602, "content exceeds the configured write limit", nil)
	}
	if cp.Name == "glob" && a.Pattern == "" {
		return protocol.Failure(req.ID, -32602, "glob pattern is required", nil)
	}
	if cp.Name == "grep" && a.Query == "" {
		return protocol.Failure(req.ID, -32602, "grep query is required", nil)
	}
	d := s.policy.Evaluate(cp.Name, a.Path)
	ev := audit.Event{RequestID: rid, SessionID: sid, Transport: s.cfg.Transport, Tool: cp.Name, Path: a.Path, PolicyID: d.PolicyID, Allowed: d.Allowed}
	if !d.Allowed {
		ev.Status = "denied"
		s.audit.Record(ev)
		return toolError(req.ID, d.Reason, d.PolicyID)
	}
	var result any
	var err error
	switch cp.Name {
	case "read_file":
		var b []byte
		b, err = s.fs.ReadFile(a.Path, s.policy.MaxReadBytes())
		result = map[string]any{"content": string(b), "bytes": len(b)}
		ev.OutputBytes = int64(len(b))
	case "list_dir":
		var names []string
		names, err = s.fs.List(a.Path, 10000)
		result = map[string]any{"entries": names}
	case "checksum":
		var sum string
		sum, err = s.fs.Checksum(a.Path)
		result = map[string]any{"sha256": sum}
	case "file_info":
		var info workspace.FileInfo
		info, err = s.fs.Info(a.Path)
		result = info
	case "glob":
		var paths []string
		paths, err = s.fs.Glob(a.Path, a.Pattern, 10000, 1000)
		result = map[string]any{"paths": paths}
	case "grep":
		var matches []workspace.Match
		matches, err = s.fs.Grep(a.Path, a.Query, 10000, 1000, 32<<20)
		result = map[string]any{"matches": matches}
	case "write_file":
		ev.InputBytes = int64(len(a.Content))
		contentDigest := sha256.Sum256([]byte(a.Content))
		contentHash := hex.EncodeToString(contentDigest[:])
		if !a.Apply {
			if sid == "" {
				err = errors.New("session ID is required for a write dry-run")
				break
			}
			if s.approvals == nil {
				err = errors.New("trusted approval service is not configured")
				break
			}
			old, checksumErr := s.fs.Checksum(a.Path)
			if checksumErr != nil && a.ExpectedHash != "" {
				err = checksumErr
				break
			}
			approvalID := newID()
			expires := time.Now().UTC().Add(5 * time.Minute)
			challenge := approval.Claims{ApprovalID: approvalID, SessionID: sid, Operation: "write_file", Path: a.Path, ContentSHA256: contentHash, ExpectedHash: old, ExpiresAt: expires}
			if challengeErr := s.approvals.RegisterChallenge(challenge); challengeErr != nil {
				err = errors.New("approval challenge storage unavailable")
				break
			}
			result = map[string]any{"dry_run": true, "path": a.Path, "before_sha256": old, "content_sha256": contentHash, "bytes": len(a.Content), "approval_required": true, "approval_id": approvalID, "approval_expires_at": expires, "session_id": sid, "operation": "write_file"}
			break
		}
		if sid == "" {
			err = errors.New("session ID is required for an approved write")
			break
		}
		if s.approvals == nil {
			err = errors.New("trusted approval service is not configured")
			break
		}
		if _, checksumErr := s.fs.Checksum(a.Path); checksumErr == nil && a.ExpectedHash == "" {
			err = errors.New("expected_hash is required when replacing an existing file")
			break
		}
		approved, approvalErr := s.approvals.Verify(a.ApprovalToken, approval.Scope{SessionID: sid, Operation: "write_file", Path: a.Path, ContentSHA256: contentHash, ExpectedHash: a.ExpectedHash})
		if approvalErr != nil {
			err = errors.New("valid trusted approval is required: " + approvalErr.Error())
			break
		}
		ev.ApprovalID = approved.ApprovalID
		ev.Status = "started"
		if auditErr := s.audit.Record(ev); auditErr != nil {
			return toolError(req.ID, "audit unavailable; write denied", d.PolicyID)
		}
		var sum string
		sum, err = s.fs.WriteFile(a.Path, []byte(a.Content), a.ExpectedHash, s.policy.MaxWriteBytes())
		result = map[string]any{"written": true, "sha256": sum}
	}
	if err != nil {
		ev.Status = "error"
		s.audit.Record(ev)
		return toolError(req.ID, err.Error(), d.PolicyID)
	}
	ev.Status = "success"
	if e := s.audit.Record(ev); e != nil && cp.Name == "write_file" {
		return toolError(req.ID, "audit unavailable; write result cannot be confirmed", d.PolicyID)
	}
	return protocol.Success(req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": mustJSON(result)}}})
}
func toolError(id json.RawMessage, msg, policyID string) protocol.Response {
	return protocol.Success(id, map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": msg}}, "policy_id": policyID})
}
func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func (s *Server) tools() []map[string]any {
	registered := []map[string]any{
		{"name": "read_file", "description": "Read a regular file inside the authorized workspace", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}}, "required": []string{"path"}}},
		{"name": "list_dir", "description": "List a directory inside the authorized workspace", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}}, "required": []string{"path"}}},
		{"name": "checksum", "description": "Compute SHA-256 for an authorized file", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}}, "required": []string{"path"}}},
		{"name": "file_info", "description": "Return metadata without exposing the host absolute path", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}}, "required": []string{"path"}}},
		{"name": "glob", "description": "Find workspace files matching a bounded relative glob", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}, "pattern": map[string]string{"type": "string"}}, "required": []string{"path", "pattern"}}},
		{"name": "grep", "description": "Search workspace text files with bounded traversal", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}, "query": map[string]string{"type": "string"}}, "required": []string{"path", "query"}}},
		{"name": "write_file", "description": "Preview or atomically write an authorized file; apply requires trusted approval", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}, "content": map[string]string{"type": "string"}, "expected_hash": map[string]string{"type": "string"}, "apply": map[string]string{"type": "boolean"}, "approval_token": map[string]string{"type": "string"}}, "required": []string{"path", "content"}}},
	}
	available := make([]map[string]any, 0, len(registered))
	for _, tool := range registered {
		name, _ := tool["name"].(string)
		if s.policy.Evaluate(name, "policy-probe.txt").Allowed {
			available = append(available, tool)
		}
	}
	return available
}
