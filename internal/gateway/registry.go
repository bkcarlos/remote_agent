package gateway

import (
	"encoding/json"
	"errors"

	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/protocol"
)

type toolArguments struct {
	Path            string
	Paths           []string
	Content         string
	ExpectedHash    string
	Apply           bool
	ApprovalToken   string
	StartLine       int
	EndLine         int
	Pattern         string
	Query           string
	Edits           []fileworker.Edit
	Files           []fileworker.EditFile
	Profile         string
	URL             string
	Method          string
	Headers         networkworker.Headers
	RemotePath      string
	DestinationPath string
	Argv            []string
	Env             map[string]string
	ProcessID       string
	Signal          string
	Memory          *execworker.MemoryScan
}

type toolSpec struct {
	Name        string
	Description string
	Risk        string
	Worker      string
	Approval    bool
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	OpenWorld   bool
	Schema      map[string]any
	Decode      func(json.RawMessage) (toolArguments, error)
}

type pathInput struct {
	Path string `json:"path"`
}
type readFileInput struct {
	Path      string `json:"path"`
	StartLine *int   `json:"start_line,omitempty"`
	EndLine   *int   `json:"end_line,omitempty"`
}
type multiReadInput struct {
	Paths []string `json:"paths"`
}
type searchInput struct {
	Path    string `json:"path"`
	Pattern string `json:"pattern,omitempty"`
	Query   string `json:"query,omitempty"`
}
type writeInput struct {
	Path          string `json:"path"`
	Content       string `json:"content"`
	ExpectedHash  string `json:"expected_hash,omitempty"`
	Apply         bool   `json:"apply,omitempty"`
	ApprovalToken string `json:"approval_token,omitempty"`
}
type diffInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
type editInput struct {
	Path          string            `json:"path"`
	Edits         []fileworker.Edit `json:"edits"`
	Apply         bool              `json:"apply,omitempty"`
	ApprovalToken string            `json:"approval_token,omitempty"`
}
type multiEditInput struct {
	Files         []fileworker.EditFile `json:"files"`
	Apply         bool                  `json:"apply,omitempty"`
	ApprovalToken string                `json:"approval_token,omitempty"`
}
type networkInput struct {
	Profile      string            `json:"profile"`
	URL          string            `json:"url"`
	Path         string            `json:"path,omitempty"`
	Method       string            `json:"method,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	ExpectedHash string            `json:"expected_hash,omitempty"`
}
type remoteInput struct {
	Profile         string   `json:"profile"`
	RemotePath      string   `json:"remote_path,omitempty"`
	DestinationPath string   `json:"destination_path,omitempty"`
	Path            string   `json:"path,omitempty"`
	Argv            []string `json:"argv,omitempty"`
}
type execInput struct {
	Profile        string            `json:"profile"`
	Argv           []string          `json:"argv,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	ProcessID      string            `json:"process_id,omitempty"`
	Signal         string            `json:"signal,omitempty"`
	Pattern        string            `json:"pattern,omitempty"`
	Mode           string            `json:"mode,omitempty"`
	IncludeContext bool              `json:"include_context,omitempty"`
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}

func stringProperty(max int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": max}
}

func registry() []toolSpec {
	pathSchema := objectSchema(map[string]any{"path": stringProperty(4096)}, "path")
	readFileSchema := objectSchema(map[string]any{
		"path": stringProperty(4096), "start_line": map[string]any{"type": "integer", "minimum": 1}, "end_line": map[string]any{"type": "integer", "minimum": 1},
	}, "path")
	editItem := objectSchema(map[string]any{
		"old": map[string]any{"type": "string", "minLength": 1, "maxLength": 1 << 20}, "new": map[string]any{"type": "string", "maxLength": 1 << 20},
		"mode": map[string]any{"type": "string", "enum": []string{"once", "all"}}, "adapt_indentation": map[string]any{"type": "boolean"},
	}, "old", "new")
	fileEdit := objectSchema(map[string]any{"path": stringProperty(4096), "edits": map[string]any{"type": "array", "minItems": 1, "maxItems": 128, "items": editItem}}, "path", "edits")
	profile := stringProperty(128)
	url := stringProperty(8192)
	headers := map[string]any{"type": "object", "maxProperties": 32, "additionalProperties": map[string]any{"type": "string", "maxLength": 8192}}
	argv := map[string]any{"type": "array", "maxItems": 64, "items": map[string]any{"type": "string", "maxLength": 4096}}
	env := map[string]any{"type": "object", "maxProperties": 32, "additionalProperties": map[string]any{"type": "string", "maxLength": 8192}}
	process := stringProperty(256)
	remotePath := stringProperty(4096)
	return []toolSpec{
		{Name: "read_file", Description: "Read and decode an authorized text file, optionally selecting up to 10000 decoded lines", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: readFileSchema, Decode: decodeReadFile},
		{Name: "read_image", Description: "Read a bounded PNG, JPEG, GIF, or WebP image identified by file magic", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: pathSchema, Decode: decodePath},
		{Name: "multi_read", Description: "Read and decode up to 20 authorized text files", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: objectSchema(map[string]any{"paths": map[string]any{"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": stringProperty(4096)}}, "paths"), Decode: decodeMultiRead},
		{Name: "list_dir", Description: "List a directory inside the authorized workspace", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: pathSchema, Decode: decodePath},
		{Name: "checksum", Description: "Compute SHA-256 for an authorized file", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: pathSchema, Decode: decodePath},
		{Name: "file_info", Description: "Return metadata without exposing the host absolute path", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: pathSchema, Decode: decodePath},
		{Name: "glob", Description: "Find workspace files matching a bounded relative glob", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: objectSchema(map[string]any{"path": stringProperty(4096), "pattern": stringProperty(1024)}, "path", "pattern"), Decode: decodeGlob},
		{Name: "grep", Description: "Search workspace text files with bounded traversal", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: objectSchema(map[string]any{"path": stringProperty(4096), "query": stringProperty(1024)}, "path", "query"), Decode: decodeGrep},
		{Name: "diff", Description: "Preview a bounded unified diff against decoded text", Risk: "L1", Worker: "file", ReadOnly: true, Idempotent: true, Schema: objectSchema(map[string]any{"path": stringProperty(4096), "content": map[string]any{"type": "string"}}, "path", "content"), Decode: decodeDiff},
		{Name: "edit", Description: "Preview or apply exact text replacements while preserving file format", Risk: "L2", Worker: "file", Approval: true, Destructive: true, Idempotent: true, Schema: objectSchema(map[string]any{"path": stringProperty(4096), "edits": map[string]any{"type": "array", "minItems": 1, "maxItems": 128, "items": editItem}, "apply": map[string]any{"type": "boolean"}, "approval_token": map[string]any{"type": "string", "maxLength": 32768}}, "path", "edits"), Decode: decodeEdit},
		{Name: "multi_edit", Description: "Preview or apply exact replacements to up to 20 files", Risk: "L2", Worker: "file", Approval: true, Destructive: true, Idempotent: true, Schema: objectSchema(map[string]any{"files": map[string]any{"type": "array", "minItems": 1, "maxItems": 20, "items": fileEdit}, "apply": map[string]any{"type": "boolean"}, "approval_token": map[string]any{"type": "string", "maxLength": 32768}}, "files"), Decode: decodeMultiEdit},
		{Name: "write_file", Description: "Preview or atomically write an authorized file", Risk: "L2", Worker: "file", Approval: true, Destructive: true, Idempotent: true, Schema: objectSchema(map[string]any{"path": stringProperty(4096), "content": map[string]any{"type": "string"}, "expected_hash": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}, "apply": map[string]any{"type": "boolean"}, "approval_token": map[string]any{"type": "string", "maxLength": 32768}}, "path", "content"), Decode: decodeWrite},
		{Name: "web_fetch", Description: "Fetch an administrator-allowlisted HTTP resource; response content is untrusted", Risk: "L3", Worker: "network", ReadOnly: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "url": url, "method": map[string]any{"type": "string", "enum": []string{"GET", "HEAD"}}, "headers": headers}, "profile", "url", "method"), Decode: decodeNetwork},
		{Name: "download", Description: "Download bytes through Network Worker and write them through File Worker", Risk: "L3", Worker: "network", Approval: true, Destructive: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "url": url, "path": stringProperty(4096), "expected_hash": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}}, "profile", "url", "path"), Decode: decodeNetwork},
		{Name: "upload", Description: "Read workspace bytes through File Worker and upload them to an administrator-allowlisted target", Risk: "L4", Worker: "network", Approval: true, Destructive: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "url": url, "path": stringProperty(4096), "method": map[string]any{"type": "string", "enum": []string{"POST", "PUT"}}, "headers": headers}, "profile", "url", "path", "method"), Decode: decodeNetwork},
		{Name: "ssh_exec", Description: "Execute an argv allowed by an administrator SSH profile", Risk: "L4", Worker: "remote", Approval: true, Destructive: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "argv": argv}, "profile", "argv"), Decode: decodeRemote},
		{Name: "sftp_list", Description: "List an administrator-allowlisted remote directory", Risk: "L3", Worker: "remote", ReadOnly: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "remote_path": remotePath}, "profile", "remote_path"), Decode: decodeRemote},
		{Name: "sftp_read", Description: "Read a small administrator-allowlisted remote file as base64 plus metadata", Risk: "L3", Worker: "remote", ReadOnly: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "remote_path": remotePath}, "profile", "remote_path"), Decode: decodeRemote},
		{Name: "sftp_write", Description: "Read local bytes through File Worker and write them to an allowlisted remote path", Risk: "L4", Worker: "remote", Approval: true, Destructive: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "remote_path": remotePath, "path": stringProperty(4096)}, "profile", "remote_path", "path"), Decode: decodeRemote},
		{Name: "sftp_mkdir", Description: "Create an allowlisted remote directory", Risk: "L4", Worker: "remote", Approval: true, Destructive: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "remote_path": remotePath}, "profile", "remote_path"), Decode: decodeRemote},
		{Name: "sftp_rename", Description: "Rename an allowlisted remote path", Risk: "L4", Worker: "remote", Approval: true, Destructive: true, Idempotent: true, OpenWorld: true, Schema: objectSchema(map[string]any{"profile": profile, "remote_path": remotePath, "destination_path": remotePath}, "profile", "remote_path", "destination_path"), Decode: decodeRemote},
		{Name: "exec_run", Description: "Run one administrator-fixed task and wait for completion", Risk: "L3", Worker: "exec", Destructive: true, Schema: objectSchema(map[string]any{"profile": profile, "argv": argv, "env": env}, "profile"), Decode: decodeExec},
		{Name: "process_start", Description: "Start one long-lived administrator-fixed task", Risk: "L3", Worker: "exec", Destructive: true, Schema: objectSchema(map[string]any{"profile": profile, "argv": argv, "env": env}, "profile"), Decode: decodeExec},
		{Name: "process_status", Description: "Read status and bounded output for a same-session managed child", Risk: "L3", Worker: "exec", ReadOnly: true, Idempotent: true, Schema: objectSchema(map[string]any{"profile": profile, "process_id": process}, "profile", "process_id"), Decode: decodeExec},
		{Name: "process_stop", Description: "Stop a same-session managed child", Risk: "L4", Worker: "exec", Approval: true, Destructive: true, Idempotent: true, Schema: objectSchema(map[string]any{"profile": profile, "process_id": process}, "profile", "process_id"), Decode: decodeExec},
		{Name: "debug_status", Description: "Read debug state for a same-session managed child", Risk: "L3", Worker: "exec", ReadOnly: true, Idempotent: true, Schema: objectSchema(map[string]any{"profile": profile, "process_id": process}, "profile", "process_id"), Decode: decodeExec},
		{Name: "debug_signal", Description: "Send a bounded named signal to a same-session managed child", Risk: "L4", Worker: "exec", Approval: true, Destructive: true, Schema: objectSchema(map[string]any{"profile": profile, "process_id": process, "signal": map[string]any{"type": "string", "enum": []string{"stop", "continue", "interrupt", "terminate"}}}, "profile", "process_id", "signal"), Decode: decodeExec},
		{Name: "mem_scan", Description: "Scan a same-session managed child using a bounded pattern without accepting addresses or writes", Risk: "L4", Worker: "exec", Approval: true, ReadOnly: true, Schema: objectSchema(map[string]any{"profile": profile, "process_id": process, "pattern": stringProperty(4096), "mode": map[string]any{"type": "string", "enum": []string{"hex", "base64"}}, "include_context": map[string]any{"type": "boolean"}}, "profile", "process_id", "pattern", "mode"), Decode: decodeExec},
	}
}

func decodeInto[T any](raw json.RawMessage) (T, error) {
	var value T
	if len(raw) == 0 || protocol.DecodeStrict(raw, &value) != nil {
		return value, errors.New("invalid tool arguments")
	}
	return value, nil
}

func decodePath(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[pathInput](raw)
	return toolArguments{Path: v.Path}, e
}
func decodeReadFile(raw json.RawMessage) (toolArguments, error) {
	v, err := decodeInto[readFileInput](raw)
	if err != nil || (v.StartLine == nil) != (v.EndLine == nil) {
		return toolArguments{}, errors.New("invalid tool arguments")
	}
	arguments := toolArguments{Path: v.Path}
	if v.StartLine != nil {
		arguments.StartLine, arguments.EndLine = *v.StartLine, *v.EndLine
		if arguments.StartLine < 1 || arguments.EndLine < arguments.StartLine || arguments.EndLine-arguments.StartLine+1 > fileworker.MaxLineRange {
			return toolArguments{}, errors.New("invalid tool arguments")
		}
	}
	return arguments, nil
}
func decodeMultiRead(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[multiReadInput](raw)
	return toolArguments{Paths: v.Paths}, e
}
func decodeGlob(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[searchInput](raw)
	return toolArguments{Path: v.Path, Pattern: v.Pattern}, e
}
func decodeGrep(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[searchInput](raw)
	return toolArguments{Path: v.Path, Query: v.Query}, e
}
func decodeWrite(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[writeInput](raw)
	return toolArguments{Path: v.Path, Content: v.Content, ExpectedHash: v.ExpectedHash, Apply: v.Apply, ApprovalToken: v.ApprovalToken}, e
}
func decodeDiff(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[diffInput](raw)
	return toolArguments{Path: v.Path, Content: v.Content}, e
}
func decodeEdit(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[editInput](raw)
	return toolArguments{Path: v.Path, Edits: v.Edits, Apply: v.Apply, ApprovalToken: v.ApprovalToken}, e
}
func decodeMultiEdit(raw json.RawMessage) (toolArguments, error) {
	v, e := decodeInto[multiEditInput](raw)
	return toolArguments{Files: v.Files, Apply: v.Apply, ApprovalToken: v.ApprovalToken}, e
}
func decodeNetwork(raw json.RawMessage) (toolArguments, error) {
	v, err := decodeInto[networkInput](raw)
	headers := make(networkworker.Headers, len(v.Headers))
	for name, value := range v.Headers {
		headers[name] = []string{value}
	}
	return toolArguments{Profile: v.Profile, URL: v.URL, Path: v.Path, Method: v.Method, Headers: headers, ExpectedHash: v.ExpectedHash}, err
}
func decodeRemote(raw json.RawMessage) (toolArguments, error) {
	v, err := decodeInto[remoteInput](raw)
	return toolArguments{Profile: v.Profile, RemotePath: v.RemotePath, DestinationPath: v.DestinationPath, Path: v.Path, Argv: v.Argv}, err
}
func decodeExec(raw json.RawMessage) (toolArguments, error) {
	v, err := decodeInto[execInput](raw)
	arguments := toolArguments{Profile: v.Profile, Argv: v.Argv, Env: v.Env, ProcessID: v.ProcessID, Signal: v.Signal, Pattern: v.Pattern}
	if v.Pattern != "" || v.Mode != "" || v.IncludeContext {
		arguments.Memory = &execworker.MemoryScan{Pattern: v.Pattern, Mode: v.Mode, IncludeContext: v.IncludeContext}
	}
	return arguments, err
}
