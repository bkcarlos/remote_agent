package protocol

import "encoding/json"

const (
	Version = "2.0"

	ProtocolVersion20250326 = "2025-03-26"
	HeaderSessionID         = "Mcp-Session-Id"
	HeaderProtocolVersion   = "MCP-Protocol-Version"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type InitializeParams struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	ClientInfo      ClientInfo                 `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (r Request) IsNotification() bool { return len(r.ID) == 0 }

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type ToolContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
}

type ToolResult struct {
	Content  []ToolContent `json:"content"`
	IsError  bool          `json:"isError,omitempty"`
	PolicyID string        `json:"policy_id,omitempty"`
}

func Success(id json.RawMessage, result any) Response {
	return Response{JSONRPC: Version, ID: id, Result: result}
}
func Failure(id json.RawMessage, code int, message string, data any) Response {
	return Response{JSONRPC: Version, ID: id, Error: &Error{Code: code, Message: message, Data: data}}
}
