package networkworker

import "time"

const (
	WorkerType             = "network"
	OperationWebFetch      = "web_fetch"
	OperationDownload      = "download"
	OperationUpload        = "upload"
	MaxJobBytes            = 24 << 20
	MaxWorkerResponseBytes = 24 << 20

	maxRequestBodyBytes  = 16 << 20
	maxResponseBodyBytes = 16 << 20
	maxHeaderBytes       = 64 << 10
	maxRedirects         = 10
	maxTimeout           = 60 * time.Second
)

type Headers map[string][]string

type ResourceLimits struct {
	MaxRequestBodyBytes    int64 `json:"max_request_body_bytes"`
	MaxResponseBodyBytes   int64 `json:"max_response_body_bytes"`
	MaxRequestHeaderBytes  int64 `json:"max_request_header_bytes"`
	MaxResponseHeaderBytes int64 `json:"max_response_header_bytes"`
	MaxRedirects           int   `json:"max_redirects"`
	TimeoutMillis          int64 `json:"timeout_millis"`
}

type Policy struct {
	AllowedDomains        []string `json:"allowed_domains"`
	AllowedPorts          []uint16 `json:"allowed_ports"`
	AllowedSchemes        []string `json:"allowed_schemes"`
	AllowedCIDRs          []string `json:"allowed_cidrs"`
	AllowedRequestHeaders []string `json:"allowed_request_headers"`
	AllowPrivate          bool     `json:"allow_private"`
}

type Job struct {
	Token           string         `json:"token"`
	TokenID         string         `json:"token_id"`
	WorkerType      string         `json:"worker_type"`
	RequestID       string         `json:"request_id"`
	Principal       string         `json:"principal"`
	WorkspaceID     string         `json:"workspace_id"`
	BridgeID        string         `json:"bridge_id"`
	SessionID       string         `json:"session_id"`
	ClientRequestID string         `json:"client_request_id"`
	Operation       string         `json:"operation"`
	URL             string         `json:"url"`
	Method          string         `json:"method"`
	Headers         Headers        `json:"headers"`
	BodyBase64      string         `json:"body_base64,omitempty"`
	PolicyID        string         `json:"policy_id"`
	ProfileID       string         `json:"profile_id"`
	Policy          Policy         `json:"policy"`
	Limits          ResourceLimits `json:"limits"`
}

type Response struct {
	TokenID   string  `json:"token_id,omitempty"`
	WorkerID  string  `json:"worker_id,omitempty"`
	Status    int     `json:"status,omitempty"`
	Headers   Headers `json:"headers,omitempty"`
	Text      string  `json:"text,omitempty"`
	Base64    string  `json:"base64,omitempty"`
	MIMEType  string  `json:"mime_type,omitempty"`
	Bytes     int64   `json:"bytes,omitempty"`
	SHA256    string  `json:"sha256,omitempty"`
	Untrusted bool    `json:"untrusted"`
	Error     string  `json:"error,omitempty"`
}

type Claims struct {
	TokenID         string         `json:"token_id"`
	WorkerType      string         `json:"worker_type"`
	RequestID       string         `json:"request_id"`
	Principal       string         `json:"principal"`
	WorkspaceID     string         `json:"workspace_id"`
	BridgeID        string         `json:"bridge_id"`
	SessionID       string         `json:"session_id"`
	ClientRequestID string         `json:"client_request_id"`
	Operation       string         `json:"operation"`
	URL             string         `json:"url"`
	Method          string         `json:"method"`
	HeadersSHA256   string         `json:"headers_sha256"`
	BodySHA256      string         `json:"body_sha256"`
	PolicyID        string         `json:"policy_id"`
	ProfileID       string         `json:"profile_id"`
	PolicySHA256    string         `json:"policy_sha256"`
	Limits          ResourceLimits `json:"limits"`
	ExpiresAt       time.Time      `json:"expires_at"`
	SingleUse       bool           `json:"single_use"`
}

type Scope struct {
	TokenID         string
	WorkerType      string
	RequestID       string
	Principal       string
	WorkspaceID     string
	BridgeID        string
	SessionID       string
	ClientRequestID string
	Operation       string
	URL             string
	Method          string
	HeadersSHA256   string
	BodySHA256      string
	PolicyID        string
	ProfileID       string
	PolicySHA256    string
	Limits          ResourceLimits
}
