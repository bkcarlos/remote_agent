package fileworker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

const MaxJobBytes = 4 << 20

type Job struct {
	Token        string `json:"token"`
	RequestID    string `json:"request_id"`
	Operation    string `json:"operation"`
	Path         string `json:"path"`
	MaxBytes     int64  `json:"max_bytes,omitempty"`
	MaxEntries   int    `json:"max_entries,omitempty"`
	Data         string `json:"data_base64,omitempty"`
	ExpectedHash string `json:"expected_hash,omitempty"`
	Pattern      string `json:"pattern,omitempty"`
	Query        string `json:"query,omitempty"`
	MaxFiles     int    `json:"max_files,omitempty"`
	MaxResults   int    `json:"max_results,omitempty"`
}

type Response struct {
	Content  string              `json:"content_base64,omitempty"`
	Entries  []string            `json:"entries,omitempty"`
	Checksum string              `json:"sha256,omitempty"`
	Info     *workspace.FileInfo `json:"info,omitempty"`
	Matches  []workspace.Match   `json:"matches,omitempty"`
	Paths    []string            `json:"paths,omitempty"`
	Error    string              `json:"error,omitempty"`
}

type Service struct {
	fs   *workspace.FS
	caps *capability.Manager
}

func New(root string, key []byte) (*Service, error) {
	return NewWithDenied(root, key, nil)
}

func NewWithDenied(root string, key []byte, deniedNames []string) (*Service, error) {
	fs, err := workspace.NewWithDenied(root, deniedNames)
	if err != nil {
		return nil, err
	}
	caps, err := capability.New(key)
	if err != nil {
		return nil, err
	}
	return &Service{fs: fs, caps: caps}, nil
}

func (s *Service) Execute(j Job) Response {
	if err := s.authorize(j); err != nil {
		return Response{Error: err.Error()}
	}
	return s.executeAuthorized(j)
}

func (s *Service) authorize(j Job) error {
	if j.RequestID == "" || j.Operation == "" || j.Path == "" || j.Token == "" {
		return errors.New("incomplete worker job")
	}
	if _, err := s.caps.Verify(j.Token, j.RequestID, j.Operation, j.Path); err != nil {
		return errors.New("capability rejected: " + err.Error())
	}
	return nil
}

func (s *Service) executeAuthorized(j Job) Response {
	switch j.Operation {
	case "read_file":
		if j.MaxBytes <= 0 {
			return Response{Error: "invalid read limit"}
		}
		b, err := s.fs.ReadFile(j.Path, j.MaxBytes)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Content: base64.StdEncoding.EncodeToString(b)}
	case "list_dir":
		if j.MaxEntries <= 0 {
			return Response{Error: "invalid directory limit"}
		}
		entries, err := s.fs.List(j.Path, j.MaxEntries)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Entries: entries}
	case "checksum":
		sum, err := s.fs.Checksum(j.Path)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Checksum: sum}
	case "file_info":
		info, err := s.fs.Info(j.Path)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Info: &info}
	case "glob":
		paths, err := s.fs.Glob(j.Path, j.Pattern, j.MaxFiles, j.MaxResults)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Paths: paths}
	case "grep":
		matches, err := s.fs.Grep(j.Path, j.Query, j.MaxFiles, j.MaxResults, j.MaxBytes)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Matches: matches}
	case "write_file":
		if j.MaxBytes <= 0 {
			return Response{Error: "invalid write limit"}
		}
		b, err := base64.StdEncoding.DecodeString(j.Data)
		if err != nil {
			return Response{Error: "invalid data encoding"}
		}
		sum, err := s.fs.WriteFile(j.Path, b, j.ExpectedHash, j.MaxBytes)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Checksum: sum}
	default:
		return Response{Error: "operation is not supported by file worker"}
	}
}

func (s *Service) Serve(r io.Reader, w io.Writer) error {
	return s.ServeWithSandbox(r, w, nil)
}

func (s *Service) ServeWithSandbox(r io.Reader, w io.Writer, apply func(operation string) error) error {
	body, err := io.ReadAll(io.LimitReader(r, MaxJobBytes+1))
	if err != nil || len(body) > MaxJobBytes {
		return errors.New("worker job exceeds size limit")
	}
	var j Job
	if err := protocol.DecodeStrict(body, &j); err != nil {
		return errors.New("invalid worker job")
	}
	if err := s.authorize(j); err != nil {
		return json.NewEncoder(w).Encode(Response{Error: err.Error()})
	}
	if apply != nil {
		if err := apply(j.Operation); err != nil {
			return json.NewEncoder(w).Encode(Response{Error: "worker sandbox unavailable: " + err.Error()})
		}
	}
	return json.NewEncoder(w).Encode(s.executeAuthorized(j))
}

func Claims(requestID, operation, path, tokenID string) capability.Claims {
	return capability.Claims{TokenID: tokenID, RequestID: requestID, Operation: operation, Path: path, ExpiresAt: time.Now().UTC().Add(30 * time.Second), SingleUse: true}
}
