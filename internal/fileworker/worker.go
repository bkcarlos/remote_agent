package fileworker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/protocol"
	"github.com/bkcarlos/remote_agent/internal/textfile"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

const (
	MaxJobBytes = 4 << 20
	// MaxBinaryBytes is the conservative raw-byte transfer ceiling after
	// accounting for base64 and JSON framing in both request and response limits.
	MaxBinaryBytes           = 2 << 20
	FileWorkerType           = "file"
	maxBatchFiles            = 20
	maxEditorConfigBytes     = 64 << 10
	maxEditorConfigTotal     = 256 << 10
	maxEditorConfigAncestors = 64
	MaxLineRange             = 10000
)

type Job struct {
	Token            string     `json:"token"`
	TokenID          string     `json:"token_id"`
	WorkerType       string     `json:"worker_type"`
	RequestID        string     `json:"request_id"`
	BridgeID         string     `json:"bridge_id,omitempty"`
	SessionID        string     `json:"session_id"`
	ClientRequestID  string     `json:"client_request_id,omitempty"`
	AuthPrincipal    string     `json:"auth_principal,omitempty"`
	Operation        string     `json:"operation"`
	Path             string     `json:"path"`
	Paths            []string   `json:"paths,omitempty"`
	PolicyID         string     `json:"policy_id"`
	WorkerPolicyID   string     `json:"worker_policy_id"`
	PolicyDecision   string     `json:"policy_decision,omitempty"`
	ApprovalRequired bool       `json:"approval_required,omitempty"`
	ArgumentsSHA256  string     `json:"arguments_sha256"`
	MaxBytes         int64      `json:"max_bytes"`
	StartLine        int        `json:"start_line,omitempty"`
	EndLine          int        `json:"end_line,omitempty"`
	MaxEntries       int        `json:"max_entries"`
	Data             string     `json:"data_base64,omitempty"`
	ExpectedHash     string     `json:"expected_hash,omitempty"`
	ContentSHA256    string     `json:"content_sha256,omitempty"`
	Pattern          string     `json:"pattern,omitempty"`
	Query            string     `json:"query,omitempty"`
	MaxFiles         int        `json:"max_files"`
	MaxResults       int        `json:"max_results"`
	Edits            []Edit     `json:"edits,omitempty"`
	Files            []EditFile `json:"files,omitempty"`
	Apply            bool       `json:"apply,omitempty"`
	Targets          []Target   `json:"targets,omitempty"`
}

type TextMetadata struct {
	Encoding        string  `json:"encoding"`
	BOM             string  `json:"bom"`
	Newline         string  `json:"newline"`
	DominantNewline string  `json:"dominant_newline"`
	Confidence      float64 `json:"confidence"`
}

type FileResult struct {
	Path         string        `json:"path"`
	Content      string        `json:"content,omitempty"`
	Bytes        int           `json:"bytes,omitempty"`
	StartLine    int           `json:"start_line,omitempty"`
	EndLine      int           `json:"end_line,omitempty"`
	TotalLines   int           `json:"total_lines,omitempty"`
	Truncated    bool          `json:"truncated,omitempty"`
	BeforeSHA256 string        `json:"before_sha256,omitempty"`
	AfterSHA256  string        `json:"after_sha256,omitempty"`
	Diff         string        `json:"diff,omitempty"`
	Metadata     *TextMetadata `json:"metadata,omitempty"`
	Replacements int           `json:"replacements,omitempty"`
}

type ErrorKind string

const (
	ErrorKindInvalidPath     ErrorKind = "invalid_path"
	ErrorKindDeniedPath      ErrorKind = "denied_path"
	ErrorKindNotFound        ErrorKind = "not_found"
	ErrorKindPermission      ErrorKind = "permission"
	ErrorKindNotDirectory    ErrorKind = "not_directory"
	ErrorKindInvalidFileType ErrorKind = "invalid_file_type"
	ErrorKindUnsafeFile      ErrorKind = "unsafe_file"
	ErrorKindLimitExceeded   ErrorKind = "limit_exceeded"
	ErrorKindInvalidPattern  ErrorKind = "invalid_pattern"
	ErrorKindConflict        ErrorKind = "conflict"
	ErrorKindIO              ErrorKind = "io"
)

type Response struct {
	TokenID    string              `json:"token_id,omitempty"`
	WorkerID   string              `json:"worker_id,omitempty"`
	Content    string              `json:"content,omitempty"`
	Base64     string              `json:"base64,omitempty"`
	MIMEType   string              `json:"mime_type,omitempty"`
	Bytes      int                 `json:"bytes,omitempty"`
	Width      int                 `json:"width,omitempty"`
	Height     int                 `json:"height,omitempty"`
	StartLine  int                 `json:"start_line"`
	EndLine    int                 `json:"end_line"`
	TotalLines int                 `json:"total_lines"`
	Truncated  bool                `json:"truncated"`
	Metadata   *TextMetadata       `json:"metadata,omitempty"`
	Entries    []string            `json:"entries,omitempty"`
	Checksum   string              `json:"sha256,omitempty"`
	Info       *workspace.FileInfo `json:"info,omitempty"`
	Matches    []workspace.Match   `json:"matches,omitempty"`
	Paths      []string            `json:"paths,omitempty"`
	Files      []FileResult        `json:"files,omitempty"`
	Diff       string              `json:"diff,omitempty"`
	Error      string              `json:"error,omitempty"`
	ErrorKind  ErrorKind           `json:"error_kind,omitempty"`
	RolledBack bool                `json:"rolled_back,omitempty"`
}

// ErrorKindFor returns the stable, path-free category carried across the
// worker protocol. Non-workspace errors intentionally have no category.
func ErrorKindFor(err error) ErrorKind {
	switch {
	case errors.Is(err, workspace.ErrInvalidPath):
		return ErrorKindInvalidPath
	case errors.Is(err, workspace.ErrDeniedPath):
		return ErrorKindDeniedPath
	case errors.Is(err, workspace.ErrNotFound):
		return ErrorKindNotFound
	case errors.Is(err, workspace.ErrPermission):
		return ErrorKindPermission
	case errors.Is(err, workspace.ErrNotDirectory):
		return ErrorKindNotDirectory
	case errors.Is(err, workspace.ErrInvalidFileType):
		return ErrorKindInvalidFileType
	case errors.Is(err, workspace.ErrUnsafeFile):
		return ErrorKindUnsafeFile
	case errors.Is(err, workspace.ErrLimitExceeded):
		return ErrorKindLimitExceeded
	case errors.Is(err, workspace.ErrInvalidPattern):
		return ErrorKindInvalidPattern
	case errors.Is(err, workspace.ErrConflict):
		return ErrorKindConflict
	case errors.Is(err, workspace.ErrIO):
		return ErrorKindIO
	default:
		return ""
	}
}

func errorResponse(err error) Response {
	return Response{Error: err.Error(), ErrorKind: ErrorKindFor(err)}
}

func workspaceErrorForKind(kind ErrorKind) error {
	switch kind {
	case ErrorKindInvalidPath:
		return workspace.ErrInvalidPath
	case ErrorKindDeniedPath:
		return workspace.ErrDeniedPath
	case ErrorKindNotFound:
		return workspace.ErrNotFound
	case ErrorKindPermission:
		return workspace.ErrPermission
	case ErrorKindNotDirectory:
		return workspace.ErrNotDirectory
	case ErrorKindInvalidFileType:
		return workspace.ErrInvalidFileType
	case ErrorKindUnsafeFile:
		return workspace.ErrUnsafeFile
	case ErrorKindLimitExceeded:
		return workspace.ErrLimitExceeded
	case ErrorKindInvalidPattern:
		return workspace.ErrInvalidPattern
	case ErrorKindConflict:
		return workspace.ErrConflict
	case ErrorKindIO:
		return workspace.ErrIO
	default:
		return nil
	}
}

type workspaceFileSystem interface {
	ReadFile(string, int64) ([]byte, error)
	List(string, int) ([]string, error)
	Checksum(string) (string, error)
	Info(string) (workspace.FileInfo, error)
	Glob(string, string, int, int) ([]string, error)
	Grep(string, string, int, int, int64) ([]workspace.Match, error)
	WriteFile(string, []byte, string, int64) (string, error)
}

type Service struct {
	fs       workspaceFileSystem
	caps     *capability.Verifier
	policyID string
	workerID string
	root     string
}

func New(root string, publicKey ed25519.PublicKey) (*Service, error) {
	return NewWithDenied(root, publicKey, nil)
}

func NewWithDenied(root string, publicKey ed25519.PublicKey, deniedNames []string) (*Service, error) {
	fs, err := workspace.NewWithDenied(root, deniedNames)
	if err != nil {
		return nil, err
	}
	caps, err := capability.NewVerifier(publicKey)
	if err != nil {
		return nil, err
	}
	canonicalRoot, canonicalErr := filepath.Abs(root)
	if canonicalErr != nil {
		return nil, errors.New("workspace path is invalid")
	}
	if resolved, resolveErr := filepath.EvalSymlinks(canonicalRoot); resolveErr == nil {
		canonicalRoot = resolved
	}
	return &Service{fs: fs, caps: caps, policyID: workerPolicyID(deniedNames), workerID: randomID("worker-"), root: canonicalRoot}, nil
}

func (s *Service) Execute(job Job) Response {
	claims, err := s.authorize(job)
	if err != nil {
		return Response{Error: s.safeError(err)}
	}
	return s.finish(claims, s.executeAuthorized(job))
}

func (s *Service) authorize(job Job) (capability.Claims, error) {
	if job.Token == "" {
		return capability.Claims{}, errors.New("incomplete worker job")
	}
	if job.WorkerPolicyID != s.policyID {
		return capability.Claims{}, errors.New("worker policy mismatch")
	}
	scope, err := scopeForJob(job)
	if err != nil {
		return capability.Claims{}, err
	}
	claims, err := s.caps.Verify(job.Token, scope)
	if err != nil {
		return capability.Claims{}, errors.New("capability rejected: " + err.Error())
	}
	if !claims.SingleUse {
		return capability.Claims{}, errors.New("capability rejected: file worker capability must be single-use")
	}
	if claims.TokenID != job.TokenID {
		return capability.Claims{}, errors.New("capability rejected: token identity mismatch")
	}
	return claims, nil
}

func (s *Service) finish(claims capability.Claims, response Response) Response {
	response.TokenID = claims.TokenID
	response.WorkerID = s.workerID
	if response.Error != "" {
		response.Error = s.safeError(errors.New(response.Error))
	}
	return response
}

func (s *Service) safeError(err error) string {
	value := err.Error()
	for _, root := range []string{s.root, strings.ReplaceAll(s.root, "\\", "/")} {
		if root != "" {
			value = strings.ReplaceAll(value, root, "[workspace]")
		}
	}
	return value
}

func (s *Service) executeAuthorized(job Job) Response {
	switch job.Operation {
	case "read_file":
		file, err := s.readText(job.Path, job.MaxBytes, job.StartLine, job.EndLine)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Content: file.Content, Bytes: file.Bytes, Checksum: file.BeforeSHA256, Metadata: file.Metadata, StartLine: file.StartLine, EndLine: file.EndLine, TotalLines: file.TotalLines, Truncated: file.Truncated}
	case "read_binary":
		raw, err := s.fs.ReadFile(job.Path, job.MaxBytes)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Base64: base64.StdEncoding.EncodeToString(raw), Bytes: len(raw), Checksum: digestBytes(raw)}
	case "read_image":
		image, err := s.readImage(job.Path, job.MaxBytes)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Base64: image.Base64, MIMEType: image.MIMEType, Bytes: image.Bytes, Checksum: image.SHA256, Width: image.Width, Height: image.Height}
	case "multi_read":
		files, err := s.multiRead(job.Paths, job.MaxBytes)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Files: files}
	case "list_dir":
		entries, err := s.fs.List(job.Path, job.MaxEntries)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Entries: entries}
	case "checksum":
		sum, err := s.fs.Checksum(job.Path)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Checksum: sum}
	case "file_info":
		info, err := s.fs.Info(job.Path)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Info: &info}
	case "glob":
		paths, err := s.fs.Glob(job.Path, job.Pattern, job.MaxFiles, job.MaxResults)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Paths: paths}
	case "grep":
		matches, err := s.fs.Grep(job.Path, job.Query, job.MaxFiles, job.MaxResults, job.MaxBytes)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Matches: matches}
	case "diff":
		return s.diff(job)
	case "edit", "multi_edit":
		return s.edit(job)
	case "write_file":
		data, err := decodeJobData(job)
		if err != nil {
			return errorResponse(err)
		}
		sum, err := s.fs.WriteFile(job.Path, data, job.ExpectedHash, job.MaxBytes)
		if err != nil {
			return errorResponse(err)
		}
		return Response{Checksum: sum}
	default:
		return Response{Error: "operation is not supported by file worker"}
	}
}

func (s *Service) readText(path string, max int64, startLine, endLine int) (FileResult, error) {
	raw, err := s.fs.ReadFile(path, max)
	if err != nil {
		return FileResult{}, err
	}
	result, err := DecodeText(raw, max, startLine, endLine)
	if err != nil {
		return FileResult{}, err
	}
	result.Path = path
	return result, nil
}

// DecodeText decodes raw file bytes before applying a bounded line range to the
// resulting Unicode text. Bytes and hash always describe the complete raw file.
func DecodeText(raw []byte, max int64, startLine, endLine int) (FileResult, error) {
	decoded, err := textfile.Decode(raw, textLimits(max))
	if err != nil {
		return FileResult{}, err
	}
	content, actualStart, actualEnd, total, truncated, err := sliceTextLines(decoded.Text(), startLine, endLine)
	if err != nil {
		return FileResult{}, err
	}
	meta := decoded.Metadata()
	return FileResult{Content: content, Bytes: len(raw), StartLine: actualStart, EndLine: actualEnd, TotalLines: total, Truncated: truncated, BeforeSHA256: digestBytes(raw), Metadata: metadataResult(meta)}, nil
}

func sliceTextLines(text string, startLine, endLine int) (string, int, int, int, bool, error) {
	if err := validateLineRange(startLine, endLine); err != nil {
		return "", 0, 0, 0, false, err
	}
	type span struct{ start, end int }
	lines := make([]span, 0, strings.Count(text, "\n")+1)
	lineStart := 0
	for index, r := range text {
		separatorEnd := index
		switch r {
		case '\r':
			separatorEnd += 1
			if separatorEnd < len(text) && text[separatorEnd] == '\n' {
				separatorEnd++
			}
		case '\n':
			if index > 0 && text[index-1] == '\r' {
				continue
			}
			separatorEnd += 1
		case '\u0085':
			separatorEnd += len("\u0085")
		case '\u2028', '\u2029':
			separatorEnd += len("\u2028")
		default:
			continue
		}
		lines = append(lines, span{start: lineStart, end: separatorEnd})
		lineStart = separatorEnd
	}
	if lineStart < len(text) {
		lines = append(lines, span{start: lineStart, end: len(text)})
	}
	total := len(lines)
	if startLine == 0 {
		if total == 0 {
			return text, 0, 0, 0, false, nil
		}
		return text, 1, total, total, false, nil
	}
	if startLine > total {
		return "", 0, 0, total, false, errors.New("requested line range starts after end of file")
	}
	actualEnd := endLine
	if actualEnd > total {
		actualEnd = total
	}
	content := text[lines[startLine-1].start:lines[actualEnd-1].end]
	return content, startLine, actualEnd, total, startLine > 1 || actualEnd < total, nil
}

func validateLineRange(startLine, endLine int) error {
	if startLine == 0 && endLine == 0 {
		return nil
	}
	if startLine < 1 || endLine < 1 || startLine > endLine || endLine-startLine+1 > MaxLineRange {
		return errors.New("start_line and end_line must form a range of at most 10000 lines")
	}
	return nil
}

func (s *Service) multiRead(paths []string, max int64) ([]FileResult, error) {
	if len(paths) == 0 || len(paths) > maxBatchFiles {
		return nil, errors.New("multi_read file count must be between 1 and 20")
	}
	remaining := max
	results := make([]FileResult, 0, len(paths))
	for _, path := range paths {
		if remaining <= 0 {
			return nil, errors.New("multi_read total byte limit exceeded")
		}
		result, err := s.readText(path, remaining, 0, 0)
		if err != nil {
			return nil, err
		}
		remaining -= int64(result.Bytes)
		results = append(results, result)
	}
	return results, nil
}

func (s *Service) diff(job Job) Response {
	original, err := s.readText(job.Path, job.MaxBytes, 0, 0)
	if err != nil {
		return errorResponse(err)
	}
	data, err := decodeJobData(job)
	if err != nil {
		return errorResponse(err)
	}
	if int64(len(data)) > job.MaxBytes {
		return Response{Error: "diff content exceeds byte limit"}
	}
	diff, err := textfile.UnifiedDiff(original.Content, string(data), textfile.DiffOptions{OldName: "a/" + job.Path, NewName: "b/" + job.Path, Context: textfile.DefaultDiffContext})
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{Diff: diff, Files: []FileResult{{Path: job.Path, Diff: diff, BeforeSHA256: original.BeforeSHA256, AfterSHA256: digestBytes(data), Metadata: original.Metadata}}}
}

type editPlan struct {
	result   FileResult
	original []byte
	updated  []byte
}

func (s *Service) edit(job Job) Response {
	files := job.Files
	if job.Operation == "edit" {
		files = []EditFile{{Path: job.Path, Edits: job.Edits}}
	}
	plans, err := s.preflightEdits(files, job.MaxBytes)
	if err != nil {
		return errorResponse(err)
	}
	results := make([]FileResult, len(plans))
	actualTargets := make([]Target, len(plans))
	for i := range plans {
		results[i] = plans[i].result
		actualTargets[i] = Target{Path: plans[i].result.Path, BeforeSHA256: plans[i].result.BeforeSHA256, AfterSHA256: plans[i].result.AfterSHA256}
	}
	if !job.Apply {
		return Response{Files: results}
	}
	if !targetsEqual(actualTargets, job.Targets) {
		return Response{Error: "edit target changed after approval preflight"}
	}
	// The worker completes this bounded, best-effort rollback transaction once
	// started. This prevents client cancellation from creating a partial batch;
	// it is not atomic across worker SIGKILL, host failure, or power loss.
	written := 0
	for i := range plans {
		if _, err := s.fs.WriteFile(plans[i].result.Path, plans[i].updated, plans[i].result.BeforeSHA256, job.MaxBytes); err != nil {
			failureKind := ErrorKindFor(err)
			rollbackOK := true
			rolledBack := false
			currentHash, checksumErr := s.fs.Checksum(plans[i].result.Path)
			switch {
			case checksumErr != nil:
				rollbackOK = false
			case currentHash == plans[i].result.AfterSHA256:
				rolledBack = true
				if !s.restoreEdit(plans[i], job.MaxBytes) {
					rollbackOK = false
				}
			case currentHash == plans[i].result.BeforeSHA256:
				// The failed write did not change the current target.
			default:
				rollbackOK = false
			}
			for previous := written - 1; previous >= 0; previous-- {
				rolledBack = true
				if !s.restoreEdit(plans[previous], job.MaxBytes) {
					rollbackOK = false
				}
			}
			if !rollbackOK {
				return Response{Error: "batch edit failed and rollback was incomplete", ErrorKind: failureKind, Files: results}
			}
			return Response{Error: "batch edit failed; completed writes were rolled back", ErrorKind: failureKind, Files: results, RolledBack: rolledBack}
		}
		written++
	}
	return Response{Files: results}
}

func (s *Service) restoreEdit(plan editPlan, max int64) bool {
	if _, err := s.fs.WriteFile(plan.result.Path, plan.original, plan.result.AfterSHA256, max); err == nil {
		return true
	}
	currentHash, err := s.fs.Checksum(plan.result.Path)
	return err == nil && currentHash == plan.result.BeforeSHA256
}

func (s *Service) preflightEdits(files []EditFile, max int64) ([]editPlan, error) {
	if len(files) == 0 || len(files) > maxBatchFiles {
		return nil, errors.New("edit file count must be between 1 and 20")
	}
	seen := make(map[string]struct{}, len(files))
	plans := make([]editPlan, 0, len(files))
	var inputTotal, outputTotal int64
	for _, item := range files {
		if _, exists := seen[item.Path]; exists {
			return nil, errors.New("edit paths must be unique")
		}
		seen[item.Path] = struct{}{}
		remaining := max - inputTotal
		if remaining <= 0 {
			return nil, errors.New("edit total byte limit exceeded")
		}
		raw, err := s.fs.ReadFile(item.Path, remaining)
		if err != nil {
			return nil, err
		}
		inputTotal += int64(len(raw))
		file, err := textfile.Decode(raw, textLimits(max))
		if err != nil {
			return nil, err
		}
		indentation := textfile.DefaultIndentation()
		if editsAdaptIndentation(item.Edits) {
			indentation, err = s.indentationFor(item.Path)
			if err != nil {
				return nil, err
			}
		}
		edits, err := convertEdits(item.Edits, indentation)
		if err != nil {
			return nil, err
		}
		edits = adaptEditNewlines(edits, file.Metadata().DominantNewline)
		preview, err := file.Preview(edits, textfile.DiffOptions{OldName: "a/" + item.Path, NewName: "b/" + item.Path, Context: textfile.DefaultDiffContext})
		if err != nil {
			return nil, err
		}
		applied, err := file.Apply(edits)
		if err != nil {
			return nil, err
		}
		updated, err := file.Encode()
		if err != nil {
			return nil, err
		}
		outputTotal += int64(len(updated))
		if outputTotal > max {
			return nil, errors.New("edit total output byte limit exceeded")
		}
		replacements := 0
		for _, result := range applied {
			replacements += result.Replacements
		}
		meta := metadataResult(file.Metadata())
		plans = append(plans, editPlan{result: FileResult{Path: item.Path, Bytes: len(updated), BeforeSHA256: digestBytes(raw), AfterSHA256: digestBytes(updated), Diff: preview.Diff, Metadata: meta, Replacements: replacements}, original: raw, updated: updated})
	}
	return plans, nil
}

func editsAdaptIndentation(edits []Edit) bool {
	for _, edit := range edits {
		if edit.AdaptIndentation {
			return true
		}
	}
	return false
}

func adaptEditNewlines(edits []textfile.Edit, style textfile.NewlineStyle) []textfile.Edit {
	if style == textfile.NewlineNone {
		return edits
	}
	separator := "\n"
	if style == textfile.NewlineCRLF {
		separator = "\r\n"
	} else if style == textfile.NewlineCR {
		separator = "\r"
	}
	adapted := append([]textfile.Edit(nil), edits...)
	for i := range adapted {
		value := strings.ReplaceAll(adapted[i].New, "\r\n", "\n")
		value = strings.ReplaceAll(value, "\r", "\n")
		adapted[i].New = strings.ReplaceAll(value, "\n", separator)
	}
	return adapted
}

func (s *Service) indentationFor(target string) (textfile.Indentation, error) {
	directory := path.Dir(target)
	configs := make([]textfile.EditorConfig, 0, 4)
	totalBytes := 0
	for ancestor := 0; ; ancestor++ {
		if ancestor >= maxEditorConfigAncestors {
			return textfile.Indentation{}, errors.New("editorconfig ancestor depth exceeds limit")
		}
		configPath := ".editorconfig"
		relativeTarget := target
		if directory != "." {
			configPath = directory + "/.editorconfig"
			relativeTarget = strings.TrimPrefix(target, directory+"/")
		}
		raw, err := s.fs.ReadFile(configPath, maxEditorConfigBytes)
		if err == nil {
			totalBytes += len(raw)
			if totalBytes > maxEditorConfigTotal {
				return textfile.Indentation{}, errors.New("editorconfig total byte limit exceeded")
			}
			config, parseErr := textfile.ParseEditorConfig(raw, relativeTarget)
			if parseErr != nil {
				return textfile.Indentation{}, parseErr
			}
			configs = append(configs, config)
			if config.Root {
				break
			}
		} else if !errors.Is(err, workspace.ErrNotFound) {
			if errors.Is(err, workspace.ErrLimitExceeded) {
				return textfile.Indentation{}, errors.New("editorconfig byte limit exceeded")
			}
			return textfile.Indentation{}, errors.New("editorconfig read failed: " + err.Error())
		}
		if directory == "." {
			break
		}
		directory = path.Dir(directory)
	}
	for left, right := 0, len(configs)-1; left < right; left, right = left+1, right-1 {
		configs[left], configs[right] = configs[right], configs[left]
	}
	return textfile.ResolveIndentation(configs), nil
}

func convertEdits(edits []Edit, indentation textfile.Indentation) ([]textfile.Edit, error) {
	if len(edits) == 0 || len(edits) > textfile.DefaultMaxEdits {
		return nil, errors.New("edits must contain between 1 and 128 entries")
	}
	out := make([]textfile.Edit, len(edits))
	for i, edit := range edits {
		mode := textfile.ReplaceOnce
		switch edit.Mode {
		case "", "once":
		case "all":
			mode = textfile.ReplaceAll
		default:
			return nil, errors.New("edit mode must be once or all")
		}
		out[i] = textfile.Edit{Old: edit.Old, New: edit.New, Mode: mode, AdaptIndentation: edit.AdaptIndentation, Indentation: indentation}
	}
	return out, nil
}

func metadataResult(meta textfile.Metadata) *TextMetadata {
	return &TextMetadata{Encoding: string(meta.Encoding), BOM: string(meta.BOM), Newline: string(meta.NewlineStyle), DominantNewline: string(meta.DominantNewline), Confidence: meta.Confidence}
}

func textLimits(max int64) textfile.Limits {
	if max <= 0 {
		max = 1
	}
	maxInt := int64(^uint(0) >> 1)
	if max > maxInt {
		max = maxInt
	}
	max = min64(max, 64<<20)
	return textfile.Limits{MaxInputBytes: int(max), MaxDecodedBytes: int(min64(max*2, 64<<20)), MaxEncodedBytes: int(min64(max*2, 64<<20)), MaxEdits: textfile.DefaultMaxEdits, MaxMatches: textfile.DefaultMaxMatches}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func decodeJobData(job Job) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(job.Data)
	if err != nil || base64.StdEncoding.EncodeToString(data) != job.Data || digestBytes(data) != job.ContentSHA256 {
		return nil, errors.New("invalid data encoding or digest")
	}
	return data, nil
}

func (s *Service) Serve(r io.Reader, w io.Writer) error { return s.ServeWithSandbox(r, w, nil) }

func (s *Service) ServeWithSandbox(r io.Reader, w io.Writer, apply func(operation string) error) error {
	body, err := io.ReadAll(io.LimitReader(r, MaxJobBytes+1))
	if err != nil || len(body) > MaxJobBytes {
		return errors.New("worker job exceeds size limit")
	}
	var job Job
	if err := protocol.DecodeStrict(body, &job); err != nil {
		return errors.New("invalid worker job")
	}
	claims, err := s.authorize(job)
	if err != nil {
		return json.NewEncoder(w).Encode(Response{Error: s.safeError(err)})
	}
	if apply != nil {
		sandboxOperation := job.Operation
		if job.Apply && (job.Operation == "edit" || job.Operation == "multi_edit") {
			sandboxOperation = "write_file"
		}
		if err := apply(sandboxOperation); err != nil {
			return json.NewEncoder(w).Encode(s.finish(claims, Response{Error: "worker sandbox unavailable: " + err.Error()}))
		}
	}
	return json.NewEncoder(w).Encode(s.finish(claims, s.executeAuthorized(job)))
}

func claimsForJob(job Job, tokenID string, expiresAt time.Time) (capability.Claims, error) {
	scope, err := scopeForJob(job)
	if err != nil {
		return capability.Claims{}, err
	}
	return capability.Claims{
		TokenID: tokenID, WorkerType: scope.WorkerType, RequestID: scope.RequestID,
		BridgeID: scope.BridgeID, SessionID: scope.SessionID, ClientRequestID: scope.ClientRequestID,
		AuthPrincipal: scope.AuthPrincipal, Operation: scope.Operation, Path: scope.Path,
		Targets: append([]capability.Target(nil), scope.Targets...), PolicyID: scope.PolicyID,
		WorkerPolicyID: scope.WorkerPolicyID, PolicyDecision: scope.PolicyDecision,
		ApprovalRequired: scope.ApprovalRequired, ArgumentsSHA256: scope.ArgumentsSHA256,
		MaxBytes: scope.MaxBytes, StartLine: scope.StartLine, EndLine: scope.EndLine,
		MaxEntries: scope.MaxEntries, MaxFiles: scope.MaxFiles,
		MaxResults: scope.MaxResults, ExpectedHash: scope.ExpectedHash, ContentSHA256: scope.ContentSHA256,
		PatternSHA256: scope.PatternSHA256, QuerySHA256: scope.QuerySHA256,
		ExpiresAt: expiresAt.UTC(), SingleUse: true,
	}, nil
}

func scopeForJob(job Job) (capability.Scope, error) {
	if job.WorkerType == "" || job.RequestID == "" || job.SessionID == "" || job.Operation == "" || job.Path == "" || job.PolicyID == "" || job.WorkerPolicyID == "" || job.TokenID == "" {
		return capability.Scope{}, errors.New("incomplete worker job")
	}
	if job.WorkerType != FileWorkerType {
		return capability.Scope{}, errors.New("invalid worker type")
	}
	if err := validateNormalizedPaths(job); err != nil {
		return capability.Scope{}, err
	}
	if len(job.Pattern) > 1024 || len(job.Query) > 1024 {
		return capability.Scope{}, errors.New("worker search argument exceeds limit")
	}
	if job.ExpectedHash != "" && !validSHA256(job.ExpectedHash) {
		return capability.Scope{}, errors.New("invalid expected hash")
	}
	if job.ArgumentsSHA256 == "" || !validSHA256(job.ArgumentsSHA256) || job.ArgumentsSHA256 != jobArgumentsDigest(job) {
		return capability.Scope{}, errors.New("worker argument digest mismatch")
	}
	if err := validateOperationFields(job); err != nil {
		return capability.Scope{}, err
	}
	targets := make([]capability.Target, len(job.Targets))
	for i, target := range job.Targets {
		targets[i] = capability.Target{Path: target.Path, BeforeSHA256: target.BeforeSHA256, AfterSHA256: target.AfterSHA256}
	}
	return capability.Scope{
		WorkerType: job.WorkerType, RequestID: job.RequestID, BridgeID: job.BridgeID,
		SessionID: job.SessionID, ClientRequestID: job.ClientRequestID, AuthPrincipal: job.AuthPrincipal,
		Operation: job.Operation, Path: job.Path, Targets: targets, PolicyID: job.PolicyID,
		WorkerPolicyID: job.WorkerPolicyID, PolicyDecision: job.PolicyDecision,
		ApprovalRequired: job.ApprovalRequired, ArgumentsSHA256: job.ArgumentsSHA256,
		MaxBytes: job.MaxBytes, StartLine: job.StartLine, EndLine: job.EndLine,
		MaxEntries: job.MaxEntries, MaxFiles: job.MaxFiles,
		MaxResults: job.MaxResults, ExpectedHash: job.ExpectedHash, ContentSHA256: job.ContentSHA256,
		PatternSHA256: digestOptional(job.Pattern), QuerySHA256: digestOptional(job.Query),
	}, nil
}

func validateNormalizedPaths(job Job) error {
	check := func(path string) error {
		normalized, err := capability.NormalizePath(path)
		if err != nil || normalized != path {
			return errors.New("worker path is not normalized")
		}
		return nil
	}
	if err := check(job.Path); err != nil {
		return err
	}
	for _, path := range job.Paths {
		if err := check(path); err != nil {
			return err
		}
	}
	for _, file := range job.Files {
		if err := check(file.Path); err != nil {
			return err
		}
	}
	for _, target := range job.Targets {
		if err := check(target.Path); err != nil {
			return err
		}
		if target.BeforeSHA256 != "" && !validSHA256(target.BeforeSHA256) {
			return errors.New("invalid target before hash")
		}
		if target.AfterSHA256 != "" && !validSHA256(target.AfterSHA256) {
			return errors.New("invalid target after hash")
		}
	}
	return nil
}

func validateOperationFields(job Job) error {
	noSearch := job.Pattern == "" && job.Query == "" && job.MaxFiles == 0 && job.MaxResults == 0
	noWrite := job.Data == "" && job.ExpectedHash == "" && job.ContentSHA256 == "" && len(job.Edits) == 0 && len(job.Files) == 0 && !job.Apply && len(job.Targets) == 0
	noRange := job.StartLine == 0 && job.EndLine == 0
	switch job.Operation {
	case "read_file":
		if job.MaxBytes <= 0 || job.MaxEntries != 0 || len(job.Paths) != 0 || !noSearch || !noWrite || validateLineRange(job.StartLine, job.EndLine) != nil {
			return errors.New("invalid read job security parameters")
		}
	case "read_binary":
		if job.MaxBytes <= 0 || job.MaxBytes > MaxBinaryBytes || job.MaxEntries != 0 || len(job.Paths) != 0 || !noSearch || !noWrite || !noRange {
			return errors.New("invalid binary read job security parameters")
		}
	case "read_image":
		if job.MaxBytes <= 0 || job.MaxBytes > MaxImageBytes || job.MaxEntries != 0 || len(job.Paths) != 0 || !noSearch || !noWrite || !noRange {
			return errors.New("invalid image read job security parameters")
		}
	case "multi_read":
		if job.MaxBytes <= 0 || len(job.Paths) == 0 || len(job.Paths) > maxBatchFiles || job.MaxEntries != 0 || !noSearch || !noWrite || !noRange {
			return errors.New("invalid multi_read job security parameters")
		}
	case "list_dir":
		if job.MaxEntries <= 0 || job.MaxBytes != 0 || len(job.Paths) != 0 || !noSearch || !noWrite || !noRange {
			return errors.New("invalid list job security parameters")
		}
	case "checksum", "file_info":
		if job.MaxBytes != 0 || job.MaxEntries != 0 || len(job.Paths) != 0 || !noSearch || !noWrite || !noRange {
			return errors.New("invalid metadata job security parameters")
		}
	case "glob":
		if job.Pattern == "" || job.Query != "" || job.MaxFiles <= 0 || job.MaxResults <= 0 || job.MaxBytes != 0 || job.MaxEntries != 0 || !noWrite || !noRange {
			return errors.New("invalid glob job security parameters")
		}
	case "grep":
		if job.Query == "" || job.Pattern != "" || job.MaxFiles <= 0 || job.MaxResults <= 0 || job.MaxBytes <= 0 || job.MaxEntries != 0 || !noWrite || !noRange {
			return errors.New("invalid grep job security parameters")
		}
	case "diff":
		if job.MaxBytes <= 0 || job.ContentSHA256 == "" || job.Data == "" || len(job.Edits) != 0 || len(job.Files) != 0 || job.Apply || len(job.Targets) != 0 || !noSearch || !noRange {
			return errors.New("invalid diff job security parameters")
		}
		if _, err := decodeJobData(job); err != nil {
			return err
		}
	case "edit":
		if job.MaxBytes <= 0 || len(job.Edits) == 0 || len(job.Files) != 0 || job.Data != "" || job.ContentSHA256 != "" || !noSearch || !noRange || (job.Apply && len(job.Targets) != 1) || (!job.Apply && len(job.Targets) != 0) {
			return errors.New("invalid edit job security parameters")
		}
	case "multi_edit":
		if job.MaxBytes <= 0 || len(job.Files) == 0 || len(job.Files) > maxBatchFiles || len(job.Edits) != 0 || job.Data != "" || job.ContentSHA256 != "" || !noSearch || !noRange || (job.Apply && len(job.Targets) != len(job.Files)) || (!job.Apply && len(job.Targets) != 0) {
			return errors.New("invalid multi_edit job security parameters")
		}
	case "write_file":
		if job.MaxBytes <= 0 || job.MaxEntries != 0 || !noSearch || !noRange || job.ContentSHA256 == "" || len(job.Edits) != 0 || len(job.Files) != 0 || job.Apply || len(job.Targets) != 0 {
			return errors.New("invalid write job security parameters")
		}
		if _, err := decodeJobData(job); err != nil {
			return err
		}
	default:
		return errors.New("operation is not supported by file worker")
	}
	return nil
}

func jobArgumentsDigest(job Job) string {
	value := struct {
		Operation     string     `json:"operation"`
		Path          string     `json:"path"`
		Paths         []string   `json:"paths,omitempty"`
		MaxBytes      int64      `json:"max_bytes"`
		StartLine     int        `json:"start_line,omitempty"`
		EndLine       int        `json:"end_line,omitempty"`
		MaxEntries    int        `json:"max_entries"`
		MaxFiles      int        `json:"max_files"`
		MaxResults    int        `json:"max_results"`
		Pattern       string     `json:"pattern,omitempty"`
		Query         string     `json:"query,omitempty"`
		ExpectedHash  string     `json:"expected_hash,omitempty"`
		ContentSHA256 string     `json:"content_sha256,omitempty"`
		Edits         []Edit     `json:"edits,omitempty"`
		Files         []EditFile `json:"files,omitempty"`
		Apply         bool       `json:"apply,omitempty"`
		Targets       []Target   `json:"targets,omitempty"`
	}{job.Operation, job.Path, job.Paths, job.MaxBytes, job.StartLine, job.EndLine, job.MaxEntries, job.MaxFiles, job.MaxResults, job.Pattern, job.Query, job.ExpectedHash, job.ContentSHA256, job.Edits, job.Files, job.Apply, job.Targets}
	encoded, _ := json.Marshal(value)
	return digestBytes(encoded)
}

func targetsEqual(a, b []Target) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func workerPolicyID(deniedNames []string) string {
	unique := make(map[string]struct{}, len(deniedNames))
	for _, name := range deniedNames {
		unique[strings.ToLower(name)] = struct{}{}
	}
	canonical := make([]string, 0, len(unique))
	for name := range unique {
		canonical = append(canonical, name)
	}
	sort.Strings(canonical)
	encoded, _ := json.Marshal(struct {
		Version string   `json:"version"`
		Denied  []string `json:"denied"`
	}{Version: "workspace-denied-v1", Denied: canonical})
	return "file-policy-sha256:" + digestBytes(encoded)
}

func digestOptional(value string) string {
	if value == "" {
		return ""
	}
	return digestBytes([]byte(value))
}
func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

var _ = fmt.Sprintf
