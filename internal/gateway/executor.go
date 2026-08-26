package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"

	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/remoteworker"
	"github.com/bkcarlos/remote_agent/internal/textfile"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

type ContextExecutor interface {
	Execute(context.Context, fileworker.Request) (fileworker.Response, error)
}

type NetworkExecutor interface {
	Execute(context.Context, networkworker.Request) (networkworker.Response, error)
}

type RemoteExecutor interface {
	Execute(context.Context, remoteworker.Request) (remoteworker.Response, error)
}

type ExecExecutor interface {
	Do(context.Context, execworker.Job) (execworker.Response, error)
}

type ExecutorCloser interface {
	Close() error
}

// WorkerExecutionScope is propagated through context to every configured
// executor adapter without changing an existing Worker wire protocol.
type WorkerExecutionScope struct {
	RequestID       string
	Principal       string
	WorkspaceID     string
	BridgeID        string
	SessionID       string
	ClientRequestID string
	PolicyID        string
	AuditID         string
	TokenID         string
	Worker          string
}

type workerExecutionScopeKey struct{}

func withWorkerExecutionScope(ctx context.Context, scope WorkerExecutionScope) context.Context {
	return context.WithValue(ctx, workerExecutionScopeKey{}, scope)
}

func WorkerExecutionScopeFromContext(ctx context.Context) (WorkerExecutionScope, bool) {
	if ctx == nil {
		return WorkerExecutionScope{}, false
	}
	scope, ok := ctx.Value(workerExecutionScopeKey{}).(WorkerExecutionScope)
	return scope, ok
}

// FileExecutor is retained as an adapter boundary for embedders and tests that
// use workspace.FS directly. Production uses ContextExecutor.
type FileExecutor interface {
	ReadFile(path string, max int64) ([]byte, error)
	List(path string, max int) ([]string, error)
	Checksum(path string) (string, error)
	Info(path string) (workspace.FileInfo, error)
	Glob(path, pattern string, maxFiles, maxResults int) ([]string, error)
	Grep(path, query string, maxFiles, maxResults int, maxBytes int64) ([]workspace.Match, error)
	WriteFile(path string, data []byte, expected string, max int64) (string, error)
}

type detailedScanExecutor interface {
	GlobScan(path, pattern string, maxFiles, maxResults int) (workspace.GlobScanResult, error)
	GrepScan(path, query string, maxFiles, maxResults int, maxBytes int64) (workspace.GrepScanResult, error)
}

type legacyExecutor struct{ fs FileExecutor }

func adaptExecutor(value any) (ContextExecutor, error) {
	if isNilInterface(value) {
		return nil, errors.New("file executor must not be nil")
	}
	if executor, ok := value.(ContextExecutor); ok {
		return executor, nil
	}
	if files, ok := value.(FileExecutor); ok {
		return legacyExecutor{fs: files}, nil
	}
	return nil, errors.New("file executor does not implement a supported interface")
}

func (e legacyExecutor) Execute(ctx context.Context, request fileworker.Request) (fileworker.Response, error) {
	if err := ctx.Err(); err != nil {
		return fileworker.Response{TokenID: request.TokenID, WorkerID: "in-process"}, err
	}
	response := fileworker.Response{TokenID: request.TokenID, WorkerID: "in-process"}
	var err error
	switch request.Operation {
	case "read_file":
		var raw []byte
		raw, err = e.fs.ReadFile(request.Path, request.MaxBytes)
		if err == nil {
			var decoded fileworker.FileResult
			decoded, err = fileworker.DecodeText(raw, request.MaxBytes, request.StartLine, request.EndLine)
			response.Content, response.Bytes, response.Checksum, response.Metadata = decoded.Content, decoded.Bytes, decoded.BeforeSHA256, decoded.Metadata
			response.StartLine, response.EndLine, response.TotalLines, response.Truncated = decoded.StartLine, decoded.EndLine, decoded.TotalLines, decoded.Truncated
		}
	case "read_binary":
		var raw []byte
		raw, err = e.fs.ReadFile(request.Path, request.MaxBytes)
		if err == nil {
			response.Base64, response.Bytes, response.Checksum = base64.StdEncoding.EncodeToString(raw), len(raw), digest(raw)
		}
	case "read_image":
		var raw []byte
		raw, err = e.fs.ReadFile(request.Path, request.MaxBytes)
		if err == nil {
			var decoded fileworker.ImageResult
			decoded, err = fileworker.DecodeImage(raw)
			response.Base64, response.MIMEType, response.Bytes, response.Checksum = decoded.Base64, decoded.MIMEType, decoded.Bytes, decoded.SHA256
			response.Width, response.Height = decoded.Width, decoded.Height
		}
	case "multi_read":
		remaining := request.MaxBytes
		for _, path := range request.Paths {
			var raw []byte
			raw, err = e.fs.ReadFile(path, remaining)
			if err != nil {
				break
			}
			var decoded fileworker.FileResult
			decoded, err = fileworker.DecodeText(raw, remaining, 0, 0)
			if err != nil {
				break
			}
			decoded.Path = path
			remaining -= int64(decoded.Bytes)
			if remaining < 0 {
				err = errors.New("multi_read total byte limit exceeded")
				break
			}
			response.Files = append(response.Files, decoded)
		}
	case "list_dir":
		response.Entries, err = e.fs.List(request.Path, request.MaxEntries)
	case "checksum":
		response.Checksum, err = e.fs.Checksum(request.Path)
	case "file_info":
		var info workspace.FileInfo
		info, err = e.fs.Info(request.Path)
		response.Info = &info
	case "glob":
		if scanner, ok := e.fs.(detailedScanExecutor); ok {
			var result workspace.GlobScanResult
			result, err = scanner.GlobScan(request.Path, request.Pattern, request.MaxFiles, request.MaxResults)
			response.Paths, response.Scan = result.Paths, &result.Scan
		} else {
			response.Paths, err = e.fs.Glob(request.Path, request.Pattern, request.MaxFiles, request.MaxResults)
			if err == nil {
				response.Scan = &workspace.ScanStats{Complete: true, FilesScanned: len(response.Paths)}
			}
		}
	case "grep":
		if scanner, ok := e.fs.(detailedScanExecutor); ok {
			var result workspace.GrepScanResult
			result, err = scanner.GrepScan(request.Path, request.Query, request.MaxFiles, request.MaxResults, request.MaxBytes)
			response.Matches, response.Scan = result.Matches, &result.Scan
		} else {
			response.Matches, err = e.fs.Grep(request.Path, request.Query, request.MaxFiles, request.MaxResults, request.MaxBytes)
			if err == nil {
				response.Scan = &workspace.ScanStats{Complete: true}
			}
		}
	case "write_file":
		response.Checksum, err = e.fs.WriteFile(request.Path, request.Data, request.ExpectedHash, request.MaxBytes)
	case "diff":
		var raw []byte
		raw, err = e.fs.ReadFile(request.Path, request.MaxBytes)
		if err == nil {
			var original string
			original, _, _, _, err = decodeLegacy(raw, request.MaxBytes)
			if err == nil {
				response.Diff, err = textfile.UnifiedDiff(original, string(request.Data), textfile.DiffOptions{OldName: "a/" + request.Path, NewName: "b/" + request.Path, Context: textfile.DefaultDiffContext})
			}
		}
	case "edit", "multi_edit":
		response, err = e.edit(ctx, request, response)
	default:
		err = errors.New("unsupported file operation")
	}
	if err != nil {
		response.Error = err.Error()
		response.ErrorKind = fileworker.ErrorKindFor(err)
	}
	return response, err
}

func decodeLegacy(raw []byte, max int64) (string, int, string, *fileworker.TextMetadata, error) {
	decoded, err := fileworker.DecodeText(raw, max, 0, 0)
	return decoded.Content, decoded.Bytes, decoded.BeforeSHA256, decoded.Metadata, err
}

type legacyPlan struct {
	result            fileworker.FileResult
	original, updated []byte
}

func (e legacyExecutor) edit(ctx context.Context, request fileworker.Request, identity fileworker.Response) (fileworker.Response, error) {
	files := request.Files
	if request.Operation == "edit" {
		files = []fileworker.EditFile{{Path: request.Path, Edits: request.Edits}}
	}
	if len(files) == 0 || len(files) > 20 {
		return identity, errors.New("edit file count must be between 1 and 20")
	}
	plans := make([]legacyPlan, 0, len(files))
	seen := map[string]bool{}
	var inputTotal, outputTotal int64
	for _, item := range files {
		if seen[item.Path] {
			return identity, errors.New("edit paths must be unique")
		}
		seen[item.Path] = true
		raw, err := e.fs.ReadFile(item.Path, request.MaxBytes-inputTotal)
		if err != nil {
			return identity, err
		}
		inputTotal += int64(len(raw))
		limit := int(request.MaxBytes)
		if limit <= 0 || int64(limit) != request.MaxBytes || limit > 64<<20 {
			limit = 64 << 20
		}
		file, err := textfile.Decode(raw, textfile.Limits{MaxInputBytes: limit, MaxDecodedBytes: minInt(limit*2, 64<<20), MaxEncodedBytes: minInt(limit*2, 64<<20), MaxEdits: 128, MaxMatches: 10000})
		if err != nil {
			return identity, err
		}
		edits := make([]textfile.Edit, len(item.Edits))
		for i, edit := range item.Edits {
			mode := textfile.ReplaceOnce
			if edit.Mode == "all" {
				mode = textfile.ReplaceAll
			} else if edit.Mode != "" && edit.Mode != "once" {
				return identity, errors.New("edit mode must be once or all")
			}
			edits[i] = textfile.Edit{Old: edit.Old, New: edit.New, Mode: mode}
		}
		preview, err := file.Preview(edits, textfile.DiffOptions{OldName: "a/" + item.Path, NewName: "b/" + item.Path, Context: textfile.DefaultDiffContext})
		if err != nil {
			return identity, err
		}
		results, err := file.Apply(edits)
		if err != nil {
			return identity, err
		}
		updated, err := file.Encode()
		if err != nil {
			return identity, err
		}
		outputTotal += int64(len(updated))
		if outputTotal > request.MaxBytes {
			return identity, errors.New("edit total output byte limit exceeded")
		}
		replacements := 0
		for _, result := range results {
			replacements += result.Replacements
		}
		meta := file.Metadata()
		metadata := &fileworker.TextMetadata{Encoding: string(meta.Encoding), BOM: string(meta.BOM), Newline: string(meta.NewlineStyle), DominantNewline: string(meta.DominantNewline), Confidence: meta.Confidence}
		plans = append(plans, legacyPlan{result: fileworker.FileResult{Path: item.Path, Bytes: len(updated), BeforeSHA256: digest(raw), AfterSHA256: digest(updated), Diff: preview.Diff, Metadata: metadata, Replacements: replacements}, original: raw, updated: updated})
	}
	identity.Files = make([]fileworker.FileResult, len(plans))
	actual := make([]fileworker.Target, len(plans))
	for i := range plans {
		identity.Files[i] = plans[i].result
		actual[i] = fileworker.Target{Path: plans[i].result.Path, BeforeSHA256: plans[i].result.BeforeSHA256, AfterSHA256: plans[i].result.AfterSHA256}
	}
	if !request.Apply {
		return identity, nil
	}
	if !workerTargetsEqual(actual, request.Targets) {
		return identity, errors.New("edit target changed after approval preflight")
	}
	// Cancellation is honored before Execute and throughout preflight. After
	// apply starts, finish the bounded batch (or its rollback) so cancellation
	// cannot strand a partial local commit. This is not power-loss atomic.
	written := 0
	for i := range plans {
		if _, err := e.fs.WriteFile(plans[i].result.Path, plans[i].updated, plans[i].result.BeforeSHA256, request.MaxBytes); err != nil {
			rollback := true
			for previous := written - 1; previous >= 0; previous-- {
				if _, rollbackErr := e.fs.WriteFile(plans[previous].result.Path, plans[previous].original, plans[previous].result.AfterSHA256, request.MaxBytes); rollbackErr != nil {
					rollback = false
				}
			}
			if !rollback {
				return identity, errors.New("batch edit failed and rollback was incomplete")
			}
			identity.RolledBack = written > 0
			return identity, errors.New("batch edit failed; completed writes were rolled back")
		}
		written++
	}
	return identity, nil
}

func workerTargetsEqual(a, b []fileworker.Target) bool {
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
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func configuredWorkerID(worker string, configured bool) string {
	if !configured {
		return ""
	}
	return newID(worker + "-worker-")
}

func workerConfigured(config Config, worker string) bool {
	switch worker {
	case "file":
		return true
	case "network":
		return !isNilInterface(config.NetworkExecutor) && len(config.NetworkProfiles) > 0
	case "remote":
		return !isNilInterface(config.RemoteExecutor)
	case "exec":
		return !isNilInterface(config.ExecExecutor) && config.ExecSigner != nil && len(config.ExecProfiles) > 0
	default:
		return false
	}
}

func cloneNetworkProfiles(profiles map[string]networkworker.Profile) map[string]networkworker.Profile {
	if profiles == nil {
		return nil
	}
	cloned := make(map[string]networkworker.Profile, len(profiles))
	for id, profile := range profiles {
		profile.Policy.AllowedDomains = append([]string(nil), profile.Policy.AllowedDomains...)
		profile.Policy.AllowedPorts = append([]uint16(nil), profile.Policy.AllowedPorts...)
		profile.Policy.AllowedSchemes = append([]string(nil), profile.Policy.AllowedSchemes...)
		profile.Policy.AllowedCIDRs = append([]string(nil), profile.Policy.AllowedCIDRs...)
		profile.Policy.AllowedRequestHeaders = append([]string(nil), profile.Policy.AllowedRequestHeaders...)
		cloned[id] = profile
	}
	return cloned
}

func cloneExecProfiles(profiles map[string]execworker.TaskProfile) map[string]execworker.TaskProfile {
	if profiles == nil {
		return nil
	}
	cloned := make(map[string]execworker.TaskProfile, len(profiles))
	for id, profile := range profiles {
		profile.FixedArgv = append([]string(nil), profile.FixedArgv...)
		profile.EnvAllowlist = append([]string(nil), profile.EnvAllowlist...)
		prefixes := profile.AllowedArgvPrefixes
		profile.AllowedArgvPrefixes = make([][]string, len(prefixes))
		for index := range prefixes {
			profile.AllowedArgvPrefixes[index] = append([]string(nil), prefixes[index]...)
		}
		cloned[id] = profile
	}
	return cloned
}
