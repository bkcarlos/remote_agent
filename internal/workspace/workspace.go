package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FS struct {
	root   string
	denied map[string]bool
}

type FileInfo struct {
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"`
	ModifiedAt time.Time `json:"modified_at"`
	IsDir      bool      `json:"is_dir"`
}

type Match struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

const (
	ScanLimitFiles   = "file_limit"
	ScanLimitDepth   = "depth_limit"
	ScanLimitBytes   = "byte_limit"
	ScanLimitResults = "result_limit"
)

// ScanStats tells callers whether an empty or partial result represents a
// complete search. LimitReason is set only when Complete is false.
type ScanStats struct {
	Complete     bool   `json:"complete"`
	LimitReason  string `json:"limit_reason,omitempty"`
	FilesScanned int    `json:"files_scanned"`
	FilesSkipped int    `json:"files_skipped"`
	BytesScanned int64  `json:"bytes_scanned"`
}

type GlobScanResult struct {
	Paths []string  `json:"paths"`
	Scan  ScanStats `json:"scan"`
}

type GrepScanResult struct {
	Matches []Match   `json:"matches"`
	Scan    ScanStats `json:"scan"`
}

var (
	errScanByteLimit   = errors.New("scan byte limit reached")
	errScanResultLimit = errors.New("scan result limit reached")
)

func New(root string) (*FS, error) {
	return NewWithDenied(root, nil)
}

func NewWithDenied(root string, deniedNames []string) (*FS, error) {
	a, err := filepath.Abs(root)
	if err != nil {
		return nil, safeError("initialize", err)
	}
	s, err := filepath.EvalSymlinks(a)
	if err != nil {
		return nil, safeError("initialize", err)
	}
	st, err := os.Stat(s)
	if err != nil {
		return nil, safeError("initialize", err)
	}
	if !st.IsDir() {
		return nil, safeError("initialize", ErrNotDirectory)
	}
	denied := map[string]bool{}
	allDenied := append([]string{".env", ".ssh", ".aws", ".gnupg", "id_rsa", "id_ed25519"}, deniedNames...)
	for _, name := range allDenied {
		if name != "" {
			denied[strings.ToLower(name)] = true
		}
	}
	return &FS{root: s, denied: denied}, nil
}

// NormalizePath converts a caller-supplied workspace path to a slash-separated,
// relative clean path. It is exported so policy layers can evaluate exactly the
// same path representation used by this package.
func NormalizePath(rel string) (string, error) {
	if rel == "" || strings.IndexByte(rel, 0) >= 0 {
		return "", ErrInvalidPath
	}
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return "", ErrInvalidPath
	}
	rel = strings.ReplaceAll(rel, `\`, "/")
	if path.IsAbs(rel) || (len(rel) >= 2 && rel[1] == ':') {
		return "", ErrInvalidPath
	}
	normalized := path.Clean(rel)
	if normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", ErrInvalidPath
	}
	return normalized, nil
}

func deniedPath(rel string, denied map[string]bool) bool {
	for _, part := range strings.Split(strings.ReplaceAll(rel, `\`, "/"), "/") {
		if denied[strings.ToLower(part)] {
			return true
		}
	}
	return false
}

// resolve validates and checks a path, then returns its normalized relative
// representation rather than a host absolute path.
func (f *FS) resolve(rel string, allowMissing bool) (string, error) {
	if deniedPath(rel, f.denied) {
		return "", ErrDeniedPath
	}
	normalized, err := NormalizePath(rel)
	if err != nil {
		return "", err
	}
	if deniedPath(normalized, f.denied) {
		return "", ErrDeniedPath
	}

	cur := f.root
	parts := strings.Split(normalized, "/")
	for i, part := range parts {
		if part == "." {
			continue
		}
		cur = filepath.Join(cur, filepath.FromSlash(part))
		st, statErr := os.Lstat(cur)
		if statErr != nil {
			if allowMissing && os.IsNotExist(statErr) && i == len(parts)-1 {
				return normalized, nil
			}
			return "", statErr
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", ErrUnsafeFile
		}
	}
	relCheck, relErr := filepath.Rel(f.root, cur)
	if relErr != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", ErrInvalidPath
	}
	return normalized, nil
}
func (f *FS) ReadFile(rel string, max int64) ([]byte, error) {
	if max < 0 {
		return nil, safeError("read file", ErrLimitExceeded)
	}
	normalized, err := f.resolve(rel, false)
	if err != nil {
		return nil, safeError("read file", err)
	}
	h, err := secureOpen(f.root, normalized, false)
	if err != nil {
		return nil, safeError("read file", err)
	}
	defer h.Close()
	st, err := h.Stat()
	if err != nil {
		return nil, safeError("read file", err)
	}
	if !st.Mode().IsRegular() {
		return nil, safeError("read file", ErrInvalidFileType)
	}
	if hasMultipleLinks(st) {
		return nil, safeError("read file", ErrUnsafeFile)
	}
	if st.Size() > max {
		return nil, safeError("read file", ErrLimitExceeded)
	}
	limit := max + 1
	if max == math.MaxInt64 {
		limit = max
	}
	data, err := io.ReadAll(io.LimitReader(h, limit))
	if err != nil {
		return nil, safeError("read file", err)
	}
	if int64(len(data)) > max {
		return nil, safeError("read file", ErrLimitExceeded)
	}
	return data, nil
}

// readWalkedFile opens a path already produced by the secure walker. openat2
// (or the checked non-Linux equivalent) repeats the kernel-enforced boundary,
// while avoiding resolve's per-component lstat loop for every scanned file.
func (f *FS) readWalkedFile(rel string, max int64) ([]byte, int64, error) {
	if max < 0 {
		return nil, 0, ErrLimitExceeded
	}
	h, err := secureOpen(f.root, rel, false)
	if err != nil {
		return nil, 0, err
	}
	defer h.Close()
	st, err := h.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		return nil, st.Size(), ErrInvalidFileType
	}
	if hasMultipleLinks(st) {
		return nil, st.Size(), ErrUnsafeFile
	}
	if st.Size() > max {
		return nil, st.Size(), ErrLimitExceeded
	}
	limit := max + 1
	if max == math.MaxInt64 {
		limit = max
	}
	data, err := io.ReadAll(io.LimitReader(h, limit))
	if err != nil {
		return nil, st.Size(), err
	}
	if int64(len(data)) > max {
		return nil, int64(len(data)), ErrLimitExceeded
	}
	return data, st.Size(), nil
}

func (f *FS) List(rel string, max int) ([]string, error) {
	if rel == "" {
		rel = "."
	}
	if max < 0 {
		return nil, safeError("list directory", ErrLimitExceeded)
	}
	normalized, err := f.resolve(rel, false)
	if err != nil {
		return nil, safeError("list directory", err)
	}
	dir, err := secureOpen(f.root, normalized, true)
	if err != nil {
		return nil, safeError("list directory", err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, safeError("list directory", err)
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		// Policy names are checked before type inspection and before limits so
		// sensitive names cannot be inferred from output or entry counts.
		if f.denied[strings.ToLower(entry.Name())] {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		out = append(out, entry.Name())
		if len(out) > max {
			return nil, safeError("list directory", ErrLimitExceeded)
		}
	}
	sort.Strings(out)
	return out, nil
}
func (f *FS) Info(rel string) (FileInfo, error) {
	normalized, err := f.resolve(rel, false)
	if err != nil {
		return FileInfo{}, safeError("inspect entry", err)
	}
	h, err := secureOpen(f.root, normalized, false)
	if err != nil {
		return FileInfo{}, safeError("inspect entry", err)
	}
	defer h.Close()
	st, err := h.Stat()
	if err != nil {
		return FileInfo{}, safeError("inspect entry", err)
	}
	return FileInfo{Size: st.Size(), Mode: uint32(st.Mode().Perm()), ModifiedAt: st.ModTime().UTC(), IsDir: st.IsDir()}, nil
}

func (f *FS) walkFiles(rel string, maxFiles int, visit func(string) error) error {
	return f.walkFilesWithDepth(rel, maxFiles, DefaultMaxTraversalDepth, visit)
}

func (f *FS) walkFilesWithDepth(rel string, maxFiles, maxDepth int, visit func(string) error) error {
	if rel == "" {
		rel = "."
	}
	if maxFiles < 0 || maxDepth < 0 {
		return ErrLimitExceeded
	}
	normalized, err := f.resolve(rel, false)
	if err != nil {
		return err
	}
	return secureWalkFilesWithDepth(f.root, normalized, f.denied, maxFiles, maxDepth, visit)
}

func validateGlobPattern(pattern string) (string, error) {
	if pattern == "" || strings.IndexByte(pattern, 0) >= 0 || filepath.IsAbs(pattern) || filepath.VolumeName(pattern) != "" {
		return "", ErrInvalidPattern
	}
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	if path.IsAbs(pattern) {
		return "", ErrInvalidPattern
	}
	for _, part := range strings.Split(pattern, "/") {
		if part == ".." {
			return "", ErrInvalidPattern
		}
	}
	if _, err := path.Match(pattern, "candidate"); err != nil {
		return "", ErrInvalidPattern
	}
	return pattern, nil
}

func (f *FS) Glob(rel, pattern string, maxFiles, maxResults int) ([]string, error) {
	result, err := f.GlobScanWithDepth(rel, pattern, maxFiles, maxResults, DefaultMaxTraversalDepth)
	if err != nil {
		return result.Paths, err
	}
	if !result.Scan.Complete {
		return result.Paths, safeError("glob", ErrLimitExceeded)
	}
	return result.Paths, nil
}

// GlobWithDepth is Glob with an explicit maximum traversal depth.
func (f *FS) GlobWithDepth(rel, pattern string, maxFiles, maxResults, maxDepth int) ([]string, error) {
	result, err := f.GlobScanWithDepth(rel, pattern, maxFiles, maxResults, maxDepth)
	if err != nil {
		return result.Paths, err
	}
	if !result.Scan.Complete {
		return result.Paths, safeError("glob", ErrLimitExceeded)
	}
	return result.Paths, nil
}

func (f *FS) GlobScan(rel, pattern string, maxFiles, maxResults int) (GlobScanResult, error) {
	return f.GlobScanWithDepth(rel, pattern, maxFiles, maxResults, DefaultMaxTraversalDepth)
}

func (f *FS) GlobScanWithDepth(rel, pattern string, maxFiles, maxResults, maxDepth int) (GlobScanResult, error) {
	result := GlobScanResult{Scan: ScanStats{Complete: true}}
	pattern, err := validateGlobPattern(pattern)
	if err != nil {
		return result, safeError("glob", err)
	}
	if maxResults < 0 {
		return result, safeError("glob", ErrLimitExceeded)
	}
	if rel == "" {
		rel = "."
	}
	normalizedRel, err := NormalizePath(rel)
	if err != nil {
		return result, safeError("glob", err)
	}
	err = f.walkFilesWithDepth(rel, maxFiles, maxDepth, func(filePath string) error {
		result.Scan.FilesScanned++
		candidate := filePath
		if normalizedRel != "." {
			candidate = strings.TrimPrefix(filePath, strings.TrimSuffix(normalizedRel, "/")+"/")
		}
		matched, matchErr := path.Match(pattern, candidate)
		if matchErr != nil {
			return ErrInvalidPattern
		}
		if !matched {
			return nil
		}
		if len(result.Paths) == maxResults {
			return errScanResultLimit
		}
		result.Paths = append(result.Paths, filePath)
		return nil
	})
	sort.Strings(result.Paths)
	switch {
	case err == nil:
		return result, nil
	case errors.Is(err, errScanResultLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitResults
		return result, nil
	case errors.Is(err, errTraversalFileLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitFiles
		return result, nil
	case errors.Is(err, errTraversalDepthLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitDepth
		return result, nil
	default:
		return result, safeError("glob", err)
	}
}

func (f *FS) Grep(rel, query string, maxFiles, maxMatches int, maxBytes int64) ([]Match, error) {
	result, err := f.GrepScanWithDepth(rel, query, maxFiles, maxMatches, maxBytes, DefaultMaxTraversalDepth)
	if err != nil {
		return result.Matches, err
	}
	if !result.Scan.Complete {
		return result.Matches, safeError("grep", ErrLimitExceeded)
	}
	return result.Matches, nil
}

// GrepWithDepth is Grep with an explicit maximum traversal depth.
func (f *FS) GrepWithDepth(rel, query string, maxFiles, maxMatches int, maxBytes int64, maxDepth int) ([]Match, error) {
	result, err := f.GrepScanWithDepth(rel, query, maxFiles, maxMatches, maxBytes, maxDepth)
	if err != nil {
		return result.Matches, err
	}
	if !result.Scan.Complete {
		return result.Matches, safeError("grep", ErrLimitExceeded)
	}
	return result.Matches, nil
}

func (f *FS) GrepScan(rel, query string, maxFiles, maxMatches int, maxBytes int64) (GrepScanResult, error) {
	return f.GrepScanWithDepth(rel, query, maxFiles, maxMatches, maxBytes, DefaultMaxTraversalDepth)
}

func (f *FS) GrepScanWithDepth(rel, query string, maxFiles, maxMatches int, maxBytes int64, maxDepth int) (GrepScanResult, error) {
	result := GrepScanResult{Scan: ScanStats{Complete: true}}
	if query == "" {
		return result, safeError("grep", ErrInvalidPattern)
	}
	if maxMatches < 0 || maxBytes < 0 {
		return result, safeError("grep", ErrLimitExceeded)
	}
	queryBytes := []byte(query)
	err := f.walkFilesWithDepth(rel, maxFiles, maxDepth, func(filePath string) error {
		remaining := maxBytes - result.Scan.BytesScanned
		if remaining <= 0 {
			return errScanByteLimit
		}
		data, _, readErr := f.readWalkedFile(filePath, remaining)
		if readErr != nil {
			switch {
			case errors.Is(readErr, ErrLimitExceeded):
				result.Scan.FilesSkipped++
				return errScanByteLimit
			case errors.Is(readErr, ErrInvalidFileType), errors.Is(readErr, ErrUnsafeFile):
				result.Scan.FilesSkipped++
				return nil
			default:
				return readErr
			}
		}
		result.Scan.FilesScanned++
		result.Scan.BytesScanned += int64(len(data))
		if bytes.IndexByte(data, 0) >= 0 {
			result.Scan.FilesSkipped++
			return nil
		}
		for i, line := range bytes.Split(data, []byte{'\n'}) {
			if !bytes.Contains(line, queryBytes) {
				continue
			}
			if len(result.Matches) == maxMatches {
				return errScanResultLimit
			}
			result.Matches = append(result.Matches, Match{Path: filePath, Line: i + 1, Text: string(line)})
		}
		return nil
	})
	switch {
	case err == nil:
		return result, nil
	case errors.Is(err, errScanResultLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitResults
		return result, nil
	case errors.Is(err, errScanByteLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitBytes
		return result, nil
	case errors.Is(err, errTraversalFileLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitFiles
		return result, nil
	case errors.Is(err, errTraversalDepthLimit):
		result.Scan.Complete, result.Scan.LimitReason = false, ScanLimitDepth
		return result, nil
	default:
		return result, safeError("grep", err)
	}
}

func (f *FS) Checksum(rel string) (string, error) {
	data, err := f.ReadFile(rel, 64<<20)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (f *FS) WriteFile(rel string, data []byte, expected string, max int64) (string, error) {
	if max < 0 || int64(len(data)) > max {
		return "", safeError("write file", ErrLimitExceeded)
	}
	normalized, err := f.resolve(rel, true)
	if err != nil {
		return "", safeError("write file", err)
	}
	mode := os.FileMode(0600)
	if existing, openErr := secureOpen(f.root, normalized, false); openErr == nil {
		st, statErr := existing.Stat()
		existing.Close()
		if statErr != nil {
			return "", safeError("write file", statErr)
		}
		if !st.Mode().IsRegular() {
			return "", safeError("write file", ErrInvalidFileType)
		}
		if hasMultipleLinks(st) {
			return "", safeError("write file", ErrUnsafeFile)
		}
		if expected == "" {
			return "", safeError("write file", ErrConflict)
		}
		mode = st.Mode().Perm()
	} else if !os.IsNotExist(openErr) {
		return "", safeError("write file", openErr)
	}
	if expected != "" {
		got, checksumErr := f.Checksum(normalized)
		if checksumErr != nil {
			return "", checksumErr
		}
		if got != expected {
			return "", safeError("write file", ErrConflict)
		}
	}
	if err := secureAtomicWrite(f.root, normalized, data, mode, expected); err != nil {
		return "", safeError("write file", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
