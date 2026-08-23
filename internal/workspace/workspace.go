package workspace

import (
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
	return f.GlobWithDepth(rel, pattern, maxFiles, maxResults, DefaultMaxTraversalDepth)
}

// GlobWithDepth is Glob with an explicit maximum traversal depth.
func (f *FS) GlobWithDepth(rel, pattern string, maxFiles, maxResults, maxDepth int) ([]string, error) {
	pattern, err := validateGlobPattern(pattern)
	if err != nil {
		return nil, safeError("glob", err)
	}
	if maxResults < 0 {
		return nil, safeError("glob", ErrLimitExceeded)
	}
	if rel == "" {
		rel = "."
	}
	normalizedRel, err := NormalizePath(rel)
	if err != nil {
		return nil, safeError("glob", err)
	}
	var results []string
	err = f.walkFilesWithDepth(rel, maxFiles, maxDepth, func(filePath string) error {
		candidate := filePath
		if normalizedRel != "." {
			candidate = strings.TrimPrefix(filePath, strings.TrimSuffix(normalizedRel, "/")+"/")
		}
		matched, matchErr := path.Match(pattern, candidate)
		if matchErr != nil {
			return ErrInvalidPattern
		}
		if matched {
			results = append(results, filePath)
			if len(results) > maxResults {
				return ErrLimitExceeded
			}
		}
		return nil
	})
	sort.Strings(results)
	if err != nil {
		return results, safeError("glob", err)
	}
	return results, nil
}

func (f *FS) Grep(rel, query string, maxFiles, maxMatches int, maxBytes int64) ([]Match, error) {
	return f.GrepWithDepth(rel, query, maxFiles, maxMatches, maxBytes, DefaultMaxTraversalDepth)
}

// GrepWithDepth is Grep with an explicit maximum traversal depth.
func (f *FS) GrepWithDepth(rel, query string, maxFiles, maxMatches int, maxBytes int64, maxDepth int) ([]Match, error) {
	if query == "" {
		return nil, safeError("grep", ErrInvalidPattern)
	}
	if maxMatches < 0 || maxBytes < 0 {
		return nil, safeError("grep", ErrLimitExceeded)
	}
	var matches []Match
	var total int64
	err := f.walkFilesWithDepth(rel, maxFiles, maxDepth, func(filePath string) error {
		remaining := maxBytes - total
		if remaining <= 0 {
			return ErrLimitExceeded
		}
		data, readErr := f.ReadFile(filePath, remaining)
		if readErr != nil {
			if errors.Is(readErr, ErrLimitExceeded) || errors.Is(readErr, ErrInvalidFileType) || errors.Is(readErr, ErrUnsafeFile) {
				return nil
			}
			return readErr
		}
		total += int64(len(data))
		if strings.IndexByte(string(data), 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, query) {
				matches = append(matches, Match{Path: filePath, Line: i + 1, Text: line})
				if len(matches) > maxMatches {
					return ErrLimitExceeded
				}
			}
		}
		return nil
	})
	if err != nil {
		return matches, safeError("grep", err)
	}
	return matches, nil
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
