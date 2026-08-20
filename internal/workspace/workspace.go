package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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
	a, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	s, e := filepath.EvalSymlinks(a)
	if e != nil {
		return nil, e
	}
	st, e := os.Stat(s)
	if e != nil || !st.IsDir() {
		return nil, errors.New("workspace root must be a directory")
	}
	denied := map[string]bool{}
	for _, name := range append([]string{".env", ".ssh", ".aws", ".gnupg", "id_rsa", "id_ed25519"}, deniedNames...) {
		denied[strings.ToLower(name)] = true
	}
	return &FS{root: s, denied: denied}, nil
}
func (f *FS) resolve(rel string, allowMissing bool) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.IndexByte(rel, 0) >= 0 {
		return "", errors.New("path must be a non-empty relative path")
	}
	c := filepath.Clean(rel)
	if c == ".." || strings.HasPrefix(c, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes workspace")
	}
	cur := f.root
	parts := strings.Split(filepath.ToSlash(c), "/")
	for i, p := range parts {
		if p == "" || p == "." {
			continue
		}
		cur = filepath.Join(cur, p)
		st, e := os.Lstat(cur)
		if e != nil {
			if allowMissing && os.IsNotExist(e) && i == len(parts)-1 {
				return cur, nil
			}
			return "", e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("symbolic links are not allowed")
		}
	}
	r, err := filepath.Rel(f.root, cur)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes workspace")
	}
	return cur, nil
}
func (f *FS) ReadFile(rel string, max int64) ([]byte, error) {
	if _, e := f.resolve(rel, false); e != nil {
		return nil, e
	}
	h, e := secureOpen(f.root, rel, false)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	st, e := h.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if hasMultipleLinks(st) {
		return nil, errors.New("hard-linked files are not allowed")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("file exceeds %d byte limit", max)
	}
	return io.ReadAll(io.LimitReader(h, max+1))
}
func (f *FS) List(rel string, max int) ([]string, error) {
	if rel == "" {
		rel = "."
	}
	if _, e := f.resolve(rel, false); e != nil {
		return nil, e
	}
	dir, e := secureOpen(f.root, rel, true)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	ds, e := dir.ReadDir(-1)
	if e != nil {
		return nil, e
	}
	if len(ds) > max {
		return nil, errors.New("directory entry limit exceeded")
	}
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		if d.Type()&os.ModeSymlink == 0 {
			out = append(out, d.Name())
		}
	}
	return out, nil
}
func (f *FS) Info(rel string) (FileInfo, error) {
	if _, err := f.resolve(rel, false); err != nil {
		return FileInfo{}, err
	}
	h, err := secureOpen(f.root, rel, false)
	if err != nil {
		return FileInfo{}, err
	}
	defer h.Close()
	st, err := h.Stat()
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Size: st.Size(), Mode: uint32(st.Mode().Perm()), ModifiedAt: st.ModTime().UTC(), IsDir: st.IsDir()}, nil
}

func (f *FS) walkFiles(rel string, maxFiles int, visit func(string) error) error {
	if rel == "" {
		rel = "."
	}
	if _, err := f.resolve(rel, false); err != nil {
		return err
	}
	return secureWalkFiles(f.root, rel, f.denied, maxFiles, visit)
}

func (f *FS) Glob(rel, pattern string, maxFiles, maxResults int) ([]string, error) {
	if pattern == "" || filepath.IsAbs(pattern) || strings.Contains(pattern, "..") {
		return nil, errors.New("glob pattern must be relative and must not contain '..'")
	}
	var results []string
	err := f.walkFiles(rel, maxFiles, func(path string) error {
		candidate := path
		if rel != "" && rel != "." {
			candidate = strings.TrimPrefix(path, strings.TrimSuffix(filepath.ToSlash(filepath.Clean(rel)), "/")+"/")
		}
		matched, err := filepath.Match(filepath.FromSlash(pattern), filepath.FromSlash(candidate))
		if err != nil {
			return errors.New("invalid glob pattern")
		}
		if matched {
			results = append(results, path)
			if len(results) > maxResults {
				return errors.New("glob result limit exceeded")
			}
		}
		return nil
	})
	sort.Strings(results)
	return results, err
}

func (f *FS) Grep(rel, query string, maxFiles, maxMatches int, maxBytes int64) ([]Match, error) {
	if query == "" {
		return nil, errors.New("grep query must not be empty")
	}
	var matches []Match
	var total int64
	err := f.walkFiles(rel, maxFiles, func(path string) error {
		remaining := maxBytes - total
		if remaining <= 0 {
			return errors.New("grep byte limit exceeded")
		}
		b, err := f.ReadFile(path, remaining)
		if err != nil {
			if strings.Contains(err.Error(), "exceeds") || strings.Contains(err.Error(), "not a regular") || strings.Contains(err.Error(), "hard-linked") {
				return nil
			}
			return err
		}
		total += int64(len(b))
		if strings.IndexByte(string(b), 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, query) {
				matches = append(matches, Match{Path: path, Line: i + 1, Text: line})
				if len(matches) > maxMatches {
					return errors.New("grep match limit exceeded")
				}
			}
		}
		return nil
	})
	return matches, err
}

func (f *FS) Checksum(rel string) (string, error) {
	b, e := f.ReadFile(rel, 64<<20)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func (f *FS) WriteFile(rel string, data []byte, expected string, max int64) (string, error) {
	if int64(len(data)) > max {
		return "", errors.New("write size limit exceeded")
	}
	if _, e := f.resolve(rel, true); e != nil {
		return "", e
	}
	mode := os.FileMode(0600)
	if existing, openErr := secureOpen(f.root, rel, false); openErr == nil {
		st, statErr := existing.Stat()
		existing.Close()
		if statErr != nil {
			return "", statErr
		}
		if !st.Mode().IsRegular() {
			return "", errors.New("write target is not a regular file")
		}
		mode = st.Mode().Perm()
	}
	if expected != "" {
		got, e := f.Checksum(rel)
		if e != nil {
			return "", e
		}
		if got != expected {
			return "", errors.New("expected hash mismatch")
		}
	}
	if err := secureAtomicWrite(f.root, rel, data, mode, expected); err != nil {
		return "", err
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:]), nil
}
