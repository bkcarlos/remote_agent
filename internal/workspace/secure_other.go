//go:build !linux

package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func secureOpen(root, rel string, directory bool) (*os.File, error) {
	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	if directory {
		st, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return nil, statErr
		}
		if !st.IsDir() {
			f.Close()
			return nil, ErrNotDirectory
		}
	}
	return f, nil
}

func secureWalkFiles(root, rel string, denied map[string]bool, maxFiles int, visit func(string) error) error {
	return secureWalkFilesWithDepth(root, rel, denied, maxFiles, DefaultMaxTraversalDepth, visit)
}

func secureWalkFilesWithDepth(root, rel string, denied map[string]bool, maxFiles, maxDepth int, visit func(string) error) error {
	if maxFiles < 0 || maxDepth < 0 {
		return ErrLimitExceeded
	}
	for _, part := range strings.Split(strings.ReplaceAll(rel, `\`, "/"), "/") {
		if denied[strings.ToLower(part)] {
			return ErrDeniedPath
		}
	}
	normalized, err := NormalizePath(rel)
	if err != nil {
		return err
	}
	rel = normalized

	start, err := openCheckedDirectory(root, "")
	if err != nil {
		return err
	}
	current := ""
	var rules []ignoreRule
	if rel != "." {
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if part == "" || part == "." {
				continue
			}
			if denied[strings.ToLower(part)] {
				start.Close()
				return ErrDeniedPath
			}
			rules, err = nonLinuxReadGitignore(root, current, denied, rules)
			if err != nil {
				start.Close()
				return err
			}
			childPath := part
			if current != "" {
				childPath = current + "/" + part
			}
			if ignoredByRules(rules, childPath, true) {
				start.Close()
				return nil
			}
			child, openErr := openCheckedDirectory(root, childPath)
			if openErr != nil {
				start.Close()
				return openErr
			}
			start.Close()
			start = child
			current = childPath
		}
	}
	defer start.Close()

	count := 0
	var walk func(*os.File, string, int, []ignoreRule) error
	walk = func(dir *os.File, current string, depth int, inherited []ignoreRule) error {
		active, readErr := nonLinuxReadGitignore(root, current, denied, inherited)
		if readErr != nil {
			return readErr
		}
		entries, readErr := dir.ReadDir(-1)
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			name := entry.Name()
			if denied[strings.ToLower(name)] {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			entryPath := name
			if current != "" {
				entryPath = current + "/" + name
			}
			isDir := info.IsDir()
			if ignoredByRules(active, entryPath, isDir) {
				continue
			}
			if !isDir && !info.Mode().IsRegular() {
				continue
			}
			if depth+1 > maxDepth {
				return errTraversalDepthLimit
			}
			if isDir {
				child, openErr := openCheckedDirectory(root, entryPath)
				if openErr != nil {
					return openErr
				}
				walkErr := walk(child, entryPath, depth+1, active)
				child.Close()
				if walkErr != nil {
					return walkErr
				}
				continue
			}
			count++
			if count > maxFiles {
				return errTraversalFileLimit
			}
			if visitErr := visit(entryPath); visitErr != nil {
				return visitErr
			}
		}
		return nil
	}
	return walk(start, current, 0, rules)
}

func openCheckedDirectory(root, rel string) (*os.File, error) {
	name := root
	if rel != "" {
		name = filepath.Join(root, filepath.FromSlash(rel))
	}
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeFile
	}
	if !before.IsDir() {
		return nil, ErrNotDirectory
	}
	dir, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, err
	}
	after, err := os.Lstat(name)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		dir.Close()
		return nil, ErrUnsafeFile
	}
	return dir, nil
}

func nonLinuxReadGitignore(root, current string, denied map[string]bool, inherited []ignoreRule) ([]ignoreRule, error) {
	if denied[".gitignore"] {
		return inherited, nil
	}
	name := filepath.Join(root, filepath.FromSlash(current), ".gitignore")
	before, err := os.Lstat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return inherited, nil
		}
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return inherited, nil
	}
	if before.Size() > maxGitignoreBytes {
		return nil, ErrLimitExceeded
	}
	if hasMultipleLinks(before) {
		return nil, ErrUnsafeFile
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(name)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, after) || hasMultipleLinks(opened) {
		return nil, ErrUnsafeFile
	}
	data, err := io.ReadAll(io.LimitReader(file, maxGitignoreBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxGitignoreBytes {
		return nil, ErrLimitExceeded
	}
	return append(inherited, parseGitignore(data, current)...), nil
}

func secureAtomicWrite(root, rel string, data []byte, mode os.FileMode, expected string) error {
	name := filepath.Join(root, rel)
	before, statErr := os.Lstat(name)
	targetExisted := statErr == nil
	if targetExisted {
		if before.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeFile
		}
		if !before.Mode().IsRegular() {
			return ErrInvalidFileType
		}
		if hasMultipleLinks(before) {
			return ErrUnsafeFile
		}
		if expected == "" {
			return ErrConflict
		}
		current, err := os.Open(name)
		if err != nil {
			return err
		}
		opened, err := current.Stat()
		if err != nil || !os.SameFile(before, opened) {
			current.Close()
			return ErrConflict
		}
		h := sha256.New()
		_, hashErr := io.Copy(h, current)
		closeErr := current.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(h.Sum(nil)) != expected {
			return ErrConflict
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	} else if expected != "" {
		return ErrConflict
	}

	tmp, err := os.CreateTemp(filepath.Dir(name), ".remote-agent-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(mode.Perm()); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}

	current, currentErr := os.Lstat(name)
	if targetExisted {
		if currentErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(before, current) {
			return ErrConflict
		}
	} else if currentErr == nil {
		return ErrConflict
	} else if !os.IsNotExist(currentErr) {
		return currentErr
	}
	return os.Rename(tmpName, name)
}
