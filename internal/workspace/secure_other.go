//go:build !linux

package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
		if statErr != nil || !st.IsDir() {
			f.Close()
			return nil, errors.New("not a directory")
		}
	}
	return f, nil
}

func secureWalkFiles(root, rel string, denied map[string]bool, maxFiles int, visit func(string) error) error {
	start := filepath.Join(root, rel)
	count := 0
	return filepath.WalkDir(start, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != start && denied[strings.ToLower(entry.Name())] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		count++
		if count > maxFiles {
			return errors.New("file traversal limit exceeded")
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return visit(filepath.ToSlash(name))
	})
}

func secureAtomicWrite(root, rel string, data []byte, mode os.FileMode, expected string) error {
	path := filepath.Join(root, rel)
	if expected != "" {
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(current)
		if hex.EncodeToString(sum[:]) != expected {
			return errors.New("expected hash mismatch")
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".remote-agent-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}
