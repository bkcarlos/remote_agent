//go:build linux

package workspace

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func secureOpen(root, rel string, directory bool) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(rootFD, filepath.ToSlash(rel), &unix.OpenHow{
		Flags:   flags,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func secureWalkFiles(root, rel string, denied map[string]bool, maxFiles int, visit func(string) error) error {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if denied[strings.ToLower(part)] {
			return errors.New("traversal root is denied by policy")
		}
	}
	start, err := secureOpen(root, rel, true)
	if err != nil {
		return err
	}
	defer start.Close()
	prefix := filepath.ToSlash(filepath.Clean(rel))
	if prefix == "." {
		prefix = ""
	}
	count := 0
	var walk func(*os.File, string) error
	walk = func(dir *os.File, current string) error {
		entries, err := dir.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			if denied[strings.ToLower(name)] {
				continue
			}
			var st unix.Stat_t
			if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			kind := st.Mode & unix.S_IFMT
			if kind == unix.S_IFLNK {
				continue
			}
			path := name
			if current != "" {
				path = current + "/" + name
			}
			if kind == unix.S_IFDIR {
				fd, err := unix.Openat2(int(dir.Fd()), name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
				if err != nil {
					return err
				}
				child := os.NewFile(uintptr(fd), name)
				err = walk(child, path)
				child.Close()
				if err != nil {
					return err
				}
				continue
			}
			if kind != unix.S_IFREG {
				continue
			}
			count++
			if count > maxFiles {
				return errors.New("file traversal limit exceeded")
			}
			if err := visit(path); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(start, prefix)
}

func secureAtomicWrite(root, rel string, data []byte, mode os.FileMode, expected string) error {
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	parent, base := filepath.Dir(rel), filepath.Base(rel)
	parentFD, err := unix.Openat2(rootFD, filepath.ToSlash(parent), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	// Reject a symlink or non-regular existing destination using the same parent handle.
	var original unix.Stat_t
	targetExisted := false
	if targetFD, openErr := unix.Openat2(parentFD, base, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS}); openErr == nil {
		targetExisted = true
		if err := unix.Fstat(targetFD, &original); err != nil {
			unix.Close(targetFD)
			return err
		}
		if original.Mode&unix.S_IFMT != unix.S_IFREG {
			unix.Close(targetFD)
			return errors.New("write target is not a regular file")
		}
		if expected != "" {
			file := os.NewFile(uintptr(targetFD), base)
			h := sha256.New()
			_, hashErr := io.Copy(h, file)
			file.Close()
			if hashErr != nil {
				return hashErr
			}
			if hex.EncodeToString(h.Sum(nil)) != expected {
				return errors.New("expected hash mismatch")
			}
		} else {
			unix.Close(targetFD)
		}
	} else if !errors.Is(openErr, unix.ENOENT) {
		return openErr
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tmpName := ".remote-agent-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(parentFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	tmp := os.NewFile(uintptr(fd), tmpName)
	cleanup := true
	defer func() {
		tmp.Close()
		if cleanup {
			_ = unix.Unlinkat(parentFD, tmpName, 0)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Bind the precondition to the same directory entry immediately before rename.
	var current unix.Stat_t
	statErr := unix.Fstatat(parentFD, base, &current, unix.AT_SYMLINK_NOFOLLOW)
	if targetExisted {
		if statErr != nil || current.Dev != original.Dev || current.Ino != original.Ino {
			return errors.New("write target changed during operation")
		}
	} else if statErr == nil {
		return errors.New("write target appeared during operation")
	} else if !errors.Is(statErr, unix.ENOENT) {
		return statErr
	}
	if err := unix.Renameat(parentFD, tmpName, parentFD, base); err != nil {
		return err
	}
	cleanup = false
	// Persist the directory entry where supported.
	return unix.Fsync(parentFD)
}
