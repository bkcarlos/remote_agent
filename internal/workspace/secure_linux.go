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

	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	start := os.NewFile(uintptr(rootFD), ".")
	current := ""
	var rules []ignoreRule

	if rel != "." {
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if part == "" || part == "." {
				continue
			}
			// Denied names are checked before reading ignore rules, statting, or
			// opening the requested child.
			if denied[strings.ToLower(part)] {
				start.Close()
				return ErrDeniedPath
			}
			rules, err = linuxReadGitignore(start, current, denied, rules)
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
			fd, openErr := unix.Openat2(int(start.Fd()), part, &unix.OpenHow{
				Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
				Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
			})
			if openErr != nil {
				start.Close()
				return openErr
			}
			start.Close()
			start = os.NewFile(uintptr(fd), part)
			current = childPath
		}
	}
	defer start.Close()

	count := 0
	var walk func(*os.File, string, int, []ignoreRule) error
	walk = func(dir *os.File, current string, depth int, inherited []ignoreRule) error {
		active, readErr := linuxReadGitignore(dir, current, denied, inherited)
		if readErr != nil {
			return readErr
		}
		entries, readErr := dir.ReadDir(-1)
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			name := entry.Name()
			// This must remain the first per-entry policy decision. In
			// particular, a ! rule can never re-include a denied name.
			if denied[strings.ToLower(name)] {
				continue
			}
			var st unix.Stat_t
			if statErr := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
				return statErr
			}
			kind := st.Mode & unix.S_IFMT
			if kind == unix.S_IFLNK {
				continue
			}
			entryPath := name
			if current != "" {
				entryPath = current + "/" + name
			}
			isDir := kind == unix.S_IFDIR
			if ignoredByRules(active, entryPath, isDir) {
				continue
			}
			if kind != unix.S_IFDIR && kind != unix.S_IFREG {
				continue
			}
			if depth+1 > maxDepth {
				return ErrLimitExceeded
			}
			if isDir {
				fd, openErr := unix.Openat2(int(dir.Fd()), name, &unix.OpenHow{
					Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
					Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
				})
				if openErr != nil {
					return openErr
				}
				child := os.NewFile(uintptr(fd), name)
				walkErr := walk(child, entryPath, depth+1, active)
				child.Close()
				if walkErr != nil {
					return walkErr
				}
				continue
			}
			count++
			if count > maxFiles {
				return ErrLimitExceeded
			}
			if visitErr := visit(entryPath); visitErr != nil {
				return visitErr
			}
		}
		return nil
	}
	return walk(start, current, 0, rules)
}

func linuxReadGitignore(dir *os.File, current string, denied map[string]bool, inherited []ignoreRule) ([]ignoreRule, error) {
	if denied[".gitignore"] {
		return inherited, nil
	}
	var before unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), ".gitignore", &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return inherited, nil
		}
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return inherited, nil
	}
	fd, err := unix.Openat2(int(dir.Fd()), ".gitignore", &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), ".gitignore")
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Dev != before.Dev || opened.Ino != before.Ino || opened.Nlink > 1 {
		return nil, ErrUnsafeFile
	}
	if opened.Size > maxGitignoreBytes {
		return nil, ErrLimitExceeded
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

const secureAtomicWriteChunkSize = 64 << 10

type secureAtomicWriteHooks struct {
	afterTempWriteChunk func(int)
}

func secureAtomicWrite(root, rel string, data []byte, mode os.FileMode, expected string) error {
	return secureAtomicWriteWithHooks(root, rel, data, mode, expected, nil)
}

func secureAtomicWriteWithHooks(root, rel string, data []byte, mode os.FileMode, expected string, hooks *secureAtomicWriteHooks) error {
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

	// Capture an existing target through the parent handle and keep its file
	// descriptor open through the final validation immediately before rename.
	var original unix.Stat_t
	var target *os.File
	targetExisted := false
	targetFD, openErr := unix.Openat2(parentFD, base, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if openErr == nil {
		targetExisted = true
		if err := unix.Fstat(targetFD, &original); err != nil {
			unix.Close(targetFD)
			return err
		}
		if original.Mode&unix.S_IFMT != unix.S_IFREG {
			unix.Close(targetFD)
			return ErrInvalidFileType
		}
		if original.Nlink > 1 {
			unix.Close(targetFD)
			return ErrUnsafeFile
		}
		if expected == "" {
			unix.Close(targetFD)
			return ErrConflict
		}
		target = os.NewFile(uintptr(targetFD), base)
		defer target.Close()
	} else if !errors.Is(openErr, unix.ENOENT) {
		return openErr
	} else if expected != "" {
		return ErrConflict
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
	if err := writeAtomicTemp(tmp, data, hooks); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if targetExisted {
		var beforeHash unix.Stat_t
		if err := unix.Fstat(int(target.Fd()), &beforeHash); err != nil ||
			!sameLinuxTargetIdentity(original, beforeHash) ||
			beforeHash.Mode&unix.S_IFMT != unix.S_IFREG || beforeHash.Nlink > 1 {
			return ErrConflict
		}
		h := sha256.New()
		if _, err := io.Copy(h, target); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != expected {
			return ErrConflict
		}
		var afterHash unix.Stat_t
		if err := unix.Fstat(int(target.Fd()), &afterHash); err != nil ||
			!sameLinuxTargetState(original, beforeHash) ||
			!sameLinuxTargetState(beforeHash, afterHash) {
			return ErrConflict
		}
		var current unix.Stat_t
		if err := unix.Fstatat(parentFD, base, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameLinuxTargetState(afterHash, current) {
			return ErrConflict
		}
		if err := unix.Renameat(parentFD, tmpName, parentFD, base); err != nil {
			return err
		}
	} else {
		var current unix.Stat_t
		statErr := unix.Fstatat(parentFD, base, &current, unix.AT_SYMLINK_NOFOLLOW)
		if statErr == nil {
			return ErrConflict
		}
		if !errors.Is(statErr, unix.ENOENT) {
			return statErr
		}
		if err := unix.Renameat2(parentFD, tmpName, parentFD, base, unix.RENAME_NOREPLACE); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return ErrConflict
			}
			return err
		}
	}
	cleanup = false
	// Persist the directory entry where supported.
	return unix.Fsync(parentFD)
}

func writeAtomicTemp(tmp *os.File, data []byte, hooks *secureAtomicWriteHooks) error {
	written := 0
	for written < len(data) {
		end := written + secureAtomicWriteChunkSize
		if end > len(data) {
			end = len(data)
		}
		n, err := tmp.Write(data[written:end])
		written += n
		if n > 0 && hooks != nil && hooks.afterTempWriteChunk != nil {
			hooks.afterTempWriteChunk(written)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func sameLinuxTargetIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func sameLinuxTargetState(left, right unix.Stat_t) bool {
	return sameLinuxTargetIdentity(left, right) &&
		left.Mode == right.Mode &&
		left.Nlink == right.Nlink &&
		left.Size == right.Size &&
		left.Mtim.Sec == right.Mtim.Sec &&
		left.Mtim.Nsec == right.Mtim.Nsec &&
		left.Ctim.Sec == right.Ctim.Sec &&
		left.Ctim.Nsec == right.Ctim.Nsec
}
