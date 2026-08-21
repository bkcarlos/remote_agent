//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ErrLandlockUnavailable = errors.New("landlock is unavailable")

type rulesetAttr struct{ HandledAccessFS uint64 }
type pathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
	Reserved      uint32
}

func ApplyWorkspace(root string, writable bool) error {
	abi, err := landlockABI()
	if errors.Is(err, ErrLandlockUnavailable) {
		// Workspace operations still use openat2 with RESOLVE_BENEATH and reject
		// symlinks. Landlock is an additional defense which older kernels may lack.
		return nil
	}
	if err != nil {
		return err
	}
	handled := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		handled |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	attr := rulesetAttr{HandledAccessFS: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create landlock ruleset: %w", errno)
	}
	rulesetFD := int(fd)
	defer unix.Close(rulesetFD)
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	allowed := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	if writable {
		allowed |= unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_REG
		if abi >= 2 {
			allowed |= unix.LANDLOCK_ACCESS_FS_REFER
		}
		if abi >= 3 {
			allowed |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
		}
	}
	rule := pathBeneathAttr{AllowedAccess: allowed, ParentFD: int32(rootFD)}
	_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD), 1, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("add landlock workspace rule: %w", errno)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return fmt.Errorf("apply landlock ruleset: %w", errno)
	}
	return nil
}

func Supported() error {
	_, err := landlockABI()
	return err
}

func landlockABI() (uintptr, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno == 0 {
		return abi, nil
	}
	// ENOSYS means the kernel predates Landlock, EOPNOTSUPP means it was
	// disabled at boot, and EPERM is commonly returned by container seccomp
	// profiles which do not expose the Landlock syscalls.
	if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP || errno == unix.EPERM {
		return 0, fmt.Errorf("%w: %v", ErrLandlockUnavailable, errno)
	}
	return 0, fmt.Errorf("query landlock ABI: %w", errno)
}
