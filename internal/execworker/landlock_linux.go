//go:build linux

package execworker

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errExecLandlockUnavailable = errors.New("Landlock is unavailable")

type execRulesetAttr struct{ HandledAccessFS uint64 }
type execPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
	Reserved      uint32
}

func execLandlockABI() (uintptr, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno == 0 {
		return abi, nil
	}
	if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP || errno == unix.EPERM {
		return 0, fmt.Errorf("%w: %v", errExecLandlockUnavailable, errno)
	}
	return 0, errno
}

func applyExecLandlock(executable, workspace string, mode WorkspaceMode) error {
	abi, err := execLandlockABI()
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
	attr := execRulesetAttr{HandledAccessFS: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return errno
	}
	ruleset := int(fd)
	defer unix.Close(ruleset)
	// Do not grant read access to /. This keeps same-UID host secrets (for
	// example, other home directories) outside the task's view. These paths are
	// the minimum common dynamic-loader/toolchain runtime set; absent optional
	// paths are ignored.
	readAccess := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	for _, path := range []string{
		executable, "/usr", "/bin", "/sbin", "/lib", "/lib64", "/nix/store",
		"/etc/ld.so.cache", "/etc/ssl", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/proc",
	} {
		if err := addExecLandlockPathIfExists(ruleset, path, readAccess); err != nil {
			return err
		}
	}
	if mode != WorkspaceNone {
		workspaceAccess := readAccess
		if mode == WorkspaceReadWrite {
			workspaceAccess |= uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
				unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
				unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
				unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
			if abi >= 2 {
				workspaceAccess |= unix.LANDLOCK_ACCESS_FS_REFER
			}
			if abi >= 3 {
				workspaceAccess |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
			}
		}
		if err := addExecLandlockPath(ruleset, workspace, workspaceAccess); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func addExecLandlockPathIfExists(ruleset int, path string, access uint64) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		access &^= unix.LANDLOCK_ACCESS_FS_READ_DIR
	}
	return addExecLandlockPath(ruleset, path, access)
}

func addExecLandlockPath(ruleset int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	rule := execPathBeneathAttr{AllowedAccess: access, ParentFD: int32(fd)}
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), 1, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
