//go:build linux

package execworker

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type childSpec struct {
	Executable    string            `json:"executable"`
	Argv          []string          `json:"argv,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Workspace     string            `json:"workspace"`
	WorkspaceMode WorkspaceMode     `json:"workspace_mode"`
	CachePaths    []string          `json:"cache_paths,omitempty"`
	Limits        Limits            `json:"limits"`
	Production    bool              `json:"production"`
}

func configureExecChild(cmd *exec.Cmd, group *execCgroup) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Unshareflags:               syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
		Setpgid:                    true,
	}
	attachExecCgroup(cmd.SysProcAttr, group)
}

// RunExecChild is used only by cmd/exec-worker --exec-child. The task spec is
// accepted exclusively from inherited fd 3; there is no shell parser.
func RunExecChild() error {
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return errors.New("set child parent-death signal")
	}
	if os.Getppid() == 1 {
		return errors.New("exec supervisor disappeared before child setup")
	}
	pipe := os.NewFile(3, "exec-supervisor-spec")
	if pipe == nil {
		return errors.New("exec child spec pipe is unavailable")
	}
	var spec childSpec
	if err := ReadFrame(pipe, &spec); err != nil {
		pipe.Close()
		return errors.New("invalid exec child spec")
	}
	pipe.Close()
	if err := validateChildSpec(spec); err != nil {
		return err
	}
	if err := applyChildRlimits(spec.Limits); err != nil {
		return errors.New("apply child resource limits")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return errors.New("make child mount namespace private")
	}
	// A fresh procfs is mandatory: inheriting the host proc mount would expose
	// host PID metadata despite CLONE_NEWPID.
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return errors.New("mount child PID namespace procfs")
	}
	if err := bringExecLoopbackUp(); err != nil {
		return errors.New("initialize child loopback interface")
	}
	if err := applyExecLandlock(spec.Executable, spec.Workspace, spec.WorkspaceMode, spec.CachePaths); err != nil && spec.Production {
		return errors.New("apply production workspace isolation")
	}
	if spec.WorkspaceMode == WorkspaceNone {
		if err := os.Chdir("/"); err != nil {
			return errors.New("enter neutral working directory")
		}
	} else if err := os.Chdir(spec.Workspace); err != nil {
		return errors.New("enter authorized workspace")
	}
	if err := applyExecSeccomp(); err != nil {
		return errors.New("apply child seccomp policy")
	}
	env := make([]string, 0, len(spec.Env))
	names := make([]string, 0, len(spec.Env))
	for name := range spec.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, name+"="+spec.Env[name])
	}
	argv := append([]string{spec.Executable}, spec.Argv...)
	return unix.Exec(spec.Executable, argv, env)
}

func validateChildSpec(spec childSpec) error {
	if !filepath.IsAbs(spec.Executable) || !filepath.IsAbs(spec.Workspace) || strings.IndexByte(spec.Executable, 0) >= 0 || strings.IndexByte(spec.Workspace, 0) >= 0 {
		return errors.New("invalid exec child paths")
	}
	if err := spec.Limits.Validate(); err != nil {
		return errors.New("invalid exec child limits")
	}
	switch spec.WorkspaceMode {
	case WorkspaceNone, WorkspaceReadOnly, WorkspaceReadWrite:
	default:
		return errors.New("invalid exec child workspace mode")
	}
	for _, cachePath := range spec.CachePaths {
		if err := validateCachePath(cachePath); err != nil {
			return errors.New("invalid exec child cache path")
		}
	}
	for _, arg := range spec.Argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("invalid exec child argv")
		}
	}
	for name, value := range spec.Env {
		if !envNamePattern.MatchString(name) || strings.IndexByte(value, 0) >= 0 {
			return errors.New("invalid exec child environment")
		}
	}
	return nil
}

func bringExecLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	request, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return err
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request)
}

func applyChildRlimits(limits Limits) error {
	// RLIMIT_AS is intentionally not used as a memory-consumption limit. Go and
	// JVM runtimes reserve large sparse virtual address ranges, so tying address
	// space to memory_bytes prevents Docker/Bazel from starting without limiting
	// actual resident memory. Production mode requires cgroup v2 memory.max and
	// disabled swap, which enforce the signed physical-memory budget.
	values := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_CPU, uint64(limits.CPUSeconds)},
		{unix.RLIMIT_NPROC, uint64(limits.PIDs)},
		{unix.RLIMIT_NOFILE, 256},
		{unix.RLIMIT_CORE, 0},
	}
	for _, value := range values {
		if err := unix.Setrlimit(value.resource, &unix.Rlimit{Cur: value.value, Max: value.value}); err != nil {
			return err
		}
	}
	return nil
}

func linuxIsolationSupported() error {
	if _, err := execAuditArch(); err != nil {
		return err
	}
	_, err := execLandlockABI()
	return err
}

func applyExecSeccomp() error {
	arch, err := execAuditArch()
	if err != nil {
		return err
	}
	denied := []uint32{
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_MOUNT, unix.SYS_UMOUNT2,
		unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_REBOOT, unix.SYS_SETNS, unix.SYS_UNSHARE,
	}
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: arch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		// JVM/Bazel needs IP and netlink sockets to inspect the isolated loopback
		// interface. Path-addressed AF_UNIX (including Docker/Podman sockets),
		// AF_PACKET, and every other socket family remain denied. Anonymous
		// socketpair is allowed for JVM/process-local wakeups and cannot connect
		// to an existing daemon path. The child inherits no socket FDs.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 5, K: unix.SYS_SOCKET},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, K: unix.AF_INET},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, K: unix.AF_INET6},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AF_NETLINK},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	for _, number := range denied {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: number},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}
	// Preserve supervisor-death cleanup: the task may use other harmless prctl
	// operations, but it cannot clear or replace PR_SET_PDEATHSIG.
	filters = append(filters,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: unix.SYS_PRCTL},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.PR_SET_PDEATHSIG},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	)
	filters = append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return errno
	}
	return nil
}

func execAuditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, nil
	case "386":
		return unix.AUDIT_ARCH_I386, nil
	default:
		return 0, fmt.Errorf("seccomp architecture %s is unsupported", runtime.GOARCH)
	}
}
