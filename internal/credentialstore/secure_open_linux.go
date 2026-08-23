//go:build linux

package credentialstore

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openSecureRegular(filePath, description string) (*os.File, error) {
	fd, err := unix.Open(filePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New(description + " is unavailable")
	}
	file := os.NewFile(uintptr(fd), description)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New(description + " is unavailable")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		_ = file.Close()
		return nil, errors.New(description + " must be a secure euid-owned regular file")
	}
	return file, nil
}
