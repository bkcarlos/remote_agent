//go:build !linux

package credentialstore

import (
	"errors"
	"os"
)

func openSecureRegular(filePath, description string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.New(description + " is unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		_ = file.Close()
		return nil, errors.New(description + " must be a secure regular file")
	}
	return file, nil
}
