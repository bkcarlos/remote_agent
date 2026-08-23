package workspace

import (
	"errors"
	"io/fs"
)

var (
	ErrInvalidPath     = errors.New("invalid workspace path")
	ErrDeniedPath      = errors.New("workspace path is denied by policy")
	ErrNotFound        = errors.New("workspace entry not found")
	ErrPermission      = errors.New("workspace permission denied")
	ErrNotDirectory    = errors.New("workspace entry is not a directory")
	ErrInvalidFileType = errors.New("workspace entry has an invalid file type")
	ErrUnsafeFile      = errors.New("unsafe workspace entry")
	ErrLimitExceeded   = errors.New("workspace resource limit exceeded")
	ErrInvalidPattern  = errors.New("invalid workspace pattern")
	ErrConflict        = errors.New("workspace entry changed during operation")
	ErrIO              = errors.New("workspace operation failed")
)

// SafeError is returned by exported workspace operations. It deliberately keeps
// the underlying OS error private so Error never exposes a host path.
type SafeError struct {
	Operation string
	kind      error
}

func (e *SafeError) Error() string {
	if e == nil {
		return "workspace operation failed"
	}
	kind := e.kind
	if kind == nil {
		kind = ErrIO
	}
	if e.Operation == "" {
		return kind.Error()
	}
	return "workspace " + e.Operation + ": " + kind.Error()
}

// Kind returns the stable, path-free error category.
func (e *SafeError) Kind() error {
	if e == nil {
		return nil
	}
	return e.kind
}

// Unwrap exposes only a stable, path-free error category for errors.Is.
func (e *SafeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

func safeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var safe *SafeError
	if errors.As(err, &safe) {
		return safe
	}

	kind := ErrIO
	switch {
	case errors.Is(err, ErrInvalidPath), errors.Is(err, fs.ErrInvalid):
		kind = ErrInvalidPath
	case errors.Is(err, ErrDeniedPath):
		kind = ErrDeniedPath
	case errors.Is(err, ErrNotFound), errors.Is(err, fs.ErrNotExist):
		kind = ErrNotFound
	case errors.Is(err, ErrPermission), errors.Is(err, fs.ErrPermission):
		kind = ErrPermission
	case errors.Is(err, ErrNotDirectory):
		kind = ErrNotDirectory
	case errors.Is(err, ErrInvalidFileType):
		kind = ErrInvalidFileType
	case errors.Is(err, ErrUnsafeFile):
		kind = ErrUnsafeFile
	case errors.Is(err, ErrLimitExceeded):
		kind = ErrLimitExceeded
	case errors.Is(err, ErrInvalidPattern):
		kind = ErrInvalidPattern
	case errors.Is(err, ErrConflict), errors.Is(err, fs.ErrExist):
		kind = ErrConflict
	}
	return &SafeError{Operation: operation, kind: kind}
}
