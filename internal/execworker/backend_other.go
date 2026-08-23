//go:build !linux

package execworker

func platformSupported() error { return ErrUnsupported }

func newBackend(Config) (backend, error) { return nil, ErrUnsupported }
