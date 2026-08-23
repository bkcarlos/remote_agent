//go:build !linux

package remoteworker

import "errors"

// RestrictFilesystem fails closed because the production Remote Worker sandbox
// requires Linux Landlock before any network connection or SSH handshake.
func RestrictFilesystem() error {
	return errors.New("production remote worker isolation is supported only on Linux")
}
