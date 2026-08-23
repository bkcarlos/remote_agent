package remoteworker

import (
	"errors"
	"path"
	"strings"

	"github.com/bkcarlos/remote_agent/internal/credentialstore"
)

func CommandAllowed(argv []string, allowedPrefixes [][]string) bool {
	if len(argv) == 0 {
		return false
	}
	for _, prefix := range allowedPrefixes {
		if len(prefix) == 0 || len(argv) < len(prefix) {
			continue
		}
		matches := true
		for i := range prefix {
			if argv[i] != prefix[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

// QuoteArgv applies strict POSIX single-quote encoding after argv policy has
// been evaluated. Callers never accept or pass through a user shell string.
func QuoteArgv(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("argv cannot be empty")
	}
	quoted := make([]string, len(argv))
	for i, argument := range argv {
		if strings.IndexByte(argument, 0) >= 0 {
			return "", errors.New("argv cannot contain NUL")
		}
		quoted[i] = "'" + strings.ReplaceAll(argument, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " "), nil
}

func NormalizeAndAuthorizeRemotePath(raw string, roots []string) (string, error) {
	if err := normalizeRemotePath(raw); err != nil {
		return "", err
	}
	for _, root := range roots {
		if raw == root || root == "/" || strings.HasPrefix(raw, root+"/") {
			return raw, nil
		}
	}
	return "", errors.New("remote path is outside allowed SFTP roots")
}

func authorizeResolvedPath(resolved string, roots []string) error {
	clean := path.Clean(resolved)
	if !path.IsAbs(clean) {
		return errors.New("SFTP server returned a non-absolute path")
	}
	for _, root := range roots {
		if clean == root || root == "/" || strings.HasPrefix(clean, root+"/") {
			return nil
		}
	}
	return errors.New("remote path resolves outside allowed SFTP roots")
}

func operationAllowed(job Job, snapshot credentialstore.Snapshot) error {
	if job.ProfileName != snapshot.Name {
		return errors.New("remote job profile name mismatch")
	}
	if job.Operation == OperationSSHExec {
		if !CommandAllowed(job.Argv, snapshot.AllowedCommands) {
			return errors.New("SSH argv is not allowed by the profile")
		}
		return nil
	}
	if _, err := NormalizeAndAuthorizeRemotePath(job.RemotePath, snapshot.SFTP.Roots); err != nil {
		return err
	}
	if job.Operation == OperationSFTPRename {
		if _, err := NormalizeAndAuthorizeRemotePath(job.DestinationPath, snapshot.SFTP.Roots); err != nil {
			return err
		}
	}
	switch job.Operation {
	case OperationSFTPList, OperationSFTPRead:
		if !snapshot.SFTP.Read {
			return errors.New("SFTP read access is disabled")
		}
	case OperationSFTPWrite, OperationSFTPMkdir, OperationSFTPRename:
		if !snapshot.SFTP.Write {
			return errors.New("SFTP write access is disabled")
		}
	default:
		return errors.New("unsupported remote operation")
	}
	return nil
}
