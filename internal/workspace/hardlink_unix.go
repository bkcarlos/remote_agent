//go:build unix

package workspace

import (
	"os"
	"syscall"
)

func hasMultipleLinks(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}
