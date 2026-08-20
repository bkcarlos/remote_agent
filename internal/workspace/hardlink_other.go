//go:build !unix

package workspace

import "os"

func hasMultipleLinks(os.FileInfo) bool { return false }
