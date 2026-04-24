//go:build unix

package config

import (
	"fmt"
	"os"
	"syscall"
)

func validateCacheOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("cache path %s is owned by uid %d, want uid %d", path, st.Uid, os.Getuid())
	}
	return nil
}
