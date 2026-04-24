//go:build !unix

package config

import "os"

func validateCacheOwner(path string, fi os.FileInfo) error {
	return nil
}
