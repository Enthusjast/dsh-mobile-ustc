package coldarchive

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadKeyFile accepts exactly 32 raw bytes from a non-symlinked, owner-only
// regular file. The returned buffer belongs to the caller and should be cleared.
func ReadKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 || len(path) > 4096 {
		return nil, ErrInvalid
	}
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() != 32 {
		return nil, ErrInvalid
	}
	if _, _, err := identity(before); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) || actual.Size() != 32 {
		return nil, ErrInvalid
	}
	value, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(value) != 32 {
		clear(value)
		return nil, ErrInvalid
	}
	return value, nil
}
