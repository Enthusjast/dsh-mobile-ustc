//go:build !unix

package coldarchive

import "os"

// File ownership and durable directory sync require a reviewed platform adapter.
func identity(os.FileInfo) (uint64, uint64, error) { return 0, 0, ErrUnavailable }
