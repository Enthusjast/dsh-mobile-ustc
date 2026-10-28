//go:build unix

package coldarchive

import (
	"os"
	"syscall"
)

func identity(info os.FileInfo) (uint64, uint64, error) {
	state, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(state.Uid) != os.Geteuid() {
		return 0, 0, ErrInvalid
	}
	return uint64(state.Dev), uint64(state.Ino), nil
}
