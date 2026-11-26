//go:build !windows

package repowrite

import (
	"os"
	"syscall"
)

func lockFile(file *os.File) error { return syscall.Flock(int(file.Fd()), syscall.LOCK_EX) }

func flushDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
