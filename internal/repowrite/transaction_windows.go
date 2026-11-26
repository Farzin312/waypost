package repowrite

import (
	"os"
	"syscall"
	"unsafe"
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

func lockFile(file *os.File) error {
	var position syscall.Overlapped
	const lockfileExclusiveLock = 2
	ok, _, err := lockFileEx.Call(file.Fd(), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&position)))
	if ok == 0 {
		return err
	}
	return nil
}

func flushDir(string) error { return nil }
