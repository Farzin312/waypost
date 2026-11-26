//go:build !windows

package shellcmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// CommandContext creates an OS-native shell command for Unix platforms.
func CommandContext(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 500 * time.Millisecond
	return cmd
}

func cleanup(cmd *exec.Cmd) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
