//go:build windows

package shellcmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// CommandContext creates an OS-native cmd.exe command on Windows using raw
// SysProcAttr.CmdLine with `/d /s /c "<command>"` to avoid CommandLineToArgvW
// misquoting documented by Go's os/exec package.
func CommandContext(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: `cmd.exe /d /s /c "` + command + `"`,
	}
	cmd.Cancel = func() error {
		tool := filepath.Join(os.Getenv("SystemRoot"), "System32", "taskkill.exe")
		killCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if err := exec.CommandContext(killCtx, tool, "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid)).Run(); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 750 * time.Millisecond
	return cmd
}

// cmd.exe does not expose Unix process groups. Cancellation uses taskkill.
func cleanup(_ *exec.Cmd) {}
