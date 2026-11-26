//go:build windows

package shellcmd

import (
	"context"
	"os/exec"
	"syscall"
)

// CommandContext creates an OS-native cmd.exe command on Windows using raw
// SysProcAttr.CmdLine with `/d /s /c "<command>"` to avoid CommandLineToArgvW
// misquoting documented by Go's os/exec package.
func CommandContext(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: `cmd.exe /d /s /c "` + command + `"`,
	}
	return cmd
}
