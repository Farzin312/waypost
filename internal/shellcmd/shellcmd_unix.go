//go:build !windows

package shellcmd

import (
	"context"
	"os/exec"
)

// CommandContext creates an OS-native shell command for Unix platforms.
func CommandContext(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", command)
}
