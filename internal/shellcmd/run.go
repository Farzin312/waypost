package shellcmd

import (
	"os"
	"os/exec"
	"slices"
	"strings"
)

// Run waits for the shell and cleans up descendants left in its process group.
func Run(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return Wait(cmd)
}

func Wait(cmd *exec.Cmd) error {
	err := cmd.Wait()
	cleanup(cmd)
	return err
}

// Environment removes runner write channels and inherited selector inputs.
func Environment() []string {
	return slices.DeleteFunc(os.Environ(), func(entry string) bool {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "WAYPOST_CHANGED_FILES_FILE", "WAYPOST_BASE_SHA", "WAYPOST_HEAD_SHA", "WAYPOST_NO_TESTS_EXIT_CODE",
			"GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY":
			return true
		default:
			return false
		}
	})
}
