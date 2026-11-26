//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVerifySIGTERMCleansUpCheckAndHandoff(t *testing.T) {
	if dir := os.Getenv("WAYPOST_SIGNAL_TEST_REPO"); dir != "" {
		os.Exit(Run([]string{"verify", "--dir", dir, "--base", "HEAD"}, os.Stdout, os.Stderr))
	}
	dir, temp := t.TempDir(), t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), `schema_version: '1'
checks:
  - id: sleeper
    command: 'printf "%s" "$WAYPOST_CHANGED_FILES_FILE" > "$WAYPOST_SIGNAL_STARTED"; sleep 5; touch "$WAYPOST_SIGNAL_ORPHAN"'
`)
	mustWriteFile(t, filepath.Join(dir, "app.go"), "package app\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "base")
	mustWriteFile(t, filepath.Join(dir, "app.go"), "package app\n// edit\n")
	marker, orphan := filepath.Join(temp, "started"), filepath.Join(temp, "orphan")
	cmd := exec.Command(os.Args[0], "-test.run=^TestVerifySIGTERMCleansUpCheckAndHandoff$")
	cmd.Env = append(os.Environ(), "TMPDIR="+temp, "WAYPOST_SIGNAL_TEST_REPO="+dir, "WAYPOST_SIGNAL_STARTED="+marker, "WAYPOST_SIGNAL_ORPHAN="+orphan)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	deadline := time.Now().Add(4 * time.Second)
	var changed []byte
	for time.Now().Before(deadline) {
		changed, _ = os.ReadFile(marker)
		if len(changed) > 0 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	handoff := string(changed)
	if !strings.HasPrefix(handoff, filepath.Join(temp, "waypost-changes-")) {
		t.Fatalf("no handoff observed: %q", handoff)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("expected verification failure after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("verify did not promptly cancel")
	}
	if _, err := os.Stat(filepath.Dir(handoff)); !os.IsNotExist(err) {
		t.Fatalf("handoff survived cancellation: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("descendant completed: %v", err)
	}
}
