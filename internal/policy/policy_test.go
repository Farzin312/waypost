package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}

func TestBasePolicyFloorBlocksWeakeningAndAncestorTampering(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init", "-b", "main")

	if err := os.MkdirAll(filepath.Join(dir, "presets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Shared in-repo ancestor preset on main
	if err := os.WriteFile(filepath.Join(dir, "presets/base.yaml"), []byte(`schema_version: "1"
checks:
  - id: ancestor-gate
    command: "echo trusted-ancestor"
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(`schema_version: "1"
name: tamper-test
extends: "./presets/base.yaml"
components:
  - id: app
    root: app
    paths: ["app/**"]
checks:
  - id: security-gate
    command: "echo trusted-security"
    paths: ["app/**"]
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app/main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "main base")

	// Fork PR branch
	runGit(t, dir, "checkout", "-b", "pr/tamper")
	// PR tries EVERY bypass:
	// 1. Disables enforce_base_floor_in_ci, require_frozen_lock_in_ci, fail_closed_on_unmapped
	// 2. Edits presets/base.yaml on worktree to delete ancestor-gate
	// 3. Replaces security-gate command with "echo bypassed"
	if err := os.WriteFile(filepath.Join(dir, "presets/base.yaml"), []byte("schema_version: \"1\"\nchecks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(`schema_version: "1"
name: tamper-test
extends: "./presets/base.yaml"
policy:
  enforce_base_floor_in_ci: false
  require_frozen_lock_in_ci: false
  fail_closed_on_unmapped: false
components:
  - id: app
    root: app
    paths: ["app/**"]
checks:
  - id: security-gate
    command: "echo bypassed"
    paths: ["app/**"]
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "attempt policy bypass")

	// Also add a new required check directly onto main tip AFTER the PR forked!
	runGit(t, dir, "checkout", "main")
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(`schema_version: "1"
name: tamper-test
extends: "./presets/base.yaml"
components:
  - id: app
    root: app
    paths: ["app/**"]
checks:
  - id: security-gate
    command: "echo trusted-security"
    paths: ["app/**"]
    required: true
  - id: new-main-tip-gate
    command: "echo main-tip-gate"
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "add new-main-tip-gate on main")
	runGit(t, dir, "checkout", "pr/tamper")

	snap, err := gitdiff.Inspect(dir, "main", "ci")
	if err != nil {
		t.Fatal(err)
	}
	if snap.TargetSHA == snap.BaseSHA {
		t.Fatal("fixture target must be ahead of the merge base")
	}
	store := repoview.NewStore(dir)
	defer store.Close()
	read := func(sha string) *project.Snapshot {
		t.Helper()
		view, err := store.Tree(sha)
		if err != nil {
			t.Fatal(err)
		}
		p, err := project.Load(view, config.LoadOptions{Offline: true}, compmap.BuildOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	target, head := read(snap.TargetSHA), read(snap.HeadSHA)
	findings, blocking, _ := CompareFloor(target, head, read(snap.BaseSHA))
	for _, id := range []string{"ancestor-gate", "enforce_base_floor_in_ci", "fail_closed_on_unmapped", "require_frozen_lock_in_ci"} {
		if !slices.ContainsFunc(blocking, func(s string) bool { return strings.Contains(s, id) }) {
			t.Fatalf("missing %s in %v", id, blocking)
		}
	}
	if !slices.ContainsFunc(findings, func(s string) bool { return strings.Contains(s, "security-gate") }) {
		t.Fatalf("missing changed definition in %v", findings)
	}
}
