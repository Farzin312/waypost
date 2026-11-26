package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
)

func TestBasePolicyFloorCatchesCheckRemovalInPR(t *testing.T) {
	dir := t.TempDir()
	mustGit := func(args ...string) {
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

	mustGit("init", "-b", "main")
	baseCfg := `schema_version: "1"
name: tamper-test
extends: "builtin:base@1.0.0"
components:
  - id: app
    root: app
    paths: ["app/**"]
checks:
  - id: security-gate
    command: "echo secure"
    paths: ["app/**"]
    required: true
`
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app/main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(baseCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit("add", ".")
	mustGit("commit", "-m", "base with security-gate")

	// PR branch deletes security-gate from .waypost.yaml
	mustGit("checkout", "-b", "pr/tamper")
	prCfg := `schema_version: "1"
name: tamper-test
extends: "builtin:base@1.0.0"
components:
  - id: app
    root: app
    paths: ["app/**"]
checks: []
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(prCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit("add", ".")
	mustGit("commit", "-m", "sneakily remove required check")

	resolved, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := gitdiff.Inspect(dir, "main", "ci")
	if err != nil {
		t.Fatal(err)
	}
	cm, err := compmap.Build(dir, &resolved.Effective, nil)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := Plan(dir, "ci", resolved, cm, snap, false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.PolicyFloorEnforced {
		t.Fatal("expected base policy floor to be enforced")
	}
	if !plan.TrustBoundaryTriggered || !plan.FullRepoEscalated {
		t.Fatalf("expected trust boundary & full escalation, got %+v", plan)
	}
	if len(plan.TamperingFindings) == 0 {
		t.Fatal("expected tampering finding for removed security-gate")
	}
	foundRestored := false
	for _, sc := range plan.Checks {
		if sc.Check.ID == "security-gate" && sc.Selected && sc.FromBase {
			foundRestored = true
		}
	}
	if !foundRestored {
		t.Fatalf("expected security-gate to be restored from base floor, got checks: %+v", plan.Checks)
	}
}
