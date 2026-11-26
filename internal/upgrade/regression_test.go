package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestUpgradeDetectsTimeoutSkillVersionAndRepairsStaleResolverLock(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "p1.yaml")
	p2 := filepath.Join(dir, "p2.yaml")

	if err := os.WriteFile(p1, []byte(`schema_version: "1"
checks:
  - id: c1
    command: "echo ok"
    timeout_seconds: 60
    required: true
skills:
  - id: s1
    source: "https://agentskills.io/example"
    version: "1.0.0"
    authorized: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte(`schema_version: "1"
checks:
  - id: c1
    command: "echo ok"
    timeout_seconds: 120
    required: true
skills:
  - id: s1
    source: "https://agentskills.io/example"
    version: "2.0.0"
    authorized: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	// Use a YAML alias node for extends to ensure replaceExtendsField handles aliases!
	if err := os.WriteFile(filepath.Join(repo, config.ConfigFileName), []byte(`schema_version: "1"
name: &ref "../p1.yaml"
extends: *ref
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := config.Load(repo, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	lf := lockfile.Generate(res)
	// Corrupt only resolver_version in lockfile to verify upgrade detects & repairs it!
	lf.ResolverVersion = "0"
	if _, err := lockfile.Write(repo, lf); err != nil {
		t.Fatal(err)
	}

	repairPlan, err := Run(repo, Options{Apply: true})
	if err != nil {
		t.Fatalf("repair upgrade failed: %v", err)
	}
	if !repairPlan.Changed || !repairPlan.Applied {
		t.Fatalf("expected resolver_version mismatch to be detected and repaired, got %+v", repairPlan)
	}

	// Now dry-run upgrade to p2 using YAML alias extends
	dry, err := Run(repo, Options{Target: "../p2.yaml", Apply: false})
	if err != nil {
		t.Fatalf("dry-run with YAML alias failed: %v", err)
	}
	if len(dry.ChangedChecks) != 1 || !strings.Contains(dry.ChangedChecks[0], "timeout=60s->120s") {
		t.Fatalf("expected timeout change surfaced, got %+v", dry.ChangedChecks)
	}
	if len(dry.PermissionChanges) != 1 || !strings.Contains(dry.PermissionChanges[0], "2.0.0") {
		t.Fatalf("expected authorized skill version change surfaced, got %+v", dry.PermissionChanges)
	}
}
