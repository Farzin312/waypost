package upgrade

import (
	"encoding/json"
	"os"
	"os/exec"
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
	res, err := config.Load(repo, config.LoadOptions{Mode: "local"})
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

func TestUpgradePreviewComparesProofsAndExecutionLanes(t *testing.T) {
	dir := t.TempDir()
	const original = `schema_version: '1'
rules:
  - id: invariant
    kind: invariant
    summary: tracked behavior
    verified_by: {checks: [gate], tests: [proof_test.go]}
checks:
  - {id: gate, command: 'echo full', local_command: 'echo local', serial: true}
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(dir, Options{Apply: true}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		raw           string
		rules, checks int
	}{
		{original, 0, 0},
		{strings.Replace(original, "proof_test.go", "another_test.go", 1), 1, 0},
		{strings.Replace(original, "echo local", "echo seam", 1), 0, 1},
		{strings.Replace(original, "serial: true", "serial: false", 1), 0, 1},
	} {
		p, err := Run(dir, Options{CandidateConfig: []byte(f.raw)})
		if err != nil || len(p.ChangedRules) != f.rules || len(p.ChangedChecks) != f.checks {
			t.Fatalf("upgrade preview: %+v %v", p, err)
		}
	}
}

func TestUpgradeRecoversInterruptedSharedPublication(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, config.ConfigFileName)
	const original = "schema_version: '1'\nname: original\n"
	const interrupted = "schema_version: '1'\nname: interrupted\n"
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(dir, Options{Apply: true}); err != nil {
		t.Fatal(err)
	}
	// Install the same durable journal used by sync immediately before publication.
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s %v", raw, err)
		}
	}
	runGit("init")
	meta := filepath.Join(dir, ".git", "waypost")
	if err := os.MkdirAll(meta, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, _ := json.Marshal([]map[string]any{{"Path": config.ConfigFileName, "Old": []byte(original), "New": []byte(interrupted), "Mode": 0o644}})
	journalPath := filepath.Join(meta, "sync-transaction.json")
	if err := os.WriteFile(journalPath, journal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(interrupted), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Run(dir, Options{Apply: true, Target: "builtin:base@1.0.0"})
	if err != nil || !p.Applied {
		t.Fatalf("upgrade after interrupted sync: %+v %v", p, err)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("journal survived: %v", err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil || !strings.Contains(string(raw), "name: original") || strings.Contains(string(raw), "interrupted") {
		t.Fatalf("recovery was not applied before planning: %s %v", raw, err)
	}
}
