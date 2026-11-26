package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestUpgradeDryRunAndApply(t *testing.T) {
	dir := t.TempDir()
	presetV1 := filepath.Join(dir, "org-v1.yaml")
	presetV2 := filepath.Join(dir, "org-v2.yaml")

	if err := os.WriteFile(presetV1, []byte(`schema_version: "1"
name: org-base
preset_version: "1.0.0"
rules:
  - id: old-crutch
    kind: crutch
    summary: "Old guidance"
checks:
  - id: base-lint
    command: "echo lint-v1"
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(presetV2, []byte(`schema_version: "1"
name: org-base
preset_version: "2.0.0"
rules:
  - id: new-invariant
    kind: invariant
    summary: "New permanent invariant"
checks:
  - id: base-lint
    command: "echo lint-v2"
    required: true
providers:
  - id: custom-prov
    tool: sh
    command: "echo '{}'"
    authorized: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, config.ConfigFileName), []byte(`schema_version: "1"
name: sample-repo
extends: "../org-v1.yaml"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res1, err := config.Load(repo, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockfile.Write(repo, lockfile.Generate(res1)); err != nil {
		t.Fatal(err)
	}

	// Dry-run reports added/removed rules, check change, and permission change without writing.
	dry, err := Run(repo, Options{Target: "../org-v2.yaml", Apply: false})
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if !dry.Changed || dry.Applied {
		t.Fatalf("expected changed=true applied=false, got %+v", dry)
	}
	if len(dry.AddedRules) != 1 || len(dry.RemovedRules) != 1 || len(dry.ChangedChecks) != 1 || len(dry.PermissionChanges) != 1 {
		t.Fatalf("unexpected dry-run diff: %+v", dry)
	}

	// Apply writes updated config & lockfile cleanly.
	applied, err := Run(repo, Options{Target: "../org-v2.yaml", Apply: true})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !applied.Applied || applied.NewLockDigest == "" {
		t.Fatalf("expected applied=true with lock digest, got %+v", applied)
	}

	res2, err := config.Load(repo, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if v := lockfile.Verify(repo, res2); !v.Valid {
		t.Fatalf("lockfile invalid after apply: %+v", v)
	}
}
