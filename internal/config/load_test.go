package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBuiltinInheritanceAndLocalOverrideIgnoredInCI(t *testing.T) {
	dir := t.TempDir()
	mainYAML := `schema_version: "1"
name: demo-app
extends: "builtin:app-ts@1.0.0"
checks:
  - id: ts-typecheck
    command: "pnpm typecheck"
    paths: ["src/**/*.ts"]
    required: true
`
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(mainYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	localYAML := `schema_version: "1"
disable_checks:
  - ts-test
`
	if err := os.WriteFile(filepath.Join(dir, LocalConfigFileName), []byte(localYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Local mode applies .waypost.local.yaml
	localRes, err := Load(dir, LoadOptions{Mode: "local"})
	if err != nil {
		t.Fatalf("local load failed: %v", err)
	}
	if !localRes.LocalOverrideApplied || localRes.LocalOverrideIgnored {
		t.Fatalf("expected local override applied, got applied=%v ignored=%v", localRes.LocalOverrideApplied, localRes.LocalOverrideIgnored)
	}
	if len(localRes.Chain) != 2 {
		t.Fatalf("expected 2 ancestors (base -> app-ts), got %d: %+v", len(localRes.Chain), localRes.Chain)
	}
	if len(localRes.Effective.Checks) != 1 || localRes.Effective.Checks[0].Command != "pnpm typecheck" {
		t.Fatalf("unexpected checks in local mode: %+v", localRes.Effective.Checks)
	}

	// CI mode strictly ignores .waypost.local.yaml
	ciRes, err := Load(dir, LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatalf("ci load failed: %v", err)
	}
	if ciRes.LocalOverrideApplied || !ciRes.LocalOverrideIgnored {
		t.Fatalf("expected local override ignored in ci, got applied=%v ignored=%v", ciRes.LocalOverrideApplied, ciRes.LocalOverrideIgnored)
	}
	if len(ciRes.Effective.Checks) != 2 {
		t.Fatalf("expected both ts-typecheck and ts-test in ci mode, got %+v", ciRes.Effective.Checks)
	}
}

func TestLoadRejectsCyclesAndDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	// Cycle: a.yaml -> b.yaml -> a.yaml
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("schema_version: \"1\"\nextends: \"./b.yaml\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("schema_version: \"1\"\nextends: \"./a.yaml\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), []byte("schema_version: \"1\"\nextends: \"./a.yaml\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, LoadOptions{Mode: "local"}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}

	// Duplicate IDs
	dupYAML := `schema_version: "1"
checks:
  - id: lint
    command: "echo 1"
  - id: lint
    command: "echo 2"
`
	if _, err := ParseBytes([]byte(dupYAML), "dup.yaml"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}
