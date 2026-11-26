package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/presets"
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

func TestNoBoundariesPreservesPolicyDigestAndPinnedAppTSPreset(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "polyglot-native")
	res, err := Load(dir, LoadOptions{Mode: "ci", Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Effective.Boundaries != nil || res.Effective.Boundaries.IsEnabled() {
		t.Fatalf("omitted boundaries became configured: %+v", res.Effective.Boundaries)
	}
	const originalDigest = "236c164a29236f19fd1cf95bc34fea605ebda5796b505cb4f7a90e2b91524d0f"
	if res.PolicyDigest != originalDigest {
		t.Fatalf("policy digest = %s, want %s", res.PolicyDigest, originalDigest)
	}
	raw, err := json.Marshal(res.Effective)
	if err != nil || bytes.Contains(raw, []byte(`"boundaries"`)) {
		t.Fatalf("omitted boundaries are in the effective config JSON: %s, %v", raw, err)
	}
	pinned, err := presets.Resolve("builtin:app-ts@1.0.0")
	const originalSHA = "dd7e7093a8522c523de8a89ab29cef926b24cde97ae7d84f8c6514fed983d4fb"
	if err != nil || pinned.SHA256 != originalSHA {
		t.Fatalf("app-ts@1.0.0 pin changed: %+v, %v", pinned, err)
	}
}

func TestBoundaryInheritanceDoesNotMutateParent(t *testing.T) {
	parent := &BoundariesConfig{
		Enabled:     BoolPtr(true),
		IgnorePaths: []string{"base/**"},
		Rules:       []BoundaryRule{{ID: "scope", From: "base", DenyDependsOn: []string{"internal"}}},
	}
	child := &BoundariesConfig{
		Mode:        "warn",
		IgnorePaths: []string{"local/**"},
		Rules:       []BoundaryRule{{ID: "scope", From: "child", DenyDependsOn: []string{"internal"}}},
	}
	got := mergeConfigs(Config{Boundaries: parent}, Config{Boundaries: child}).Boundaries
	if !got.IsEnabled() || got.EffectiveMode() != "warn" || got.Rules[0].From != "child" ||
		!slices.Equal(got.IgnorePaths, []string{"base/**", "local/**"}) {
		t.Fatalf("merged boundary policy = %+v", got)
	}
	if parent.Mode != "" || parent.Rules[0].From != "base" || !slices.Equal(parent.IgnorePaths, []string{"base/**"}) {
		t.Fatalf("mutation of inherited boundary policy: %+v", parent)
	}
}

func TestRatchetBaselinePathValidation(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	baseline := "schema_version: '1'\nboundaries: {enabled: true, mode: ratchet, baseline: '%s'}\n"
	for _, rel := range []string{"/tmp/baseline.json", "../baseline.json", "policy/../baseline.json", "C:/escape.json", ".git/config", "policy//baseline.json"} {
		if _, err := ParseBytes([]byte(fmt.Sprintf(baseline, rel)), "fixture"); err == nil {
			t.Fatalf("accepted unsafe baseline path %q", rel)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dir, "policies")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	raw := []byte(fmt.Sprintf(baseline, "policies/baseline.json"))
	if _, err := Load(dir, LoadOptions{Mode: "ci", OverrideRootRaw: raw}); err == nil {
		t.Fatal("worktree config accepted baseline path through escaping parent")
	}
	// The same path may be regular on the base branch. Resolving trusted config
	// from Git must not validate it against the PR's filesystem.
	reader := func(string) ([]byte, bool, error) { return nil, false, nil }
	if _, err := Load(dir, LoadOptions{Mode: "ci", OverrideRootRaw: raw, RepoFileReader: reader}); err != nil {
		t.Fatalf("trusted config consulted the worktree: %v", err)
	}
}

func TestBoundariesYAMLMerge(t *testing.T) {
	cfg, err := ParseBytes([]byte(`schema_version: '1'
boundaries:
  <<: [&preferred {enabled: true, mode: warn, baseline: tests/debt.json}, {enabled: false, no_cycles: false}]
  mode: ratchet
`), "merged boundaries")
	if err != nil || !cfg.Boundaries.IsEnabled() || cfg.Boundaries.EffectiveMode() != "ratchet" ||
		cfg.Boundaries.BaselinePath() != "tests/debt.json" || BoolVal(cfg.Boundaries.NoCycles, true) {
		t.Fatalf("YAML merge lost fields or override precedence: %+v, %v", cfg, err)
	}
	for _, merged := range []string{"{baseline: 123}", "{baseline: null}", "{baseline: ''}", "{unknown: true}"} {
		raw := []byte("schema_version: '1'\nboundaries: {<<: " + merged + "}\n")
		if _, err := ParseBytes(raw, "invalid merged boundaries"); err == nil {
			t.Fatalf("accepted invalid merged fields: %s", merged)
		}
	}
}
