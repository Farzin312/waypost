package compmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
)

func TestBoundsManifestStaticIngestionAndReverseDeps(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "tsconfig.json"), `{}`)
	mustWrite(t, filepath.Join(dir, ".bounds", "manifests", "contracts.yaml"), `name: contracts
role: library
description: Generated OpenAPI types
paths:
  - src/api/generated
`)
	mustWrite(t, filepath.Join(dir, ".bounds", "manifests", "api.yaml"), `name: api
role: library
description: HTTP client layer
paths:
  - src/api/*.ts
consumes:
  - subsystem: contracts
`)
	mustWrite(t, filepath.Join(dir, ".bounds", "manifests", "chat.yaml"), `name: chat
role: service
paths:
  - src/features/chat
consumes:
  - subsystem: api
  - subsystem: contracts
`)

	m, err := Build(dir, nil, []string{"src/api/generated/schema.ts", "src/api/client.ts", "src/features/chat/screen.tsx"})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if !m.Ecosystem.HasBounds {
		t.Fatal("expected Ecosystem.HasBounds=true")
	}

	byID := map[string]Component{}
	for _, c := range m.Components {
		byID[c.ID] = c
	}

	apiComp, ok := byID["api"]
	if !ok {
		t.Fatal("expected api component from .bounds/manifests")
	}
	if apiComp.Provenance != ProvenanceToolObserved {
		t.Fatalf("expected provenance=%s, got %s", ProvenanceToolObserved, apiComp.Provenance)
	}
	if apiComp.Root != "src/api" {
		t.Fatalf("expected normalized root src/api, got %q", apiComp.Root)
	}
	if apiComp.Language != "typescript" {
		t.Fatalf("expected typescript language, got %q", apiComp.Language)
	}

	imp := m.ImpactedByPaths([]string{"src/api/generated/schema.ts"})
	if len(imp.DirectComponents) != 1 || imp.DirectComponents[0] != "contracts" {
		t.Fatalf("expected direct component [contracts], got %v", imp.DirectComponents)
	}
	if len(imp.TransitiveDependents) != 2 || imp.TransitiveDependents[0] != "api" || imp.TransitiveDependents[1] != "chat" {
		t.Fatalf("expected transitive dependents [api chat], got %v", imp.TransitiveDependents)
	}
}

func TestAAIFSkillsDiscoveryAndDuplicateWarning(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "AGENTS.md"), "# AGENTS\n")
	mustWrite(t, filepath.Join(dir, ".agents", "skills", "quality-gates", "SKILL.md"), `---
name: quality-gates
description: Empirical pre-merge verification without fake passes
---
# Quality Gates
`)
	// Real non-symlink duplicate in .claude/skills should trigger warning.
	mustWrite(t, filepath.Join(dir, ".claude", "skills", "quality-gates", "SKILL.md"), "# duplicate")

	m, err := Build(dir, nil, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(m.Ecosystem.DiscoveredSkills) != 1 || m.Ecosystem.DiscoveredSkills[0].Name != "quality-gates" {
		t.Fatalf("expected quality-gates skill discovered, got %+v", m.Ecosystem.DiscoveredSkills)
	}
	if len(m.Ecosystem.DuplicateSkillPaths) != 1 {
		t.Fatalf("expected 1 duplicate skill path, got %v", m.Ecosystem.DuplicateSkillPaths)
	}
	foundDupGap := false
	for _, g := range m.CoverageGaps {
		if strings.Contains(g, ".claude/skills/") {
			foundDupGap = true
		}
	}
	if !foundDupGap {
		t.Fatalf("expected duplicate skill coverage gap warning, got %v", m.CoverageGaps)
	}

	// Replace with symlink -> warning should disappear.
	_ = os.RemoveAll(filepath.Join(dir, ".claude", "skills", "quality-gates"))
	if err := os.Symlink(filepath.Join(dir, ".agents", "skills", "quality-gates"), filepath.Join(dir, ".claude", "skills", "quality-gates")); err == nil {
		m2, err := Build(dir, nil, nil)
		if err != nil {
			t.Fatalf("Build2 failed: %v", err)
		}
		if len(m2.Ecosystem.DuplicateSkillPaths) != 0 {
			t.Fatalf("expected 0 duplicate skill paths when symlinked, got %v", m2.Ecosystem.DuplicateSkillPaths)
		}
	}
}

func TestPythonToolsGoReplaceCargoPathAndCycleDetection(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "tools", "check_data.py"), "print('ok')\n")
	mustWrite(t, filepath.Join(dir, "go", "lib", "go.mod"), "module example.com/lib\n\ngo 1.24\n")
	mustWrite(t, filepath.Join(dir, "go", "svc", "go.mod"), "module example.com/svc\n\ngo 1.24\nreplace example.com/lib => ../lib\n")
	mustWrite(t, filepath.Join(dir, "crates", "core", "Cargo.toml"), "[package]\nname = \"my-core\"\nversion = \"0.1.0\"\n")
	mustWrite(t, filepath.Join(dir, "crates", "cli", "Cargo.toml"), "[package]\nname = \"my-cli\"\nversion = \"0.1.0\"\n[dependencies]\nmy-core = { path = \"../core\" }\n")

	m, err := Build(dir, nil, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	byID := map[string]Component{}
	for _, c := range m.Components {
		byID[c.ID] = c
	}
	if _, ok := byID["tools-python"]; !ok {
		t.Fatalf("expected tools-python inferred component, got keys %v", keysOf(byID))
	}
	svc, ok := byID["svc"]
	if !ok || len(svc.DependsOn) != 1 || svc.DependsOn[0] != "lib" {
		t.Fatalf("expected go replace edge svc -> lib, got %+v", svc)
	}
	cliComp, ok := byID["my-cli"]
	if !ok || len(cliComp.DependsOn) != 1 || cliComp.DependsOn[0] != "my-core" {
		t.Fatalf("expected cargo path edge my-cli -> my-core, got %+v", cliComp)
	}

	// Cycle detection test via declared config.
	cycCfg := &config.Config{
		Components: []config.ComponentConfig{
			{ID: "alpha", Root: "a", DependsOn: []string{"beta"}},
			{ID: "beta", Root: "b", DependsOn: []string{"alpha"}},
		},
	}
	cmCyc, err := Build(dir, cycCfg, nil)
	if err != nil {
		t.Fatalf("Build cycle failed: %v", err)
	}
	foundCycle := false
	for _, g := range cmCyc.CoverageGaps {
		if strings.Contains(g, "cycle detected") {
			foundCycle = true
		}
	}
	if !foundCycle {
		t.Fatalf("expected cycle warning in coverage gaps, got %v", cmCyc.CoverageGaps)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func keysOf(m map[string]Component) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSymlinkOutsideRepoIgnoredAndSelfCycleDetected(t *testing.T) {
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "leak.yaml")
	mustWrite(t, outsideFile, "name: leaked\npaths:\n  - secret\n")
	outsideSkill := filepath.Join(outside, "SKILL.md")
	mustWrite(t, outsideSkill, "---\nname: leaked-skill\ndescription: secret\n---\n")

	repo := t.TempDir()
	_ = os.MkdirAll(filepath.Join(repo, ".bounds", "manifests"), 0o755)
	_ = os.Symlink(outsideFile, filepath.Join(repo, ".bounds", "manifests", "leak.yaml"))
	_ = os.MkdirAll(filepath.Join(repo, ".agents", "skills", "leak"), 0o755)
	_ = os.Symlink(outsideSkill, filepath.Join(repo, ".agents", "skills", "leak", "SKILL.md"))

	// Valid in-repo .bounds manifest with `./` prefix and self-cycle.
	mustWrite(t, filepath.Join(repo, ".bounds", "manifests", "selfloop.yaml"), `name: selfloop
role: library
paths:
  - ./src/selfloop
consumes:
  - subsystem: selfloop
`)

	m, err := Build(repo, nil, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	for _, c := range m.Components {
		if c.ID == "leaked" {
			t.Fatal("external symlink .bounds manifest should have been ignored")
		}
		if c.ID == "selfloop" && c.Root != "src/selfloop" {
			t.Fatalf("expected ./src/selfloop normalized to src/selfloop, got %q", c.Root)
		}
	}
	if len(m.Ecosystem.DiscoveredSkills) != 0 {
		t.Fatalf("external symlink SKILL.md should have been ignored, got %+v", m.Ecosystem.DiscoveredSkills)
	}
	foundSelfCycle := false
	for _, g := range m.CoverageGaps {
		if strings.Contains(g, "selfloop -> selfloop") {
			foundSelfCycle = true
		}
	}
	if !foundSelfCycle {
		t.Fatalf("expected self-cycle warning in coverage gaps, got %v", m.CoverageGaps)
	}
}
