package archgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

func TestTypeScriptAliasesBoundariesPublicEntrypointsAndBlastRadius(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "tsconfig.json"), `{
  // JSONC comment should be stripped cleanly
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
    },
  }
}`)
	mustWrite(t, filepath.Join(dir, "src", "contracts", "types.ts"), `export interface User { id: string }`)
	mustWrite(t, filepath.Join(dir, "src", "ui", "button.ts"), `// import { bad } from "@/features/chat/internal/secret"
export const Button = () => null;
`)
	mustWrite(t, filepath.Join(dir, "src", "features", "chat", "index.ts"), `export { chatScreen } from "./internal/screen";`)
	mustWrite(t, filepath.Join(dir, "src", "features", "chat", "internal", "screen.ts"), `import { User } from "@/contracts/types";
import { Button } from "@/ui/button";
export const chatScreen = (u: User) => Button();
`)
	// Violation 1: routes deep-imports private chat/internal/screen instead of chat/index.ts!
	// Violation 2: ui imports contracts if allow_depends_on is [] (test below).
	mustWrite(t, filepath.Join(dir, "src", "routes", "home.ts"), `import { chatScreen } from "@/features/chat/internal/screen";
export const home = () => chatScreen({ id: "1" });
`)

	emptyAllow := []string{}
	cfg := &config.Config{
		Components: []config.ComponentConfig{
			{ID: "contracts", Root: "src/contracts", Paths: []string{"src/contracts/**"}},
			{ID: "ui", Root: "src/ui", Paths: []string{"src/ui/**"}},
			{ID: "chat", Root: "src/features/chat", Paths: []string{"src/features/chat/**"}, DependsOn: []string{"contracts", "ui"}},
			{ID: "routes", Root: "src/routes", Paths: []string{"src/routes/**"}, DependsOn: []string{"chat"}},
		},
		Boundaries: &config.BoundariesConfig{
			Enabled:             config.BoolPtr(true),
			Mode:                "enforce",
			NoCycles:            config.BoolPtr(true),
			EnforceDeclaredDeps: config.BoolPtr(true),
			Rules: []config.BoundaryRule{
				{ID: "contracts-pure-leaf", From: "contracts", AllowDependsOn: &emptyAllow},
				{ID: "ui-no-features", From: "ui", DenyDependsOn: []string{"chat"}},
				{ID: "chat-public-api", Target: "chat", PublicEntrypoints: []string{"src/features/chat/index.ts"}},
			},
		},
	}

	cm, err := compmap.Build(dir, cfg, nil)
	if err != nil {
		t.Fatalf("compmap.Build: %v", err)
	}
	rep, err := Analyze(dir, cm, cfg.Boundaries)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Commented import in ui/button.ts MUST NOT trigger ui-no-features!
	if len(rep.Violations) != 1 {
		t.Fatalf("expected exactly 1 violation (chat-public-api private import), got %d: %+v", len(rep.Violations), rep.Violations)
	}
	v := rep.Violations[0]
	if v.RuleID != "chat-public-api" || v.Kind != "private-import" || v.File != "src/routes/home.ts" || v.Line != 1 {
		t.Fatalf("unexpected violation: %+v", v)
	}

	// Blast radius of changing src/contracts/types.ts must reach chat/internal/screen.ts AND routes/home.ts!
	br := rep.ComputeBlastRadius([]string{"src/contracts/types.ts"})
	if len(br.DirectImporters) != 1 || br.DirectImporters[0] != "src/features/chat/internal/screen.ts" {
		t.Fatalf("unexpected direct importers: %v", br.DirectImporters)
	}
	if len(br.TransitiveFiles) != 3 {
		t.Fatalf("expected 3 transitive files (index.ts, screen.ts, home.ts), got %v", br.TransitiveFiles)
	}
	if len(br.TransitiveDependents) != 2 || br.TransitiveDependents[0] != "chat" || br.TransitiveDependents[1] != "routes" {
		t.Fatalf("expected transitive dependent components [chat routes], got %v", br.TransitiveDependents)
	}

	// Mermaid output must be valid flowchart LR.
	mm := RenderMermaid(rep)
	if !strings.HasPrefix(mm, "flowchart LR\n") || !strings.Contains(mm, "routes -->|") {
		t.Fatalf("unexpected mermaid:\n%s", mm)
	}
}

func TestPolyglotGoPythonRustImportEdgesAndCycles(t *testing.T) {
	dir := t.TempDir()

	// Go cycle: pkg/a <-> pkg/b
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/demo\n\ngo 1.24\n")
	mustWrite(t, filepath.Join(dir, "pkg", "a", "a.go"), "package a\nimport _ \"example.com/demo/pkg/b\"\n")
	mustWrite(t, filepath.Join(dir, "pkg", "b", "b.go"), "package b\nimport _ \"example.com/demo/pkg/a\"\n")

	// Python edge: tools/cli.py -> pycore/util.py
	mustWrite(t, filepath.Join(dir, "pycore", "util.py"), "def ok(): return True\n")
	mustWrite(t, filepath.Join(dir, "tools", "cli.py"), "from pycore.util import ok\n")

	// Rust edge: src/app/mod.rs -> src/core/mod.rs
	mustWrite(t, filepath.Join(dir, "crates", "demo", "src", "core", "mod.rs"), "pub fn run() {}\n")
	mustWrite(t, filepath.Join(dir, "crates", "demo", "src", "app", "mod.rs"), "use crate::core::run;\n")

	cfg := &config.Config{
		Components: []config.ComponentConfig{
			{ID: "go-a", Root: "pkg/a", Paths: []string{"pkg/a/**"}},
			{ID: "go-b", Root: "pkg/b", Paths: []string{"pkg/b/**"}},
			{ID: "py-core", Root: "pycore", Paths: []string{"pycore/**"}},
			{ID: "py-tools", Root: "tools", Paths: []string{"tools/**"}},
			{ID: "rs-core", Root: "crates/demo/src/core", Paths: []string{"crates/demo/src/core/**"}},
			{ID: "rs-app", Root: "crates/demo/src/app", Paths: []string{"crates/demo/src/app/**"}},
		},
		Boundaries: &config.BoundariesConfig{
			Enabled:  config.BoolPtr(true),
			Mode:     "enforce",
			NoCycles: config.BoolPtr(true),
		},
	}

	cm, err := compmap.Build(dir, cfg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rep, err := Analyze(dir, cm, cfg.Boundaries)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	edgeSet := map[string]bool{}
	for _, e := range rep.Edges {
		edgeSet[e.From+"->"+e.To] = true
	}
	for _, want := range []string{"go-a->go-b", "go-b->go-a", "py-tools->py-core", "rs-app->rs-core"} {
		if !edgeSet[want] {
			t.Fatalf("missing expected observed edge %q; got %v", want, edgeSet)
		}
	}
	if len(rep.Cycles) == 0 {
		t.Fatal("expected go-a <-> go-b cycle to be detected")
	}
	if len(rep.Cycles[0].Witnesses) == 0 || rep.Cycles[0].Witnesses[0].Line != 2 {
		t.Fatalf("expected exact line=2 witness in Go cycle, got %+v", rep.Cycles[0])
	}
	if len(rep.Violations) == 0 || rep.Violations[0].RuleID != "no-cycles" {
		t.Fatalf("expected no-cycles violation, got %+v", rep.Violations)
	}
}

func TestMigrateFromBounds(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "tsconfig.json"), `{}`)
	mustWrite(t, filepath.Join(dir, ".bounds", "root.yaml"), "version: '1'\nenforce: 'on'\n")
	mustWrite(t, filepath.Join(dir, ".bounds", "ignore"), "# comment\n**/*.test.ts\n")
	mustWrite(t, filepath.Join(dir, ".bounds", "manifests", "api.yaml"), `name: api
role: library
description: HTTP layer
paths:
  - src/api
exposes:
  - name: hugeSymbolChurn
    kind: function
consumes:
  - subsystem: contracts
`)
	mustWrite(t, filepath.Join(dir, ".bounds", "manifests", "contracts.yaml"), `name: contracts
role: library
paths:
  - src/contracts
`)

	bm, err := MigrateFromBounds(dir)
	if err != nil {
		t.Fatalf("MigrateFromBounds failed: %v", err)
	}
	if bm.Subsystems != 2 {
		t.Fatalf("expected 2 migrated subsystems, got %d", bm.Subsystems)
	}
	if !bm.Boundaries.IsEnabled() || bm.Boundaries.EffectiveMode() != "enforce" {
		t.Fatalf("expected enforce boundaries, got %+v", bm.Boundaries)
	}
	if len(bm.Boundaries.IgnorePaths) != 1 || bm.Boundaries.IgnorePaths[0] != "**/*.test.ts" {
		t.Fatalf("expected migrated ignore path, got %v", bm.Boundaries.IgnorePaths)
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
