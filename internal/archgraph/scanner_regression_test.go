package archgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

func TestTypeScriptLexingMultilineImportsAndExactLines(t *testing.T) {
	src := strings.Join([]string{
		"// import './wrong'",
		"/* export {x} from './wrong'",
		" */",
		"const a = 'require(\"./wrong\")';",
		"const b = \"import './wrong'\";",
		"const c = \x60import './wrong' ${\x60require(\"./wrong\") ${{x: '}'}}\x60}",
		" export './wrong'\x60;",
		"",
		"   import type {",
		"     T,",
		"   } from './types'",
		"import X,",
		"  { y } from './default'",
		"import /* initialized */ './side-effect'",
		"  export type {",
		"     T",
		"  } from './public-types'",
		"export * as extras",
		"  from './extras'",
		"export { Y } from './y'; export * from './z';",
		"const lazy = import(",
		" './lazy', { with: { type: 'json' } }",
		");",
		"const old = require(",
		"  './old'",
		");",
		"const x = obj.require('./wrong')",
		"import './esc\\x61ped'",
	}, "\n")
	want := []parsedRef{
		{9, "./types"}, {12, "./default"}, {14, "./side-effect"}, {15, "./public-types"},
		{18, "./extras"}, {20, "./y"}, {20, "./z"}, {21, "./lazy"}, {24, "./old"}, {28, "./escaped"},
	}
	if got := extractTSImports([]byte(src)); !reflect.DeepEqual(got, want) {
		t.Fatalf("TypeScript imports = %+v, want %+v", got, want)
	}
}

func TestTypeScriptExtendsAliasPriorityAndModuleExtensions(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"app/tsconfig.json": `{
			"extends": "../presets/tsconfig.middle",
			"compilerOptions": {
				"baseUrl": "../src",
				"paths": { "@overridden": ["from-child"], "@exact": ["exact"], "@tie/*z": ["suffix/*"] }
			}
		}`,
		"app/tsconfig.base.json":       `{"compilerOptions":{"baseUrl":"../wrong","paths":{"*":["*"]}}}`,
		"presets/tsconfig.middle.json": `{"extends":"./tsconfig.base","compilerOptions":{"paths":{"@overridden":["from-middle"]}}}`,
		"presets/tsconfig.base.json": `{
			"compilerOptions":{
				"baseUrl": "../wrong",
				"paths": {"@overridden":["from-parent"], "@exact*":["wild"], "@tie/*":["generic/*"], "@inherited/*":["inherit/*"]}
			}
		}`,
		"app/index.mts":               "import '@overridden';\nimport '@exact';\nimport '@tie/valuez';\nimport '@inherited/tool';\nimport '../src/common.cjs';",
		"src/from-child.cts":          "import './extra.mjs';",
		"src/exact.mts":               "",
		"src/generic/valuez.mts":      "",
		"src/suffix/value.cts":        "",
		"src/inherit/tool.cts":        "",
		"src/common.cts":              "",
		"src/extra.mts":               "",
		"src/wild.cts":                "",
		"wrong/from-child.mts":        "",
		"fallback/tsconfig.base.json": `{"compilerOptions":{"paths":{"@fallback":["module"]}}}`,
		"fallback/module.cts":         "",
		"fallback/importer.cts":       "import '@fallback';",
	})
	g, err := Analyze(dir, &compmap.Map{}, nil)
	if err != nil || len(g.ScanErrors) > 0 {
		t.Fatalf("scan: %v, %+v", err, g)
	}
	if g.FilesScanned != 12 {
		t.Fatalf("scanned %d source files, want 12", g.FilesScanned)
	}
	for file, want := range map[string][]string{
		"app/index.mts":         {"src/from-child.cts", "src/exact.mts", "src/generic/valuez.mts", "src/inherit/tool.cts", "src/common.cts"},
		"src/from-child.cts":    {"src/extra.mts"},
		"fallback/importer.cts": {"fallback/module.cts"},
	} {
		var got []string
		for _, imp := range g.rawImports {
			if imp.File == file {
				got = append(got, imp.TargetFile)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s targets = %v, want %v", file, got, want)
		}
	}
}

func TestTSConfigExtendsCyclesAndMissingTrackedInputsFailClosed(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"tsconfig.json":      `{"extends":"./tsconfig.base"}`,
		"tsconfig.base.json": `{"extends":"./tsconfig"}`,
		"app.ts":             "import './absent';",
	})
	policy := &config.BoundariesConfig{Enabled: config.BoolPtr(true)}
	g, err := Analyze(dir, &compmap.Map{}, policy)
	if err != nil || len(g.ScanErrors) != 1 || !strings.Contains(g.ScanErrors[0], "extends cycle") {
		t.Fatalf("cyclic extension scan: %v, %+v", err, g)
	}
	files := map[string]bool{"app.ts": true, "tsconfig.json": true, "deleted.ts": true}
	g, err = AnalyzeWithOptions(dir, &compmap.Map{}, policy, AnalyzeOptions{AllowedFiles: files})
	if err != nil || len(g.Violations) != 2 ||
		!strings.Contains(g.ScanErrors[0], "deleted.ts") ||
		!strings.Contains(g.ScanErrors[1], "unavailable file") {
		t.Fatalf("tracked scan: %v, %+v", err, g)
	}
}

func TestPythonSubmodulesAndSingleCharacterImports(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"a.py": "", "b/__init__.py": "",
		"pkg/sub/__init__.py": "", "pkg/sub/helper.py": "", "pkg/sub/utils/__init__.py": "",
		"pkg/sub/more.py": "", "pkg/shared/__init__.py": "", "pkg/shared/submodule.py": "",
		"pkg/sub/app.py": "\n\nimport a, b as c\nfrom . import helper, utils as u\n\nfrom ..shared import submodule\n\nfrom . import (\n  more, # comment\n)\nimportant = 'a'\n",
	})
	g, err := Analyze(dir, &compmap.Map{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		line   int
		target string
	}{
		{3, "a.py"}, {3, "b/__init__.py"},
		{4, "pkg/sub/__init__.py"}, {4, "pkg/sub/helper.py"}, {4, "pkg/sub/utils/__init__.py"},
		{6, "pkg/shared/__init__.py"}, {6, "pkg/shared/submodule.py"},
		{8, "pkg/sub/__init__.py"}, {8, "pkg/sub/more.py"},
	}
	if len(g.rawImports) != len(want) {
		t.Fatalf("Python imports = %+v, want %+v", g.rawImports, want)
	}
	for i, w := range want {
		if got := g.rawImports[i]; got.Line != w.line || got.TargetFile != w.target {
			t.Errorf("import %d = %+v, want %+v", i, got, w)
		}
	}
}

func TestRustGroupedRelativeAndWorkspaceImports(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"Cargo.toml":                   "[workspace]\nmembers = ['crates/app', 'crates/shared']",
		"crates/app/Cargo.toml":        "[package]\nname = 'my-app'",
		"crates/shared/Cargo.toml":     "[package]\nname = \"my-shared-crate\"",
		"crates/shared/src/lib.rs":     "",
		"crates/shared/src/foo.rs":     "",
		"crates/app/src/a.rs":          "",
		"crates/app/src/b/c.rs":        "",
		"crates/app/src/b/nested/d.rs": "",
		"crates/app/src/d/mod.rs":      "",
		"crates/app/src/main.rs":       "",
		"crates/app/src/sub/helper.rs": "",
		"crates/app/src/sub/child.rs":  "",
		"crates/app/src/sub/mod.rs": strings.Join([]string{
			"",
			"  pub(crate) mod child;",
			"",
			"  use crate::{",
			"      a, b::{c, nested::{d as renamed}}, d as e",
			"  };",
			"  use super::{a, b::c};",
			"  use super::d;",
			"  use self::helper;",
			"  use my_shared_crate::{foo, self as shared};",
			"  const TEXT: &str = r#\"use crate::a;\"#;",
			"  /* /* comment */ use crate::a; */",
		}, "\n"),
	})
	g, err := Analyze(dir, &compmap.Map{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := []struct {
		line int
		file string
	}{
		{2, "app/src/sub/child.rs"}, {4, "app/src/a.rs"}, {4, "app/src/b/c.rs"},
		{4, "app/src/b/nested/d.rs"}, {4, "app/src/d/mod.rs"},
		{7, "app/src/a.rs"}, {7, "app/src/b/c.rs"}, {8, "app/src/d/mod.rs"},
		{9, "app/src/sub/helper.rs"}, {10, "shared/src/foo.rs"}, {10, "shared/src/lib.rs"},
	}
	if len(g.rawImports) != len(expected) {
		t.Fatalf("Rust imports = %+v, want %+v", g.rawImports, expected)
	}
	for i, w := range expected {
		if got := g.rawImports[i]; got.Line != w.line || got.TargetFile != "crates/"+w.file {
			t.Errorf("import %d = %+v, want %+v", i, got, w)
		}
	}
}

func TestGoPackageEntrypointsAndBlastRadius(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"go.mod":          "module example.com/demo",
		"api/aaa.ts":      "",
		"api/load.go":     "package api\n",
		"api/types.go":    "package api\n",
		"onlyjs/index.ts": "",
		"client/use.go":   "package client\nimport (\n_ \"example.com/demo/api\"\n_ \"example.com/demo/onlyjs\"\n)\n",
		"top/run.go":      "package top\nimport _ \"example.com/demo/client\"\n",
	})
	cm := &compmap.Map{Components: []compmap.Component{
		{ID: "api", Root: "api", Paths: []string{"api/**"}},
		{ID: "client", Root: "client", Paths: []string{"client/**"}},
		{ID: "top", Root: "top", Paths: []string{"top/**"}},
	}}
	policy := &config.BoundariesConfig{Enabled: config.BoolPtr(true), Rules: []config.BoundaryRule{
		{ID: "public-go-file", Target: "api", PublicEntrypoints: []string{"api/types.go"}},
		{ID: "public-go-package", Target: "api", PublicEntrypoints: []string{"api"}},
		{ID: "non-go-file", Target: "api", PublicEntrypoints: []string{"api/*.ts"}},
	}}
	g, err := Analyze(dir, cm, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.rawImports) != 2 || g.rawImports[0].TargetFile != "api/load.go" || g.rawImports[0].TargetPackageDir != "api" {
		t.Fatalf("unexpected resolved Go imports: %+v", g.rawImports)
	}
	if len(g.Violations) != 1 || g.Violations[0].RuleID != "non-go-file" {
		t.Fatalf("expected only the non-Go entrypoint to be rejected: %+v", g.Violations)
	}
	br := g.ComputeBlastRadius([]string{"api/types.go"})
	if !slices.Equal(br.DirectImporters, []string{"client/use.go"}) || !slices.Equal(br.TransitiveFiles, []string{"client/use.go", "top/run.go"}) {
		t.Fatalf("unexpected Go package blast radius: %+v", br)
	}
	first := g.ComputeBlastRadius([]string{"api/types.go", "client/use.go"})
	second := g.ComputeBlastRadius([]string{"client/use.go", "api/types.go"})
	if !reflect.DeepEqual(first, second) || !slices.Equal(first.DirectImporters, []string{"top/run.go"}) {
		t.Fatalf("changed importers must be excluded in either order: first=%+v second=%+v", first, second)
	}
}

func TestScanExplicitPlatformAndHiddenComponents(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"ios/app.ts":             "import '../android/bridge';",
		"android/bridge.ts":      "import '../.github/scripts/lib';",
		".github/scripts/lib.ts": "",
		"src/.generated/gen.ts":  "",
		".cache/ignored.ts":      "",
		"other/ios/skipped.ts":   "",
	})
	cm := &compmap.Map{Components: []compmap.Component{
		{ID: "ios", Root: "ios", Paths: []string{"ios/**"}, Provenance: compmap.ProvenanceDeclared},
		{ID: "android", Root: ".", Paths: []string{"android/**"}, Provenance: compmap.ProvenanceDeclared},
		{ID: "ci", Root: ".", Paths: []string{".github/**"}, Provenance: compmap.ProvenanceDeclared},
		{ID: "gen", Root: ".", Paths: []string{"src/**/.generated/**"}, Provenance: compmap.ProvenanceDeclared},
	}}
	g, err := Analyze(dir, cm, nil)
	if err != nil || g.FilesScanned != 4 || g.ImportsScanned != 2 {
		t.Fatalf("explicit platform and hidden scan: %v, %+v", err, g)
	}
}

func TestIncompleteScanReportsUnreadableOversizedAndMissingInputs(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"app.ts":        "import './oversized'; import './unreadable';",
		"oversized.ts":  strings.Repeat(" ", maxSourceFileBytes+1),
		"unreadable.ts": "import './app';",
	})
	unreadable := filepath.Join(dir, "unreadable.ts")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	_, readErr := os.ReadFile(unreadable)
	wantErrors, wantFiles, wantImports := 2, 1, 0
	if readErr == nil {
		wantErrors, wantFiles, wantImports = 1, 2, 2 // e.g. tests running as root
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 && readErr == nil {
		t.Fatal("fixture expected to be unreadable")
	}
	for _, mode := range []string{"enforce", "warn", "off"} {
		t.Run(mode, func(t *testing.T) {
			var policy *config.BoundariesConfig
			if mode != "off" {
				policy = &config.BoundariesConfig{Enabled: config.BoolPtr(true), Mode: mode}
			}
			g, err := Analyze(dir, &compmap.Map{}, policy)
			if err != nil || g.FilesScanned != wantFiles || g.ImportsScanned != wantImports ||
				len(g.ScanErrors) != wantErrors || !strings.Contains(g.ScanErrors[0], "oversized.ts") {
				t.Fatalf("incomplete scan: %v, %+v", err, g)
			}
			if mode == "off" {
				if len(g.Violations) != 0 || !strings.Contains(RenderText(g), "Scan errors:") {
					t.Fatalf("unexpected reporting for disabled boundaries: %+v", g)
				}
				return
			}
			if len(g.Violations) != wantErrors {
				t.Fatalf("expected %d violations, got %+v", wantErrors, g.Violations)
			}
			for _, v := range g.Violations {
				if v.RuleID != "incomplete-scan" || (v.Severity == "error") != (mode == "enforce") {
					t.Errorf("unexpected violation: %+v", v)
				}
			}
		})
	}
	for _, root := range []string{filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "app.ts")} {
		if _, err := Analyze(root, &compmap.Map{}, nil); err == nil {
			t.Errorf("invalid scan root %s passed", root)
		}
	}
}

func TestWalkDirFailureRecordedForUnreadableDirectory(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	mustWrite(t, filepath.Join(blocked, "app.ts"), "import './never-scanned';")
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
	if _, err := os.ReadDir(blocked); err == nil {
		t.Skip("this environment can read a mode 000 directory")
	}
	g, err := Analyze(dir, &compmap.Map{}, &config.BoundariesConfig{Enabled: config.BoolPtr(true)})
	if err != nil || len(g.ScanErrors) != 1 || len(g.Violations) != 1 || g.FilesScanned != 0 {
		t.Fatalf("unreadable subtree did not fail enforcement: %v, %+v", err, g)
	}
	if _, err := Analyze(blocked, &compmap.Map{}, nil); err == nil {
		t.Fatal("unwalkable root passed")
	}
}

func TestMermaidDisambiguatesComponentsAndEdges(t *testing.T) {
	g := &Report{
		Nodes: []NodeMetrics{{ID: "foo_bar_2", FileCount: 1}, {ID: "foo-bar", FileCount: 1}, {ID: "foo_bar", FileCount: 1}},
		Edges: []ComponentEdge{{From: "foo-bar", To: "foo_bar", ImportCount: 2}, {From: "foo_bar", To: "foo_bar_2", ImportCount: 3}},
	}
	mermaid := RenderMermaid(g)
	for _, want := range []string{`foo_bar["foo-bar `, `foo_bar_2["foo_bar `, `foo_bar_2_2["foo_bar_2 `, "foo_bar -->|2| foo_bar_2", "foo_bar_2 -->|3| foo_bar_2_2"} {
		if !strings.Contains(mermaid, want) {
			t.Errorf("missing %q in diagram:\n%s", want, mermaid)
		}
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, data := range files {
		mustWrite(t, filepath.Join(dir, rel), data)
	}
}
