package archgraph

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

func TestMigrationPreservesPublicFilesAndReportsSymbolRestrictions(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		".bounds/root.yaml": "subsystems: [app, api, contracts, extras]\nenforce: on\n",
		".bounds/ignore":    "# old exclusions\nsrc/generated/\n/vendor\n**/*.test.ts\n",
		".bounds/manifests/app.yaml": `name: app
files: [src/app/use.ts]
consumes:
  - api
  - subsystem: contracts
    interfaces: [User]
`,
		".bounds/manifests/api.yaml": `name: api
paths: [src/api]
exposes:
  - name: publicAPI
    kind: function
    signature: "() => void"
  - AnotherSymbol
`,
		".bounds/manifests/contracts.yaml": `name: contracts
paths: [src/contracts]
exposes:
  - entry.mts
`,
		".bounds/manifests/extras.yaml": "name: extras\npaths: [src/extras]\nexposes: [someSymbol]\n",
		".bounds/manifests/stale.yaml":  "name: stale\npaths: ['**']\n",
		"src/app/use.ts":                "import '../api';\nimport '../api/private';\nimport '../contracts/entry';\nimport '../contracts/private';",
		"src/api/index.ts":              "export { publicAPI } from './private';",
		"src/api/private.ts":            "export const publicAPI = () => {}; export const internal = 42;",
		"src/contracts/entry.mts":       "export type User = string;",
		"src/contracts/private.mts":     "export type Private = string;",
	})
	migration, err := MigrateFromBounds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if migration.Subsystems != 4 || migration.Boundaries.EffectiveMode() != "enforce" {
		t.Fatalf("migration: %+v", migration)
	}
	if app := migration.Components[1]; app.ID != "app" || app.Root != "src/app" ||
		!slices.Equal(app.Paths, []string{"src/app/use.ts"}) || !slices.Equal(app.DependsOn, []string{"api", "contracts"}) {
		t.Fatalf("files-only subsystem or consumes lost: %+v", app)
	}
	if rules := migration.Boundaries.Rules; len(rules) != 2 ||
		!slices.Equal(rules[0].PublicEntrypoints, []string{"src/api/index.ts"}) ||
		!slices.Equal(rules[1].PublicEntrypoints, []string{"src/contracts/entry.mts"}) {
		t.Fatalf("unexpected public entrypoint migration: %+v", rules)
	}
	warnings := strings.Join(migration.Warnings, "\n")
	if !strings.Contains(warnings, `"api" has symbol-level exposes`) ||
		!strings.Contains(warnings, "with file-level public_entrypoints") ||
		!strings.Contains(warnings, `"extras" has symbol-level exposes`) ||
		!strings.Contains(warnings, "no public entrypoint files could be identified") ||
		strings.Contains(warnings, `"contracts"`) {
		t.Fatalf("unexpected warnings: %s", warnings)
	}
	if want := []string{"**/*.test.ts", "src/generated/**", "vendor/**"}; !slices.Equal(migration.Boundaries.IgnorePaths, want) {
		t.Fatalf("ignore paths = %v, want %v", migration.Boundaries.IgnorePaths, want)
	}
	for _, rel := range []string{"src/generated/nested/code.ts", "vendor/pkg/lib.ts", "app.test.ts"} {
		if !compmap.MatchAnyGlob(migration.Boundaries.IgnorePaths, rel) {
			t.Errorf("migrated exclusions do not exclude %s", rel)
		}
	}
	if compmap.MatchAnyGlob(migration.Boundaries.IgnorePaths, "src/generated-other/code.ts") {
		t.Fatal("migrated directory ignore leaked into neighboring directory")
	}
	config := &config.Config{Components: migration.Components, Boundaries: migration.Boundaries}
	cm, err := compmap.Build(dir, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cm.Components) != 4 {
		t.Fatalf("legacy allowlist bypassed during discovery: %+v", cm.Components)
	}
	report, err := Analyze(dir, cm, config.Boundaries)
	if err != nil || len(report.Violations) != 2 {
		t.Fatalf("deep imports not rejected in native graph: %v, %+v", err, report)
	}
	for _, violation := range report.Violations {
		if violation.Kind != "private-import" || !strings.Contains(violation.TargetFile, "/private.") {
			t.Errorf("unexpected migration violation: %+v", violation)
		}
	}
}

func TestMigrationMapsLegacyEnforcementModes(t *testing.T) {
	for name, tc := range map[string]struct{ root, mode string }{
		"no-root":     {"", "warn"},
		"unspecified": {"version: '1'", "warn"},
		"off":         {"enforce: off", "warn"},
		"warn":        {"enforce: warn", "warn"},
		"on":          {"enforce: on", "enforce"},
		"true":        {"enforce: true", "enforce"},
		"enforce":     {"enforce: enforce", "enforce"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, ".bounds/manifests/app.yaml"), "name: app\npaths: [src/app]\n")
			if tc.root != "" {
				mustWrite(t, filepath.Join(dir, ".bounds/root.yaml"), tc.root)
			}
			got, err := MigrateFromBounds(dir)
			if err != nil || !got.Boundaries.IsEnabled() || got.Boundaries.EffectiveMode() != tc.mode {
				t.Fatalf("migration for %q: %+v, %v", tc.root, got, err)
			}
		})
	}
}

func TestBoundedReaderRejectsSymlinksEscapesAndOversizedManifests(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "source.ts"), "import './untrusted';")
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := compmap.ReadBoundedRegularFile(dir, filepath.Join(dir, "escape/source.ts"), maxSourceFileBytes); err == nil || !strings.Contains(err.Error(), "outside repository") {
		t.Fatalf("file via escaped parent symlink: %v", err)
	}
	if err := os.Symlink("escape/source.ts", filepath.Join(dir, "link.ts")); err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(dir, &compmap.Map{}, nil)
	if err != nil || len(report.ScanErrors) != 1 || !strings.Contains(report.ScanErrors[0], "not a regular file") || report.FilesScanned != 0 {
		t.Fatalf("symlink source indexed: %v, %+v", err, report)
	}
	for _, file := range []string{"go.mod", "Cargo.toml", "tsconfig.json"} {
		mustWrite(t, filepath.Join(dir, file), strings.Repeat(" ", maxSourceFileBytes+1))
	}
	report, err = Analyze(dir, &compmap.Map{}, &config.BoundariesConfig{Enabled: config.BoolPtr(true)})
	if err != nil || len(report.ScanErrors) != 4 || len(report.Violations) != 4 {
		t.Fatalf("oversized architecture manifests bypassed bounded read: %v, %+v", err, report)
	}
	mustWrite(t, filepath.Join(dir, ".bounds/manifests/valid.yaml"), "name: valid\npaths: [src]\n")
	mustWrite(t, filepath.Join(dir, ".bounds/manifests/huge.yaml"), strings.Repeat(" ", compmap.MaxStaticDiscoveryBytes+1))
	migration, err := MigrateFromBounds(dir)
	if err != nil || migration.Subsystems != 1 || len(migration.Warnings) != 1 || !strings.Contains(migration.Warnings[0], "exceeds") {
		t.Fatalf("oversized legacy manifest: %v, %+v", err, migration)
	}
	mustWrite(t, filepath.Join(dir, ".bounds/ignore"), strings.Repeat(" ", maxSourceFileBytes+1))
	if _, err := MigrateFromBounds(dir); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized legacy ignore: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, ".bounds/manifests/valid.yaml"), filepath.Join(dir, ".bounds/root.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateFromBounds(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink legacy root: %v", err)
	}
}

func TestBoundsMigrationFollowsOnlySameRepoFileSymlinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	writeFiles(t, dir, map[string]string{
		".bounds/root.yaml": "enforce: 'on'\n",
		"legacy/ignore":     "src/generated/\n",
		"legacy/api.yaml":   "name: api\npaths: [src/api]\n",
	})
	mustWrite(t, filepath.Join(outside, "outside.yaml"), "name: escaped\npaths: [src/escaped]\n")
	if err := os.MkdirAll(filepath.Join(dir, ".bounds/manifests"), 0o755); err != nil {
		t.Fatal(err)
	}
	ignore := filepath.Join(dir, ".bounds/ignore")
	if err := os.Symlink("../legacy/ignore", ignore); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "legacy/api.yaml"), filepath.Join(dir, ".bounds/manifests/api.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "outside.yaml"), filepath.Join(dir, ".bounds/manifests/outside.yaml")); err != nil {
		t.Fatal(err)
	}
	migration, err := MigrateFromBounds(dir)
	if err != nil || migration.Subsystems != 1 || migration.Components[0].ID != "api" ||
		!slices.Equal(migration.Boundaries.IgnorePaths, []string{"src/generated/**"}) ||
		len(migration.Warnings) != 1 || !strings.Contains(migration.Warnings[0], "outside repository") {
		t.Fatalf("unexpected migration: %+v, %v", migration, err)
	}
	for _, target := range []string{filepath.Join(outside, "outside.yaml"), filepath.Join(outside, "missing")} {
		if err := os.Remove(ignore); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, ignore); err != nil {
			t.Fatal(err)
		}
		if _, err := MigrateFromBounds(dir); err == nil {
			t.Fatalf("accepted escaping ignore %q", target)
		}
	}
}
