package syncer

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestSyncAppliesSafeDriftAndPreservesYAML(t *testing.T) {
	dir := t.TempDir()
	configRaw := `# repo comments survive sync
schema_version: "1"
name: delivery
boundaries:
  ignore_paths: [ignored/**]
components:
  # keep this comment
  - id: api
    root: src/api
    paths: [src/api/**]
  - id: deleted
    root: deleted
  - id: referenced
    root: old/client
  - id: metadata
    root: .
    paths: [package.json]
pins:
  - {id: app-contract, producer: org/app, artifact: "@org/api", consumer: api, version: "1.0.0"} # pinned package
  - id: api-spec
    producer: org/api
    artifact: contracts/openapi.json
    consumer: api
    version: "1.0.0" # pinned spec
  - {id: range, producer: org/app, artifact: ranged, consumer: api, version: "1.0.0"}
  - {id: exact, producer: org/app, artifact: exact, consumer: api, version: "1.0.0"}
checks:
  - id: package-check
    workdir: src/api
    command: 'echo "npm run false-positive" && npm run good && pnpm run gone'
    components: [referenced]
  - id: check-root
    command: "yarn lint"
`
	syncWrite(t, dir, config.ConfigFileName, configRaw)
	syncWrite(t, dir, "src/api/index.ts", "export const api = 1;")
	syncWrite(t, dir, "src/client/index.mts", "import '../api/index';")
	syncWrite(t, dir, "src/watch/index.py", "pass")
	syncWrite(t, dir, "ignored/do-not-add.ts", "")
	syncWrite(t, dir, "node_modules/pkg/dep.js", "")
	syncWrite(t, dir, "assets/empty.txt", "")
	syncWrite(t, dir, "package.json", `{
		"scripts": {"lint":"never executed","typecheck":"tsc"},
		"dependencies": {"@org/api":"file:./vendor/org-api-2.4.0-rc.1.tgz","ranged":"^2.0.0"},
		"devDependencies": {"exact":"3.1.2"}
	}`)
	syncWrite(t, dir, "contracts/package.json", `{"name":"@org/contracts","version":"4.3.0"}`)
	syncWrite(t, dir, "src/api/package.json", `{"scripts":{"good":"touch should-not-exist"}}`)
	if err := os.Symlink("../api/index.ts", filepath.Join(dir, "assets/link.ts")); err != nil {
		t.Logf("symlink unavailable: %v", err)
	}

	dry, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for kind, subjects := range map[string][]string{
		"unmapped_dir": {"src/client", "src/watch"}, "stale_component": {"deleted", "referenced"},
		"missing_script": {"package-check"}, "unwired_script": {"typecheck"},
		"pin_drift": {"api-spec", "app-contract", "exact"}, "lock_stale": {lockfile.LockFileName},
	} {
		if got := subjectsOf(dry, kind); !slices.Equal(got, subjects) {
			t.Errorf("%s = %v, want %v (all items: %+v)", kind, got, subjects, dry.Items)
		}
	}
	if string(syncRead(t, dir, config.ConfigFileName)) != configRaw {
		t.Fatal("dry-run changed YAML")
	}
	if _, err := os.Stat(filepath.Join(dir, lockfile.LockFileName)); !os.IsNotExist(err) {
		t.Fatalf("dry-run created lock: %v", err)
	}

	applied, err := Run(dir, Options{Apply: true})
	if err != nil || !applied.Pending() || !applied.LockRefreshed {
		t.Fatalf("expected safe updates with pending manual fixes: %+v, %v", applied, err)
	}
	raw := string(syncRead(t, dir, config.ConfigFileName))
	for _, kept := range []string{"# repo comments survive sync", "# keep this comment", "# pinned package", "# pinned spec",
		"paths: [src/api/**]", "command: 'echo", "version: \"2.4.0-rc.1\"", "version: \"4.3.0\"", "version: \"3.1.2\"",
		"id: referenced"} {
		if !strings.Contains(raw, kept) {
			t.Errorf("updated YAML is missing %q:\n%s", kept, raw)
		}
	}
	res := syncConfig(t, dir)
	for _, c := range res.Effective.Components {
		switch c.ID {
		case "client":
			if c.Root != "src/client" || c.Language != "typescript" || !slices.Equal(c.DependsOn, []string{"api"}) {
				t.Errorf("wrong inferred component: %+v", c)
			}
		case "watch":
			if c.Language != "python" || len(c.DependsOn) != 0 {
				t.Errorf("wrong Python component: %+v", c)
			}
		case "deleted", "assets":
			t.Errorf("unexpected component: %+v", c)
		}
	}
	if lock := lockfile.Verify(dir, res); !lock.Valid {
		t.Fatalf("sync published invalid lock: %+v", lock)
	}
	if _, err := os.Stat(filepath.Join(dir, "src/api/should-not-exist")); !os.IsNotExist(err) {
		t.Fatalf("sync executed the repository check: %v", err)
	}

	second, err := Run(dir, Options{Apply: true})
	if err != nil || !second.Pending() || second.LockRefreshed ||
		len(subjectsOf(second, "unmapped_dir"))+len(subjectsOf(second, "pin_drift"))+len(subjectsOf(second, "lock_stale")) != 0 ||
		!bytes.Equal([]byte(raw), syncRead(t, dir, config.ConfigFileName)) {
		t.Fatalf("repeat sync was not idempotent: %+v, %v", second, err)
	}
}

func TestSyncSkipsCatchAllAndAvoidsCyclicDeclaredEdges(t *testing.T) {
	t.Run("catch-all", func(t *testing.T) {
		dir := t.TempDir()
		syncWrite(t, dir, config.ConfigFileName, "schema_version: '1'\ncomponents: [{id: app, root: ., paths: ['**']}]\n")
		syncWrite(t, dir, "elsewhere/index.cjs", "")
		report, err := Run(dir, Options{Apply: true})
		if err != nil || report.Pending() || len(subjectsOf(report, "unmapped_dir")) != 0 {
			t.Fatalf("catch-all generated drift: %+v, %v", report, err)
		}
	})
	t.Run("cycle", func(t *testing.T) {
		dir := t.TempDir()
		syncWrite(t, dir, config.ConfigFileName, "schema_version: '1'\ncomponents: [{id: api, root: src/api}]\n")
		syncWrite(t, dir, "src/api/index.ts", "import '../next/index';")
		syncWrite(t, dir, "src/next/index.ts", "import '../api/index';")
		report, err := Run(dir, Options{Apply: true})
		if err != nil || report.Pending() {
			t.Fatalf("apply: %+v, %v", report, err)
		}
		res := syncConfig(t, dir)
		if c := res.Effective.Components[1]; c.ID != "next" || len(c.DependsOn) > 0 {
			t.Fatalf("declared dependency creates a cycle: %+v", c)
		}
	})
}

func TestSyncRecognizesInferredAndBoundsOwnership(t *testing.T) {
	dir := t.TempDir()
	const raw = "schema_version: '1'\ncomponents: [{id: api, root: api}]\n"
	syncWrite(t, dir, config.ConfigFileName, raw)
	syncWrite(t, dir, "api/index.ts", "")
	syncWrite(t, dir, "packages/ui/package.json", `{"name":"@org/ui"}`)
	syncWrite(t, dir, "packages/ui/src/index.ts", "")
	syncWrite(t, dir, ".bounds/manifests/runtime.yaml", "subsystem: runtime\npaths: [legacy/runtime/**]\n")
	syncWrite(t, dir, "legacy/runtime/lib/index.ts", "")
	for _, apply := range []bool{true, false} {
		report, err := Run(dir, Options{Apply: apply})
		if err != nil || report.Pending() || len(subjectsOf(report, "unmapped_dir")) != 0 {
			t.Fatalf("sync apply=%t did not respect inferred ownership: %+v, %v", apply, report, err)
		}
	}
	if got := string(syncRead(t, dir, config.ConfigFileName)); got != raw {
		t.Fatalf("sync added a redundant component:\n%s", got)
	}
}

func TestSyncShrinksBaselineOccurrenceCount(t *testing.T) {
	dir := t.TempDir()
	syncWrite(t, dir, config.ConfigFileName, `schema_version: '1'
boundaries: {enabled: true, mode: ratchet, enforce_declared_deps: true}
components: [{id: app, root: app}, {id: api, root: api}]
`)
	const importAPI = "import '../api/index';\n"
	syncWrite(t, dir, "api/index.ts", "export const api = 1;")
	syncWrite(t, dir, "app/index.ts", strings.Repeat(importAPI, 3))
	res := syncConfig(t, dir)
	live, err := archgraph.AnalyzeLive(dir, &compmap.Map{Components: []compmap.Component{
		{ID: "app", Root: "app", Paths: []string{"app/**"}},
		{ID: "api", Root: "api", Paths: []string{"api/**"}},
	}}, res.Effective.Boundaries, archgraph.AnalyzeOptions{})
	if err != nil || len(live.Violations) != 3 {
		t.Fatalf("analyze: %+v, %v", live, err)
	}
	rel := config.DefaultBaselinePath
	if err := archgraph.SaveBaseline(dir, rel, live.Violations); err != nil {
		t.Fatal(err)
	}
	if got := string(syncRead(t, dir, rel)); !strings.Contains(got, `"count": 3`) {
		t.Fatalf("baseline did not record three occurrences: %s", got)
	}
	syncWrite(t, dir, "app/index.ts", strings.Repeat(importAPI, 2))
	report, err := Run(dir, Options{Apply: true})
	if err != nil || report.Pending() || len(subjectsOf(report, "baseline_shrink")) != 1 {
		t.Fatalf("shrink count: %+v, %v", report, err)
	}
	if got := string(syncRead(t, dir, rel)); !strings.Contains(got, `"count": 2`) {
		t.Fatalf("sync did not shrink the count to two: %s", got)
	}
}

func TestSyncRejectsOversizedRootConfig(t *testing.T) {
	dir := t.TempDir()
	syncWrite(t, dir, config.ConfigFileName, "schema_version: '1'\n# "+strings.Repeat("x", compmap.MaxStaticDiscoveryBytes))
	if _, err := Run(dir, Options{Apply: true}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("sync accepted an oversized root config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, lockfile.LockFileName)); !os.IsNotExist(err) {
		t.Fatalf("sync wrote a lock after reading an oversized config: %v", err)
	}
}

func TestSyncRatchetNeverExpandsAndSafelyGraduates(t *testing.T) {
	dir := t.TempDir()
	const rel = "policies/ratchet.json"
	syncWrite(t, dir, config.ConfigFileName, `# keep ratchet comments
schema_version: '1'
boundaries:
  enabled: true
  mode: ratchet # shrink when debt is resolved
  baseline: policies/ratchet.json
  enforce_declared_deps: true
components:
  - {id: app, root: app}
  - {id: api, root: api}
`)
	syncWrite(t, dir, "api/index.ts", "export const api = 1;")
	importAPI := "import '../api/index';"
	syncWrite(t, dir, "app/a.ts", importAPI)
	syncWrite(t, dir, "app/b.ts", importAPI)
	res := syncConfig(t, dir)
	live, err := analyze(dir, &res.Effective)
	if err != nil || len(live.ScanErrors) != 1 || len(live.Violations) != 3 {
		t.Fatalf("missing baseline did not fail closed: %+v, %v", live, err)
	}
	if err := archgraph.SaveBaseline(dir, rel, live.Violations[:2]); err != nil {
		t.Fatal(err)
	}
	before := syncRead(t, dir, rel)
	syncWrite(t, dir, "app/a.ts", "export const a = 1;")
	syncWrite(t, dir, "app/new.ts", importAPI)
	blocked, err := Run(dir, Options{Apply: true})
	if err != nil || blocked.Pending() || len(subjectsOf(blocked, "baseline_shrink")) != 0 ||
		!bytes.Equal(before, syncRead(t, dir, rel)) {
		t.Fatalf("sync changed the baseline with a new violation: %+v, %v", blocked, err)
	}
	if err := os.Remove(filepath.Join(dir, "app/new.ts")); err != nil {
		t.Fatal(err)
	}
	shrunk, err := Run(dir, Options{Apply: true})
	if err != nil || shrunk.Pending() || len(subjectsOf(shrunk, "baseline_shrink")) != 1 {
		t.Fatalf("shrink: %+v, %v", shrunk, err)
	}
	baseline, err := archgraph.LoadBaseline(dir, rel)
	if err != nil || len(baseline.Entries) != 1 || baseline.Entries[0].Source != "app/b.ts" {
		t.Fatalf("wrong baseline after shrink: %+v, %v", baseline, err)
	}
	syncWrite(t, dir, "app/b.ts", "export const b = 2;")
	graduate, err := Run(dir, Options{Apply: true})
	if err != nil || graduate.Pending() || !graduate.LockRefreshed || len(subjectsOf(graduate, "baseline_graduate")) != 1 {
		t.Fatalf("graduate: %+v, %v", graduate, err)
	}
	if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
		t.Fatalf("graduation left the baseline in place: %v", err)
	}
	if !strings.Contains(string(syncRead(t, dir, config.ConfigFileName)), "mode: enforce # shrink when debt is resolved") {
		t.Fatal("graduation did not preserve the comment or enforce the mode")
	}
	final := syncConfig(t, dir)
	if final.Effective.Boundaries.EffectiveMode() != "enforce" || !lockfile.Verify(dir, final).Valid {
		t.Fatal("graduation did not preserve frozen verification")
	}
}

func TestSyncDoesNotGraduateWhenNewOwnershipExposesViolation(t *testing.T) {
	dir := t.TempDir()
	syncWrite(t, dir, config.ConfigFileName, `schema_version: '1'
boundaries: {enabled: true, mode: ratchet, enforce_declared_deps: true}
components: [{id: app, root: app}]
`)
	syncWrite(t, dir, "app/index.ts", "import '../new/index';")
	syncWrite(t, dir, "new/index.ts", "export const x = 1;")
	if err := archgraph.SaveBaseline(dir, config.DefaultBaselinePath, nil); err != nil {
		t.Fatal(err)
	}
	got, err := Run(dir, Options{Apply: true})
	if err != nil || !got.Pending() || len(subjectsOf(got, "unmapped_dir")) != 1 ||
		syncConfig(t, dir).Effective.Boundaries.EffectiveMode() != "ratchet" {
		t.Fatalf("sync graduated into a new violation: %+v, %v", got, err)
	}
	if baseline, err := archgraph.LoadBaseline(dir, config.DefaultBaselinePath); err != nil || len(baseline.Entries) != 0 {
		t.Fatalf("sync expanded/deleted baseline: %+v, %v", baseline, err)
	}
}

func TestManifestParsingDoesNotGuessRangesOrShellData(t *testing.T) {
	for spec, want := range map[string]string{
		"1.2.3": "1.2.3", "2.5.0-rc.1+build.4": "2.5.0-rc.1+build.4",
		"file:./vendor/internal-lib-1.2.3-rc.4.5.6.tgz": "1.2.3-rc.4.5.6",
		"^1.2.3": "", "file:../vendor/lib-1.2.3.tgz": "", "1.2": "", "01.2.3": "", "workspace:*": "",
	} {
		if got := dependencyVersion(spec); got != want {
			t.Errorf("%q parsed as %q, want %q", spec, got, want)
		}
	}
	command := `echo "&& yarn do-not-count" && APP="hello world" npm run "typecheck"; pnpm run test:unit | yarn docs:check
yarn install # && npm run not-actual
npm test && yarn run lint`
	want := []string{"typecheck", "test:unit", "docs:check", "test", "lint"}
	if got := commandScripts(command); !slices.Equal(got, want) {
		t.Fatalf("script references = %v, want %v", got, want)
	}
}

func syncWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	file := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func syncRead(t *testing.T, dir, rel string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func syncConfig(t *testing.T, dir string) *config.ResolvedConfig {
	t.Helper()
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func subjectsOf(report Report, kind string) []string {
	var subjects []string
	for _, item := range report.Items {
		if item.Kind == kind {
			subjects = append(subjects, item.Subject)
		}
	}
	slices.Sort(subjects)
	return subjects
}

func TestSyncAvoidsReadingEscapingManifestsAndReplacingSymlinkLocks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	syncWrite(t, dir, config.ConfigFileName, "schema_version: '1'\ncomponents: [{id: app, root: app}]\n")
	syncWrite(t, dir, "app/index.ts", "")
	syncWrite(t, outside, "secret.json", `{"scripts":{"typecheck":"secret command"}}`)
	syncWrite(t, outside, "lock", "keep untouched")
	for link, target := range map[string]string{"package.json": "secret.json", lockfile.LockFileName: "lock"} {
		if err := os.Symlink(filepath.Join(outside, target), filepath.Join(dir, link)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	result, err := Run(dir, Options{Apply: true})
	if err != nil || !result.Pending() || result.LockRefreshed ||
		len(subjectsOf(result, "manifest_error")) != 1 || len(subjectsOf(result, "unwired_script")) != 0 {
		t.Fatalf("unexpected apply of unsafe paths: %+v, %v", result, err)
	}
	if got := string(syncRead(t, outside, "lock")); got != "keep untouched" {
		t.Fatalf("external lock was modified: %s", got)
	}
}
