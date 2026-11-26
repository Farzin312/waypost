package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/history"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/spec"
)

func changedState(t *testing.T, dir, base string) ContextChanged {
	t.Helper()
	var out ContextChanged
	raw := command(t, 0, "context", "--dir", dir, "--changed", "--base", base, "--recent", "0", "--format", "json")
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWorkStateUsesPrefixIndexBaseAndPlan(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	for _, project := range []string{"alpha", "beta"} {
		root := filepath.Join(dir, project)
		mustWriteFile(t, filepath.Join(root, ".waypost.yaml"), `schema_version: '1'
components: [{id: app, root: app}]
rules:
  - {id: proof, kind: invariant, summary: proof, verified_by: {tests: [app/proof_test.go]}}
checks: [{id: ok, command: echo ok, paths: [app/**]}]
`)
		mustWriteFile(t, filepath.Join(root, "app/proof_test.go"), "package app\n")
		mustWriteFile(t, filepath.Join(root, "app/code.go"), "package app\n")
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "projects")
	mustGit(t, dir, "commit", "--allow-empty", "-m", "alternate base")
	for _, project := range []string{"alpha", "beta"} {
		mustWriteFile(t, filepath.Join(dir, project, "app/code.go"), "package app\n// changed\n")
	}
	alpha, beta := filepath.Join(dir, "alpha"), filepath.Join(dir, "beta")
	command(t, 0, "verify", "--dir", alpha, "--base", "HEAD")
	if state := changedState(t, beta, "HEAD").WorkState; state == nil || state.Verification != "none" {
		t.Fatalf("cross-project state: %+v", state)
	}
	command(t, 0, "verify", "--dir", beta, "--base", "HEAD")
	if state := changedState(t, alpha, "HEAD").WorkState; state == nil || state.Verification != "fresh" {
		t.Fatalf("missing fresh alpha state: %+v", state)
	}
	if state := changedState(t, alpha, "HEAD^").WorkState; state == nil || state.Verification != "stale" {
		t.Fatalf("changed base remained fresh: %+v", state)
	}
	mustGit(t, dir, "rm", "--cached", "alpha/app/proof_test.go")
	if state := changedState(t, alpha, "HEAD").WorkState; state == nil || state.Verification != "stale" {
		t.Fatalf("index removal remained fresh: %+v", state)
	}
	command(t, 1, "verify", "--dir", alpha, "--base", "HEAD")
}

func TestSubmoduleReadsDisableFiltersAndTrackDirt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix clean filter")
	}
	origin, dir := t.TempDir(), t.TempDir()
	mustGit(t, origin, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(origin, ".gitattributes"), "*.txt filter=fixture\n")
	mustWriteFile(t, filepath.Join(origin, "asset.txt"), "clean\n")
	mustGit(t, origin, "add", ".")
	mustGit(t, origin, "commit", "-m", "asset")
	mustGit(t, dir, "init", "-b", "main")
	mustGit(t, dir, "-c", "protocol.file.allow=always", "submodule", "add", origin, "dependency")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "schema_version: '1'\nchecks: [{id: ok, command: echo ok}]\n")
	mustWriteFile(t, filepath.Join(dir, "app.go"), "package app\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "policy and submodule")
	mustWriteFile(t, filepath.Join(dir, "app.go"), "package app\n// edit\n")
	marker := filepath.Join(t.TempDir(), "filter-ran")
	sub := filepath.Join(dir, "dependency")
	mustGit(t, sub, "config", "filter.fixture.clean", "touch '"+marker+"'; cat")
	command(t, 0, "verify", "--dir", dir, "--base", "HEAD")
	if state := changedState(t, dir, "HEAD").WorkState; state == nil || state.Verification != "fresh" {
		t.Fatalf("gitlink fingerprint: %+v", state)
	}
	mustWriteFile(t, filepath.Join(sub, "asset.txt"), "changed submodule worktree\n")
	if state := changedState(t, dir, "HEAD").WorkState; state == nil || state.Verification != "stale" {
		t.Fatalf("dirty gitlink fingerprint: %+v", state)
	}
	command(t, 0, "verify", "--dir", dir, "--base", "HEAD")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("clean filter ran: %v", err)
	}
}

func TestHistoricalPolicyStaysInTheSelectedTree(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "empty policy")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "schema_version: '1'\nextends: builtin:base@latest\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "floating without lock")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "schema_version: '1'\nextends: builtin:base@1.0.0\n")
	command(t, 0, "upgrade", "--dir", dir, "--apply")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "pinned")
	command(t, 1, "spec", "--dir", dir, "--ref", "HEAD~2")
	command(t, 1, "spec", "--dir", dir, "--ref", "HEAD^")
	raw := command(t, 0, "history", "--dir", dir, "--format", "json")
	var report history.Result
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Complete || !bytes.Contains(raw, []byte("requires an exact lock anchor")) || !bytes.Contains(raw, []byte("EOF")) {
		t.Fatalf("lost historical diagnostics: %s", raw)
	}
}

func TestUntestedComponentsCreditsOnlySurvivingTests(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "schema_version: '1'\ncomponents: [{id: app, root: .}]\n")
	for _, file := range []string{"src/main.cts", "src/proof.test.mts", "vite.config.ts", "next.config.mjs", "eslint.config.js", "tailwind.config.ts", "docs/conf.py"} {
		mustWriteFile(t, filepath.Join(dir, file), "// original\n")
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "base")
	for _, file := range []string{"vite.config.ts", "next.config.mjs", "eslint.config.js", "tailwind.config.ts", "docs/conf.py"} {
		mustWriteFile(t, filepath.Join(dir, file), "// config or docs edit\n")
	}
	if state := changedState(t, dir, "HEAD").WorkState; state == nil || len(state.UntestedComponents) > 0 {
		t.Fatalf("production false positive: %+v", state)
	}
	mustWriteFile(t, filepath.Join(dir, "src/main.cts"), "export const changed = 1;")
	mustGit(t, dir, "mv", "src/proof.test.mts", "docs/old-proof.mts")
	if state := changedState(t, dir, "HEAD").WorkState; state == nil || !slices.Equal(state.UntestedComponents, []string{"app"}) {
		t.Fatalf("old-side test was credited: %+v", state)
	}
	mustWriteFile(t, filepath.Join(dir, "src/current.test.mts"), "export {};")
	if state := changedState(t, dir, "HEAD").WorkState; state == nil || len(state.UntestedComponents) != 0 {
		t.Fatalf("new test was not credited: %+v", state)
	}
}

func TestHistoryBoundsAndProjectsComparisonSamples(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), `schema_version: '1'
components: [{id: app, root: app}, {id: lib, root: lib}]
boundaries: {enabled: true, mode: ratchet, enforce_declared_deps: true}
`)
	mustWriteFile(t, filepath.Join(dir, "lib/api.ts"), "export {};")
	for n := range 75 {
		mustWriteFile(t, filepath.Join(dir, fmt.Sprintf("app/file-%02d.ts", n)), "export {};")
	}
	command(t, 0, "graph", "--dir", dir, "--update-baseline")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "base")
	for n := range 75 {
		mustWriteFile(t, filepath.Join(dir, fmt.Sprintf("app/file-%02d.ts", n)), "import '../lib/api';")
	}
	mustWriteFile(t, filepath.Join(dir, "lib/unrelated.ts"), "export {};")
	command(t, 0, "graph", "--dir", dir, "--update-baseline")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "large change")
	raw := command(t, 0, "history", "--dir", dir, "--limit", "1", "--component", "app", "--format", "json")
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	schema := loadJSONSchema(t, filepath.Join("..", "..", "schemas", "history.v1.schema.json"))
	if problems := validateAgainstSchema(schema, document, "$"); len(problems) > 0 {
		t.Fatalf("history schema: %v", problems)
	}
	var report history.Result
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	c := report.Events[0].Comparisons[0]
	if bytes.Contains(raw, []byte("unrelated.ts")) || bytes.Count(raw, []byte("\n")) != 1 ||
		len(c.Changes) != 50 || c.OmittedChanges != 25 || c.ComponentCounts["app"] != 75 ||
		len(c.Baseline) != 12 || c.BaselineCount != 75 || c.OmittedBaseline != 63 {
		t.Fatalf("unbounded or unrelated history: %+v", c)
	}
}

func TestSpecInheritsManifestEntrypointAndRejectsUnexpectedArguments(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "package.json"), `{"name":"app","main":"index.js"}`)
	mustWriteFile(t, filepath.Join(dir, "index.js"), "module.exports = {};")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "schema_version: '1'\ncomponents: [{id: app, root: .}]\n")
	var report spec.Report
	raw := command(t, 0, "spec", "--dir", dir, "--component", "app", "--format", "json")
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Components) != 1 || !slices.Contains(report.Components[0].Entrypoints, spec.Fact{Value: "index.js", Source: "manifest"}) {
		t.Fatalf("manifest entrypoint lost: %+v", report.Components)
	}
	for _, args := range [][]string{{"spec", "--limit", "0"}, {"spec", "--since", "2026-01-01"}, {"spec", "--history", "--limit", "0"}, {"spec", "--dir", dir, "--component", "unknown"}} {
		command(t, 1, args...)
	}
	for _, sub := range []string{"verify", "sync"} {
		command(t, 2, sub, "unexpected", "--dir", dir)
	}
	for _, sub := range []string{"init", "context", "spec", "history", "pins", "graph", "sync", "verify", "upgrade", "version"} {
		if raw := command(t, 0, sub, "-h"); !bytes.Contains(raw, []byte("Usage of waypost "+sub)) {
			t.Fatalf("missing help for %s: %s", sub, raw)
		}
	}
}

func TestDefaultContextSanitizesRepoDerivedText(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), `schema_version: '1'
name: "demo\x1b[31m\n## Forged"
components: [{id: app, root: ., kind: "<img>"}]
rules: [{id: proof, kind: invariant, summary: "One\nTwo"}]
checks: [{id: ok, command: "echo first\nsecond"}]
`)
	raw := command(t, 0, "context", "--dir", dir)
	if bytes.Contains(raw, []byte("\x1b")) || bytes.Contains(raw, []byte("\n## Forged")) ||
		bytes.Contains(raw, []byte("<img>")) || !bytes.Contains(raw, []byte(`One\\nTwo`)) {
		t.Fatalf("unsafe terminal text: %s", raw)
	}
}

func TestInitStaticMixedLanguageChecksAndBoundaries(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	for file, body := range map[string]string{
		"package.json":          `{"name":"project","scripts":{"type-check":"touch should-not-run","check-types":"false","test":"touch should-not-run","lint":"false"}}`,
		"go/go.mod":             "module example.test/lib\n\ngo 1.26.3\n",
		"go/lib.go":             "package lib\n",
		"rust/Cargo.toml":       "[package]\nname = 'fixture'\nversion = '0.1.0'\n",
		"rust/src/lib.rs":       "pub fn sample() {}",
		"pyproject.toml":        "[tool.pytest.ini_options]\n[tool.ruff.lint]\n",
		"tests/test_fixture.py": "def test_example():\n    assert True\n",
		"index.mts":             "export {};",
	} {
		mustWriteFile(t, filepath.Join(dir, file), body)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "third-party project")
	command(t, 0, "init", "--dir", dir, "--ci")
	command(t, 0, "sync", "--dir", dir, "--check", "--offline")
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	assertStarterChecks(t, res.Effective.Checks, map[string]string{
		"ts-typecheck": "npm run type-check", "ts-test": "npm test", "lint": "npm run lint",
		"go-vet": "go vet ./...", "go-test": "go test ./...", "cargo-test": "cargo test",
		"python-test": "pytest", "ruff": "ruff check .",
	})
	if res.Effective.Boundaries.EffectiveMode() != "enforce" || !lockfile.Verify(dir, res).Valid {
		t.Fatalf("inferred policy not enforced or locked: %+v", res.Effective.Boundaries)
	}
	if _, err := os.Stat(filepath.Join(dir, "should-not-run")); !os.IsNotExist(err) {
		t.Fatalf("init executed a starter check: %v", err)
	}
	workflow, err := os.ReadFile(filepath.Join(dir, starterWorkflowPath))
	if err != nil || !bytes.Contains(workflow, []byte("github.com/Farzin312/waypost/cmd/waypost@v0.3.0")) ||
		!bytes.Contains(workflow, []byte("contents: read")) || !bytes.Contains(workflow, []byte("fetch-depth: 0")) {
		t.Fatalf("workflow: %s %v", workflow, err)
	}
	mustWriteFile(t, filepath.Join(dir, starterWorkflowPath), "existing workflow\n")
	command(t, 0, "init", "--dir", dir, "--force", "--ci")
	got, err := os.ReadFile(filepath.Join(dir, starterWorkflowPath))
	if err != nil || !bytes.Equal(workflow, got) {
		t.Fatalf("force did not restore generated workflow: %s %v", got, err)
	}
}

func TestInitSeedsRatchetAndPreservesExistingWorkflow(t *testing.T) {
	dir := t.TempDir()
	for file, body := range map[string]string{
		"app/package.json": `{"name":"app"}`, "lib/package.json": `{"name":"lib"}`,
		"app/main.ts": "import '../lib/api';", "lib/api.ts": "export {};",
		"tests/test_fixture.py": "import unittest\n",
		starterWorkflowPath:     "existing workflow\n",
	} {
		mustWriteFile(t, filepath.Join(dir, file), body)
	}
	command(t, 0, "init", "--dir", dir, "--ci")
	command(t, 0, "sync", "--dir", dir, "--check", "--offline")
	raw := command(t, 0, "graph", "--dir", dir, "--check-boundaries", "--format", "json")
	if !bytes.Contains(raw, []byte(`"grandfathered_count": 1`)) {
		t.Fatalf("missing grandfathered import: %s", raw)
	}
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	assertStarterChecks(t, res.Effective.Checks, map[string]string{"python-test": "python3 -m unittest discover -s tests"})
	if res.Effective.Boundaries.EffectiveMode() != "ratchet" || !slices.Contains(res.Effective.Policy.TrustPaths, config.DefaultBaselinePath) ||
		!lockfile.Verify(dir, res).Valid {
		t.Fatalf("ratchet setup: %+v", res.Effective)
	}
	if got, err := os.ReadFile(filepath.Join(dir, starterWorkflowPath)); err != nil || string(got) != "existing workflow\n" {
		t.Fatalf("existing workflow was replaced: %q %v", got, err)
	}
}

func assertStarterChecks(t *testing.T, checks []config.Check, wants map[string]string) {
	t.Helper()
	for id, command := range wants {
		i := slices.IndexFunc(checks, func(c config.Check) bool { return c.ID == id })
		if i < 0 || checks[i].Command != command {
			t.Fatalf("wanted %s %s in %+v", id, command, checks)
		}
		if (id == "ruff" || id == "lint") == checks[i].IsRequired() || strings.TrimSpace(checks[i].RequiresBin) == "" {
			t.Fatalf("starter check metadata: %+v", checks[i])
		}
	}
}

func TestSyncCommittedViewExcludesGeneratedAndLiveManifests(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, ".gitignore"), "generated/\n")
	mustWriteFile(t, filepath.Join(dir, ".waypost.yaml"), "schema_version: '1'\ncomponents: [{id: app, root: app}]\n")
	mustWriteFile(t, filepath.Join(dir, "app/code.ts"), "export {};")
	mustWriteFile(t, filepath.Join(dir, "package.json"), "{}")
	command(t, 0, "upgrade", "--dir", dir, "--apply")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "policy")
	mustWriteFile(t, filepath.Join(dir, "generated/output.ts"), "export {};")
	mustWriteFile(t, filepath.Join(dir, "package.json"), "{")
	command(t, 0, "sync", "--dir", dir, "--check", "--offline", "--ref", "HEAD")
	command(t, 1, "sync", "--dir", dir, "--check", "--offline")
	command(t, 2, "sync", "--dir", dir, "--apply", "--ref", "HEAD")
}
