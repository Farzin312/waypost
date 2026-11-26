package verify

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestCIBoundariesUseTrustedOwnershipDependenciesAndExclusions(t *testing.T) {
	const baseComponents = `
components:
  - id: client
    root: src/client
    paths: ["src/client/**"]
  - id: api
    root: src/api
`
	const denyRule = `
  rules:
    - id: client-no-api
      from: client
      deny_depends_on: [api]
`
	for _, tc := range []struct {
		name, basePolicy, headPolicy, headComponents, wantRule string
		wantTampering                                          bool
	}{
		{
			name: "component-paths-and-root", basePolicy: denyRule, headPolicy: denyRule,
			headComponents: strings.ReplaceAll(baseComponents, "src/client", "relocated"), wantRule: "client-no-api",
		},
		{
			name: "declared-dependencies", basePolicy: "\n  enforce_declared_deps: true\n",
			headPolicy: "\n  enforce_declared_deps: true\n", wantRule: "enforce-declared-deps",
			headComponents: strings.Replace(baseComponents, `    paths: ["src/client/**"]`, `    paths: ["src/client/**"]
    depends_on: [api]`, 1),
		},
		{
			name: "ignore-paths", basePolicy: denyRule,
			headPolicy:     denyRule + "\n  ignore_paths: [src/client/use.ts]\n",
			headComponents: baseComponents, wantRule: "client-no-api", wantTampering: true,
		},
		{
			name:           "strengthened-rule",
			basePolicy:     strings.Replace(denyRule, "[api]", "[client]", 1),
			headPolicy:     strings.Replace(denyRule, "[api]", "[client, api]", 1),
			headComponents: baseComponents, wantRule: "client-no-api",
		},
		{
			name: "new-rule-on-new-component", basePolicy: denyRule,
			headPolicy: denyRule + `    - id: new-component-no-api
      from: new-client
      deny_depends_on: [api]
`,
			headComponents: baseComponents + `  - id: new-client
    root: src/client/nested
`,
			wantRule: "new-component-no-api",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			const boundaryHeader = `schema_version: "1"
name: trusted-boundaries
boundaries:
  enabled: true
  mode: enforce
  no_cycles: false
`
			writeBoundaryFixture(t, dir, config.ConfigFileName,
				boundaryHeader+"  ignore_paths: [src/client/known.ts]\n"+tc.basePolicy+baseComponents)
			writeBoundaryFixture(t, dir, "src/client/known.ts", "import '../api/public';")
			writeBoundaryFixture(t, dir, "src/api/public.ts", "export const api = 1;")
			writeBoundaryFixture(t, dir, "src/client/use.ts", "export const app = 1;")
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "base")
			gitBoundaryFixture(t, dir, "checkout", "-b", "feature")

			gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "unchanged policy")
			opts := Options{Mode: "ci", Base: "main", Frozen: true, All: true}
			if rec, err := Run(dir, opts); err != nil || rec.Summary.Outcome != StatusPass {
				t.Fatalf("base fixture should pass: %+v, %v", rec, err)
			}

			headPolicy := boundaryHeader + "  ignore_paths: [src/client/known.ts]\n" + tc.headPolicy
			if tc.wantTampering {
				headPolicy = boundaryHeader + strings.Replace(tc.headPolicy, "[src/client/use.ts]", "[src/client/known.ts, src/client/use.ts]", 1)
			}
			writeBoundaryFixture(t, dir, config.ConfigFileName, headPolicy+tc.headComponents)
			if tc.name == "new-rule-on-new-component" {
				writeBoundaryFixture(t, dir, "src/client/nested/use.ts", "import '../../api/public';")
			} else {
				writeBoundaryFixture(t, dir, "src/client/use.ts", "import '../api/public';")
			}
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "head")

			rec, err := Run(dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Git.Dirty || len(rec.Policy.PreflightFailures) > 0 || !rec.Policy.PolicyFloorEnforced || !rec.Policy.LockValid {
				t.Fatalf("expected clean CI receipt with a trusted floor: %+v", rec)
			}
			got := onlyBoundaryCheck(t, rec)
			if got.Status != StatusFail || !got.Required || !got.FromBaseFloor ||
				!strings.Contains(got.OutputExcerpt, "["+tc.wantRule+"]") || strings.Contains(got.OutputExcerpt, "known.ts") {
				t.Fatalf("wrong boundary check: %+v", got)
			}
			if tc.name != "new-rule-on-new-component" && got.Reason != "1 boundary violation(s)" {
				t.Fatalf("boundary results were duplicated or a trusted ignore was dropped: %+v", got)
			}
			findings := strings.Join(rec.Policy.TamperingFindings, "\n")
			if strings.Contains(findings, "boundaries.ignore_paths") != tc.wantTampering {
				t.Fatalf("unexpected tampering findings: %s", findings)
			}
		})
	}
}

func TestCIBoundariesUseTrustedBaseManifestInference(t *testing.T) {
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: "1"
boundaries:
  enabled: true
  rules:
    - id: consumer-no-library
      from: consumer
      deny_depends_on: [library]
`)
	writeBoundaryFixture(t, dir, "consumer/package.json", `{"name":"consumer"}`)
	writeBoundaryFixture(t, dir, "library/package.json", `{"name":"library"}`)
	writeBoundaryFixture(t, dir, "library/public.ts", "export const x = 1;")
	writeBoundaryFixture(t, dir, "consumer/main.ts", "export const y = 1;")
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "base")
	gitBoundaryFixture(t, dir, "checkout", "-b", "feature")
	raw, err := os.ReadFile(filepath.Join(dir, config.ConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	writeBoundaryFixture(t, dir, config.ConfigFileName, strings.ReplaceAll(string(raw), "from: consumer", "from: renamed"))
	writeBoundaryLock(t, dir)
	writeBoundaryFixture(t, dir, "consumer/package.json", `{"name":"renamed"}`)
	writeBoundaryFixture(t, dir, "consumer/main.ts", "import '../library/public';")
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "rename owner and import library")

	rec, err := Run(dir, Options{Mode: "ci", Base: "main", Frozen: true, All: true})
	if err != nil {
		t.Fatal(err)
	}
	got := onlyBoundaryCheck(t, rec)
	if got.Status != StatusFail || !strings.Contains(got.OutputExcerpt, "[consumer-no-library]") {
		t.Fatalf("inferred base ownership was changed by a head manifest: %+v", got)
	}
}

func TestCIBoundariesExcludeIgnoredFilesAndLocalBoundariesIncludeNewFiles(t *testing.T) {
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: "1"
boundaries:
  enabled: true
  rules:
    - id: client-no-api
      from: client
      deny_depends_on: [api]
components:
  - id: client
    root: client
  - id: api
    root: api
`)
	writeBoundaryFixture(t, dir, ".gitignore", "api/ignored.ts\nclient/ignored.ts\nclient/tsconfig.json\nclient/nested/package.json\n")
	writeBoundaryFixture(t, dir, "client/nested/main.ts", "import '../../api/ignored'; import '@ignored-config';")
	writeBoundaryFixture(t, dir, "api/public.ts", "export const pub = 1;")
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "base")
	writeBoundaryFixture(t, dir, "client/tsconfig.json", `{"compilerOptions":{"paths":{"@ignored-config":["../api/public"]}}}`)
	writeBoundaryFixture(t, dir, "client/nested/package.json", `{"name":"ignored-ownership"}`)
	writeBoundaryFixture(t, dir, "client/ignored.ts", "import '../api/public';")
	writeBoundaryFixture(t, dir, "api/ignored.ts", "export const ignored = 1;")

	gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "check ignored inputs")
	rec, err := Run(dir, Options{Mode: "ci", Base: "HEAD^", Frozen: true, All: true})
	if err != nil {
		t.Fatal(err)
	}
	if g := onlyBoundaryCheck(t, rec); g.Status != StatusPass || rec.Git.Dirty {
		t.Fatalf("ignored files affected clean CI: %+v", rec)
	}
	writeBoundaryFixture(t, dir, "client/nested/new.ts", "import '../../api/public';")
	rec, err = Run(dir, Options{Mode: "local", Frozen: true, All: true})
	if err != nil {
		t.Fatal(err)
	}
	g := onlyBoundaryCheck(t, rec)
	if g.Status != StatusFail || g.Reason != "1 boundary violation(s)" || !strings.Contains(g.OutputExcerpt, "client/nested/new.ts") {
		t.Fatalf("local scan must see untracked non-ignored inputs: %+v", g)
	}
}

func TestBoundaryScanRunsBeforeProvidersAndChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX shell commands")
	}
	for _, kind := range []string{"shell-check", "provider"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cfg := `schema_version: "1"
boundaries:
  enabled: true
  enforce_declared_deps: true
components:
  - id: client
    root: client
  - id: api
    root: api
checks:
  - id: can-mutate
    command: "touch external-ran"
`
			if kind == "provider" {
				cfg += `
providers:
  - id: can-mutate
    tool: sh
    authorized: true
    command: "rm client/use.ts && echo '{}'"
`
			} else {
				cfg = strings.Replace(cfg, "touch external-ran", "rm client/use.ts && touch external-ran", 1)
			}
			writeBoundaryFixture(t, dir, config.ConfigFileName, cfg)
			writeBoundaryFixture(t, dir, "client/use.ts", "import '../api/public';")
			writeBoundaryFixture(t, dir, "api/public.ts", "export const pub = 1;")
			writeBoundaryLock(t, dir)

			rec, err := Run(dir, Options{Mode: "local", All: true, Frozen: true, Providers: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.Checks) != 2 || rec.Checks[0].ID != "waypost-boundaries" || rec.Checks[0].Status != StatusFail ||
				!strings.Contains(rec.Checks[0].OutputExcerpt, "client/use.ts") || rec.Checks[1].Status != StatusPass {
				t.Fatalf("boundary scan missed source before external mutation: %+v", rec.Checks)
			}
			if _, err := os.Stat(filepath.Join(dir, "client/use.ts")); !os.IsNotExist(err) {
				t.Fatalf("fixture did not delete source file: %v", err)
			}
		})
	}
}

func TestIncompleteBoundaryScanCannotPassVerify(t *testing.T) {
	for mode, status := range map[string]string{"enforce": StatusFail, "warn": StatusWarn} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cfg := fmt.Sprintf("schema_version: '1'\nboundaries: {enabled: true, mode: %s}\n", mode)
			writeBoundaryFixture(t, dir, config.ConfigFileName, cfg)
			writeBoundaryFixture(t, dir, "oversized.ts", strings.Repeat(" ", 1024*1024+1))
			rec, err := Run(dir, Options{All: true})
			if err != nil {
				t.Fatal(err)
			}
			g := onlyBoundaryCheck(t, rec)
			if g.Status != status || rec.Summary.Outcome != status || !strings.Contains(g.OutputExcerpt, "[incomplete-scan]") {
				t.Fatalf("incomplete scan did not produce %s: %+v", status, rec)
			}
		})
	}
}

func onlyBoundaryCheck(t *testing.T, rec *Receipt) CheckResult {
	t.Helper()
	if len(rec.Checks) != 1 || rec.Checks[0].ID != "waypost-boundaries" {
		t.Fatalf("expected one built-in boundary check: %+v", rec)
	}
	return rec.Checks[0]
}

func writeBoundaryFixture(t *testing.T, dir, rel, text string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeBoundaryLock(t *testing.T, dir string) {
	t.Helper()
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockfile.Write(dir, lockfile.Generate(res)); err != nil {
		t.Fatal(err)
	}
}

func gitBoundaryFixture(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestCIRatchetTrustedBaseline(t *testing.T) {
	const clean = "export const x = 1;\n"
	const violating = "import '../api/index';\n"
	const baselinePath = "policy/baseline[1].json"
	for _, tc := range []struct {
		name, baseMode, headMode, action, wantStatus, finding string
	}{
		{"grandfathered", "ratchet", "ratchet", "", StatusPass, ""},
		{"line shift", "ratchet", "ratchet", "shift", StatusPass, ""},
		{"net new", "ratchet", "ratchet", "new", StatusFail, ""},
		{"fingerprint expansion", "ratchet", "ratchet", "expand", StatusFail, "expanded boundary baseline"},
		{"expansion with component remap", "ratchet", "ratchet", "remap", StatusFail, "expanded boundary baseline"},
		{"expansion with a renamed baseline", "ratchet", "ratchet", "rename", StatusFail, "expanded boundary baseline"},
		{"fingerprint expansion without live violation", "ratchet", "ratchet", "expand-unused", StatusFail, "expanded boundary baseline"},
		{"resolved fingerprint removed", "ratchet", "ratchet", "shrink", StatusPass, ""},
		{"graduation and deletion", "ratchet", "enforce", "graduate", StatusPass, ""},
		{"ratchet downgrade with no live violations", "ratchet", "warn", "graduate", StatusFail, "from ratchet to warn"},
		{"enforce downgrade with no live violations", "enforce", "ratchet", "seed", StatusFail, "from enforce to ratchet"},
		{"warn upgraded to ratchet", "warn", "ratchet", "seed", StatusPass, ""},
		{"missing head baseline", "ratchet", "ratchet", "delete", StatusFail, ""},
		{"corrupt head baseline", "ratchet", "ratchet", "corrupt", StatusFail, "boundary baseline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := func(mode, rel string) string {
				return fmt.Sprintf(`schema_version: "1"
boundaries:
  enabled: true
  mode: %s
  baseline: "%s"
  rules:
    - id: web-no-api
      from: web
      deny_depends_on: [api]
components:
  - id: api
    root: src/api
  - id: web
    root: src/web
`, mode, rel)
			}
			writeBoundaryFixture(t, dir, config.ConfigFileName, cfg(tc.baseMode, baselinePath))
			writeBoundaryFixture(t, dir, "src/api/index.ts", clean)
			old := violating
			if tc.baseMode == "enforce" {
				old = clean
			}
			writeBoundaryFixture(t, dir, "src/web/old.ts", old)
			writeBoundaryFixture(t, dir, "src/web/older.ts", old)
			if tc.baseMode == "ratchet" {
				seedBoundaryFixture(t, dir, baselinePath)
			}
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "base")
			gitBoundaryFixture(t, dir, "checkout", "-b", "pr")

			headPath := baselinePath
			if tc.action == "rename" {
				headPath = "policy/moved.json"
			}
			writeBoundaryFixture(t, dir, config.ConfigFileName, cfg(tc.headMode, headPath))
			switch tc.action {
			case "shift":
				writeBoundaryFixture(t, dir, "src/web/old.ts", "\n// moved\n\n"+violating)
			case "new", "expand", "remap", "rename", "expand-unused":
				writeBoundaryFixture(t, dir, "src/web/new.ts", violating)
				if tc.action != "new" {
					seedBoundaryFixture(t, dir, headPath)
				}
				if tc.action == "expand-unused" {
					writeBoundaryFixture(t, dir, "src/web/new.ts", clean)
				}
				if tc.action == "remap" {
					writeBoundaryFixture(t, dir, config.ConfigFileName, strings.ReplaceAll(cfg(tc.headMode, headPath), "root: src/web", "root: src/reassigned"))
				}
			case "shrink":
				writeBoundaryFixture(t, dir, "src/web/old.ts", clean)
				seedBoundaryFixture(t, dir, headPath)
			case "graduate":
				writeBoundaryFixture(t, dir, "src/web/old.ts", clean)
				writeBoundaryFixture(t, dir, "src/web/older.ts", clean)
				fallthrough
			case "delete":
				if err := os.Remove(filepath.Join(dir, baselinePath)); err != nil {
					t.Fatal(err)
				}
			case "seed":
				seedBoundaryFixture(t, dir, headPath)
			case "corrupt":
				writeBoundaryFixture(t, dir, headPath, "{}")
			}
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "pr")

			rec, err := Run(dir, Options{Mode: "ci", Frozen: true, Base: "main"})
			if err != nil {
				t.Fatal(err)
			}
			check := onlyBoundaryCheck(t, rec)
			if rec.Summary.Outcome != tc.wantStatus || check.Status != tc.wantStatus || !check.Required || !check.FromBaseFloor {
				t.Fatalf("want %s from base floor, got %+v with policy %+v", tc.wantStatus, check, rec.Policy)
			}
			findings := strings.Join(rec.Policy.TamperingFindings, "\n")
			if (tc.finding == "" && findings != "") || (tc.finding != "" && !strings.Contains(findings, tc.finding)) {
				t.Fatalf("expected finding %q, got %q", tc.finding, findings)
			}
			switch tc.action {
			case "new", "expand", "remap", "rename":
				if !strings.Contains(check.OutputExcerpt, "src/web/new.ts") || strings.Contains(check.OutputExcerpt, "src/web/older.ts") {
					t.Fatalf("base floor did not surface only the new violation: %+v", check)
				}
			case "", "shift":
				if !strings.Contains(check.Reason, "2 grandfathered") {
					t.Fatalf("missing grandfathered count: %+v", check)
				}
			case "shrink":
				if !strings.Contains(strings.Join(rec.Policy.EscalationReasons, "\n"), baselinePath) {
					t.Fatalf("custom baseline was not a trust path: %+v", rec.Policy)
				}
			}
		})
	}
}

func TestCIRatchetCycleIdentity(t *testing.T) {
	const baseline = config.DefaultBaselinePath
	for _, tc := range []struct {
		name, a, b, c, extra, want string
	}{
		{"larger SCC", "import '../b/index';", "import '../a/zzz';", "import '../b/index';", "", StatusFail},
		{"earlier witness", "import '../b/index';", "import '../a/zzz';", "", "import '../b/index';", StatusPass},
		{"new edge within SCC", "import '../b/index';", "import '../c/index';", "import '../a/zzz';", "import '../c/index';", StatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: '1'
boundaries: {enabled: true, mode: ratchet}
components: [{id: a, root: src/a}, {id: b, root: src/b}, {id: c, root: src/c}]
`)
			writeBoundaryFixture(t, dir, "src/a/zzz.ts", tc.a)
			writeBoundaryFixture(t, dir, "src/b/index.ts", tc.b)
			initialC := tc.c
			if tc.name == "larger SCC" {
				initialC = ""
			}
			writeBoundaryFixture(t, dir, "src/c/index.ts", initialC)
			seedBoundaryFixture(t, dir, baseline)
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "base")
			gitBoundaryFixture(t, dir, "checkout", "-b", "pr")
			if tc.name == "larger SCC" {
				writeBoundaryFixture(t, dir, "src/a/zzz.ts", tc.a+"\nimport '../c/index';")
				writeBoundaryFixture(t, dir, "src/c/index.ts", tc.c)
			} else {
				writeBoundaryFixture(t, dir, "src/a/aaa.ts", tc.extra)
			}
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "pr")
			rec, err := Run(dir, Options{Mode: "ci", Frozen: true, Base: "main"})
			if err != nil {
				t.Fatal(err)
			}
			check := onlyBoundaryCheck(t, rec)
			wantReason := "1 boundary violation(s)"
			if tc.want == StatusPass {
				wantReason = "1 grandfathered"
			}
			if rec.Summary.Outcome != tc.want || check.Status != tc.want || !strings.Contains(check.Reason, wantReason) {
				t.Fatalf("want %s with %s, got %+v", tc.want, wantReason, check)
			}
		})
	}
}

func TestCIRatchetCountsRepeatedImportsAndRejectsCountExpansion(t *testing.T) {
	const baseline = config.DefaultBaselinePath
	const violating = "import '../api/index';"
	for _, tc := range []struct {
		name, imports string
		expand        bool
	}{
		{"extra imports on separate lines", strings.Repeat(violating+"\n", 3), false},
		{"extra imports on the same line", strings.Repeat(violating+" ", 3), false},
		{"count expansion", strings.Repeat(violating+"\n", 3), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: '1'
boundaries: {enabled: true, mode: ratchet, enforce_declared_deps: true}
components: [{id: api, root: api}, {id: web, root: web}]
`)
			writeBoundaryFixture(t, dir, "api/index.ts", "export const a = 1;")
			writeBoundaryFixture(t, dir, "web/index.ts", violating)
			seedBoundaryFixture(t, dir, baseline)
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "base")
			gitBoundaryFixture(t, dir, "checkout", "-b", "pr")
			writeBoundaryFixture(t, dir, "web/index.ts", tc.imports)
			if tc.expand {
				seedBoundaryFixture(t, dir, baseline)
			}
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "pr")
			rec, err := Run(dir, Options{Mode: "ci", Frozen: true, Base: "main"})
			if err != nil {
				t.Fatal(err)
			}
			check := onlyBoundaryCheck(t, rec)
			if rec.Summary.Outcome != StatusFail || check.Status != StatusFail ||
				!strings.Contains(check.Reason, "2 boundary violation(s)") {
				t.Fatalf("want both excess imports to fail CI, got %+v", check)
			}
			findings := strings.Join(rec.Policy.TamperingFindings, "\n")
			if tc.expand != strings.Contains(findings, "expanded boundary baseline") {
				t.Fatalf("expand=%t, findings=%q", tc.expand, findings)
			}
		})
	}
}

func TestCIRejectsUncommittedAndInvalidGitBaselines(t *testing.T) {
	for _, tc := range []string{"ignored", "symlink", "malformed base", "missing base", "oversized base"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			baseMode := "warn"
			if strings.HasSuffix(tc, "base") {
				baseMode = "ratchet"
			}
			cfg := func(mode string) string {
				return "schema_version: '1'\nboundaries: {enabled: true, mode: " + mode + "}\n"
			}
			writeBoundaryFixture(t, dir, config.ConfigFileName, cfg(baseMode))
			switch tc {
			case "ignored":
				writeBoundaryFixture(t, dir, ".gitignore", config.DefaultBaselinePath+"\n")
			case "malformed base":
				writeBoundaryFixture(t, dir, config.DefaultBaselinePath, "{}")
			case "oversized base":
				writeBoundaryFixture(t, dir, config.DefaultBaselinePath, strings.Repeat(" ", archgraph.MaxBaselineBytes+1))
			}
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "base")
			gitBoundaryFixture(t, dir, "checkout", "-b", "pr")
			writeBoundaryFixture(t, dir, config.ConfigFileName, cfg("ratchet"))
			switch tc {
			case "ignored":
				seedBoundaryFixture(t, dir, config.DefaultBaselinePath)
			case "symlink":
				seedBoundaryFixture(t, dir, "other.json")
				if err := os.Symlink("other.json", filepath.Join(dir, config.DefaultBaselinePath)); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			default:
				if tc == "oversized base" {
					if err := os.Remove(filepath.Join(dir, config.DefaultBaselinePath)); err != nil {
						t.Fatal(err)
					}
				}
				seedBoundaryFixture(t, dir, config.DefaultBaselinePath)
			}
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "pr")
			rec, err := Run(dir, Options{Mode: "ci", Base: "main", Frozen: true})
			if err != nil || rec.Summary.Outcome != StatusFail {
				t.Fatalf("CI accepted untrusted baseline: %+v, %v", rec, err)
			}
			if strings.HasSuffix(tc, "base") && !strings.Contains(strings.Join(rec.Policy.PreflightFailures, "\n"), "trusted base boundary baseline") {
				t.Fatalf("expected base baseline preflight failure: %+v", rec.Policy)
			}
		})
	}
}

func seedBoundaryFixture(t *testing.T, dir, rel string) {
	t.Helper()
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	cm, err := compmap.Build(dir, &res.Effective, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := archgraph.AnalyzeLive(dir, cm, res.Effective.Boundaries, archgraph.AnalyzeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := archgraph.SaveBaseline(dir, rel, report.Violations); err != nil {
		t.Fatal(err)
	}
}

func TestCIAnalyzesHeadSourceWithTrustedAliasDefinitions(t *testing.T) {
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: "1"
components:
  - {id: web, root: web}
  - {id: internal, root: internal}
  - {id: public, root: public}
boundaries:
  enabled: true
  rules:
    - {id: web-no-internal, from: web, deny_depends_on: [internal]}
`)
	writeBoundaryFixture(t, dir, "tsconfig.paths.jsonc", `{"compilerOptions":{"paths":{"@lib/*":["./internal/*"]}}}`)
	writeBoundaryFixture(t, dir, "tsconfig.json", `{"extends":"./tsconfig.paths.jsonc"}`)
	writeBoundaryFixture(t, dir, "internal/lib.ts", "export const x = 1;")
	writeBoundaryFixture(t, dir, "public/lib.ts", "export const x = 1;")
	writeBoundaryFixture(t, dir, "web/app.ts", "export const app = 1;")
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "trusted alias")
	gitBoundaryFixture(t, dir, "checkout", "-b", "candidate")
	writeBoundaryFixture(t, dir, "tsconfig.paths.jsonc", `{"compilerOptions":{"paths":{"@lib/*":["./public/*"]}}}`)
	writeBoundaryFixture(t, dir, "web/app.ts", "import '@lib/lib';")
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "change alias and import")
	rec, err := Run(dir, Options{Mode: "ci", Base: "main", Frozen: true})
	if err != nil {
		t.Fatal(err)
	}
	got := onlyBoundaryCheck(t, rec)
	if got.Status != StatusFail || !strings.Contains(got.OutputExcerpt, "[web-no-internal]") {
		t.Fatalf("base alias resolution was replaced with head metadata: %+v", got)
	}
}

func TestCITrackedSourceInHeuristicallySkippedDirectory(t *testing.T) {
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: '1'
components: [{id: app, root: app}, {id: lib, root: lib}]
boundaries:
  enabled: true
  no_cycles: true
  enforce_declared_deps: true
`)
	writeBoundaryFixture(t, dir, "app/main.ts", "export {};")
	writeBoundaryFixture(t, dir, "lib/public.ts", "export {};")
	writeBoundaryFixture(t, dir, ".gitignore", "node_modules/\n")
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "base")
	for _, name := range []string{"vendor", "build", ".internal", "coverage"} {
		writeBoundaryFixture(t, dir, "app/"+name+"/new.ts", "import '../../lib/public';")
	}
	writeBoundaryFixture(t, dir, "app/node_modules/ignored.ts", "import '../../lib/public';")
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "track sources")
	rec, err := Run(dir, Options{Mode: "ci", Base: "HEAD^", Frozen: true})
	if err != nil {
		t.Fatal(err)
	}
	check := onlyBoundaryCheck(t, rec)
	if check.Status != StatusFail || !strings.Contains(check.Reason, "4 boundary violation(s)") || strings.Contains(check.OutputExcerpt, "node_modules") {
		t.Fatalf("tracked sources skipped or installed dependency scanned: %+v", check)
	}
}
