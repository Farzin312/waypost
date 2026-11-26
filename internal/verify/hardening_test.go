package verify

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/config"
)

func TestCIAuthorityAndFirstAdoption(t *testing.T) {
	for _, fixture := range []string{"explicit self", "environment self", "descendant", "missing policy", "first adoption", "past policy", "missing target lock"} {
		t.Run(fixture, func(t *testing.T) {
			dir := t.TempDir()
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			const policy = "schema_version: '1'\n"
			if fixture == "past policy" || fixture == "missing target lock" {
				writeBoundaryFixture(t, dir, config.ConfigFileName, policy)
				gitBoundaryFixture(t, dir, "add", ".")
			}
			gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "initial")
			if fixture == "past policy" {
				gitBoundaryFixture(t, dir, "rm", config.ConfigFileName)
				gitBoundaryFixture(t, dir, "commit", "-m", "remove past policy")
			}
			gitBoundaryFixture(t, dir, "branch", "target")
			writeBoundaryFixture(t, dir, config.ConfigFileName, policy)
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "candidate")
			opts := Options{Mode: "ci", Base: "target", Frozen: true, Offline: true}
			var diagnostic string
			switch fixture {
			case "explicit self":
				opts.Base, diagnostic = "HEAD", "points to the worktree HEAD"
			case "environment self":
				t.Setenv("WAYPOST_CI_BASE", "HEAD")
				opts.Base, diagnostic = "", "points to the worktree HEAD"
			case "descendant":
				gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "future target")
				gitBoundaryFixture(t, dir, "reset", "--hard", "HEAD^")
				opts.Base, diagnostic = "HEAD@{1}", "merge-base points to the worktree HEAD"
			case "missing policy":
				diagnostic = "first adoption requires --allow-bootstrap"
			case "first adoption":
				opts.AllowBootstrap = true
			case "past policy":
				opts.AllowBootstrap = true
				diagnostic = "requires previous trees with no Waypost policy"
			case "missing target lock":
				diagnostic = "trusted target lock is missing"
			}
			receipt, err := Run(dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			if diagnostic == "" {
				if !receipt.PlanComplete || receipt.Summary.Outcome != StatusPass || receipt.Policy.PolicyFloorEnforced {
					t.Fatalf("first adoption: %+v", receipt)
				}
			} else if receipt.PlanComplete || receipt.Summary.Outcome != StatusFail ||
				!strings.Contains(strings.Join(receipt.Policy.PreflightFailures, "\n"), diagnostic) {
				t.Fatalf("expected %q, got %+v", diagnostic, receipt)
			}
		})
	}
}

func TestCIRetainedProofAndCandidateWrapperReporting(t *testing.T) {
	for _, removeProof := range []bool{false, true} {
		name := "changed wrapper"
		if removeProof {
			name = "deleted proof"
		}
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("check fixture uses a Unix shell")
			}
			dir := t.TempDir()
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			const policy = `schema_version: '1'
components: [{id: app, root: app}]
rules:
  - id: protected
    kind: invariant
    summary: protected behavior
    verified_by: {tests: [app/proof.test.ts], checks: [gate]}
checks:
  - {id: gate, command: 'sh scripts/gate.sh', paths: [app/**]}
`
			writeBoundaryFixture(t, dir, config.ConfigFileName, policy)
			writeBoundaryFixture(t, dir, "app/proof.test.ts", "export {};")
			writeBoundaryFixture(t, dir, "scripts/gate.sh", "echo target")
			writeBoundaryLock(t, dir)
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "target")
			gitBoundaryFixture(t, dir, "checkout", "-b", "candidate")
			writeBoundaryFixture(t, dir, "scripts/gate.sh", "echo candidate")
			if removeProof {
				writeBoundaryFixture(t, dir, config.ConfigFileName, strings.Replace(policy, "tests: [app/proof.test.ts], ", "", 1))
				gitBoundaryFixture(t, dir, "rm", "app/proof.test.ts")
				writeBoundaryLock(t, dir)
			}
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "candidate policy and wrapper")
			rec, err := Run(dir, Options{Mode: "ci", Base: "main", Frozen: true})
			if err != nil {
				t.Fatal(err)
			}
			check := rec.Checks[0]
			if removeProof {
				if rec.Summary.Outcome != StatusFail || check.Status != StatusSkip ||
					!strings.Contains(strings.Join(rec.Policy.PreflightFailures, "\n"), "app/proof.test.ts") {
					t.Fatalf("retained proof was lost: %+v", rec)
				}
			} else if check.Status != StatusPass || check.DefinitionSource != "head" || !check.FromBaseFloor ||
				!rec.Policy.TrustBoundaryTriggered || !strings.Contains(check.OutputExcerpt, "candidate") {
				t.Fatalf("wrapper receipt: %+v, policy %+v", check, rec.Policy)
			}
		})
	}
}

func TestLocalExplicitSelectorAndNoMatchFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix shell")
	}
	for _, f := range []struct{ command, result, lane string }{
		{"true", "full", "full"},
		{"node --test --passWithNoTests app/proof.test.js", "full", "full"},
		{"node --test app/proof.test.js", "seam", "local_changed"},
		{"node --import tsx --test app/proof.test.js", "seam", "local_changed"},
		{"npm run test:project -- --runTestsByPath app/proof.test.js", "seam", "local_changed"},
		{"node --test app/proof.test.js", "fallback", "full"},
	} {
		t.Run(f.command+"/"+f.result, func(t *testing.T) {
			dir, tools := t.TempDir(), t.TempDir()
			t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
			for _, bin := range []string{"node", "npm"} {
				runner := "#!/bin/sh\necho seam\n"
				if f.result == "fallback" {
					runner = "#!/bin/sh\nexit \"$WAYPOST_NO_TESTS_EXIT_CODE\"\n"
				}
				if err := os.WriteFile(filepath.Join(tools, bin), []byte(runner), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			gitBoundaryFixture(t, dir, "init", "-b", "main")
			writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: '1'
components: [{id: app, root: app}]
checks:
  - id: gate
    paths: [app/**]
    command: echo full
    local_command: `+f.command+"\n")
			writeBoundaryFixture(t, dir, "package.json", `{"scripts":{"test:project":"jest --maxWorkers=2"}}`)
			writeBoundaryFixture(t, dir, "app/code.mts", "export const value = 1;")
			writeBoundaryFixture(t, dir, "app/proof.test.js", "export {};")
			gitBoundaryFixture(t, dir, "add", ".")
			gitBoundaryFixture(t, dir, "commit", "-m", "policy")
			writeBoundaryFixture(t, dir, "app/code.mts", "export const value = 2;")
			rec, err := Run(dir, Options{Base: "HEAD"})
			if err != nil {
				t.Fatal(err)
			}
			check := rec.Checks[0]
			if check.Status != StatusPass || check.Lane != f.lane {
				t.Fatalf("selector: %+v", check)
			}
			if f.lane == "full" && (check.Command != "echo full" || check.OutputExcerpt != "full") {
				t.Fatalf("full receipt: %+v", check)
			}
			if f.result == "fallback" && !strings.Contains(check.Reason, "found no tests") {
				t.Fatalf("fallback receipt: %+v", check)
			}
		})
	}
}

func TestCheckWaitDelayPreservesSuccessAndKillsDescendants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process group fixture")
	}
	dir := t.TempDir()
	check := changeplan.Check{Selected: true, Check: config.Check{
		ID: "background", Command: "(sleep 1; touch orphan) & echo started",
	}}
	got := executeCheckContext(context.Background(), dir, check, "full", handoff{})
	if got.Status != StatusPass || !strings.Contains(got.Reason, "leaked child stdio") {
		t.Fatalf("expected a successful shell with an advisory: %+v", got)
	}
	time.Sleep(650 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "orphan")); !os.IsNotExist(err) {
		t.Fatalf("background descendant survived: %v", err)
	}
}

func TestProviderEdgesReplanWithScrubbedRunnerEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix shell")
	}
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	writeBoundaryFixture(t, dir, config.ConfigFileName, `schema_version: '1'
components: [{id: api, root: api}, {id: web, root: web}]
checks:
  - {id: web, command: 'echo web', paths: [web/**], components: [web]}
providers:
  - id: edges
    authorized: true
    tool: sh
    command: 'sh edges.sh'
`)
	writeBoundaryFixture(t, dir, "edges.sh", `test -z "${GITHUB_ENV+x}${GITHUB_OUTPUT+x}${GITHUB_PATH+x}${GITHUB_STATE+x}${GITHUB_STEP_SUMMARY+x}" || exit 1
printf '%s\n' '{"edges":[{"from":"web","to":"api"}]}'
`)
	for _, key := range []string{"GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"} {
		t.Setenv(key, "runner")
	}
	writeBoundaryFixture(t, dir, "api/main.ts", "")
	writeBoundaryFixture(t, dir, "web/main.ts", "")
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "policy")
	writeBoundaryFixture(t, dir, "api/main.ts", "export const api = 1;")
	for _, enabled := range []bool{false, true} {
		rec, err := Run(dir, Options{Base: "HEAD", Providers: enabled})
		if err != nil {
			t.Fatal(err)
		}
		status := StatusSkip
		if enabled {
			status = StatusPass
			if len(rec.Policy.Providers) != 1 || !rec.Policy.Providers[0].Executed {
				t.Fatalf("provider did not run: %+v", rec.Policy.Providers)
			}
		}
		if len(rec.Checks) != 1 || rec.Checks[0].Status != status {
			t.Fatalf("provider enabled %t: %+v", enabled, rec.Checks)
		}
	}
}

func TestReceiptMarkdownEscapesAllRepositoryText(t *testing.T) {
	injection := "a|`\n<img src=x>\x1b[31m"
	markdown := RenderMarkdown(&Receipt{
		Summary: ReceiptSummary{Outcome: "FAIL"},
		Policy:  ReceiptPolicy{PreflightFailures: []string{injection}},
		Checks:  []CheckResult{{ID: injection, Status: "FAIL", Reason: injection}},
	})
	if strings.Contains(markdown, "<img") || strings.Contains(markdown, "\x1b") ||
		strings.Contains(markdown, "a|") || !strings.Contains(markdown, "&#124;") {
		t.Fatalf("unsafe Markdown: %q", markdown)
	}
}
