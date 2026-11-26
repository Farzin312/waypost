package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestFrozenLockAbortRunsZeroChecksAndZeroProviders(t *testing.T) {
	dir := t.TempDir()
	markerCheck := filepath.Join(dir, "check-ran.marker")
	markerProv := filepath.Join(dir, "prov-ran.marker")

	cfgYAML := `schema_version: "1"
name: preflight-guard
extends: "builtin:base@1.0.0"
checks:
  - id: side-effect
    command: "touch ` + markerCheck + `"
    required: true
providers:
  - id: side-effect-prov
    tool: sh
    command: "touch ` + markerProv + ` && echo '{}'"
    authorized: true
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// Intentionally DO NOT write a valid .waypost.lock!
	rec, err := Run(dir, Options{Mode: "local", Frozen: true, Providers: true})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if rec.Summary.Outcome != StatusFail {
		t.Fatalf("expected FAIL when frozen lock missing, got %s", rec.Summary.Outcome)
	}
	if _, err := os.Stat(markerCheck); err == nil {
		t.Fatal("check command executed despite frozen lock failure!")
	}
	if _, err := os.Stat(markerProv); err == nil {
		t.Fatal("provider command executed despite frozen lock failure!")
	}
}

func TestNoChecksReceiptEmitsJSONArrayNotNullAndUnicodeTrustMatch(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}
	git("init", "-b", "main")
	cfgYAML := `schema_version: "1"
name: unicode-test
policy:
  trust_paths:
    - "café.txt"
checks: []
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockfile.Write(dir, lockfile.Generate(res)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "café.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-m", "init")

	git("checkout", "-b", "feat/unicode")
	if err := os.WriteFile(filepath.Join(dir, "café.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-m", "edit café.txt")

	// Also place a directory at .waypost.local.yaml to verify CI never opens/aborts on it!
	if err := os.Mkdir(filepath.Join(dir, config.LocalConfigFileName), 0o755); err != nil {
		t.Fatal(err)
	}

	rec, err := Run(dir, Options{Mode: "ci", Base: "main", Frozen: true})
	if err != nil {
		t.Fatalf("CI Run failed: %v", err)
	}
	if !rec.Policy.TrustBoundaryTriggered {
		t.Fatalf("expected café.txt edit to trigger trust boundary! changed=%v", rec.Impact.ChangedPaths)
	}
	if !rec.Policy.LocalOverrideIgnored {
		t.Fatal("expected local_override_ignored=true when .waypost.local.yaml directory exists in CI")
	}
	rawJSON, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawJSON), `"checks":[]`) {
		t.Fatalf("expected empty JSON array for checks, got: %s", string(rawJSON))
	}
}

func TestCIRequiresEventBaseAndRunsBothCheckDefinitions(t *testing.T) {
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	cfg := func(command string) string {
		return fmt.Sprintf(`schema_version: "1"
checks:
  - id: obligated
    command: "echo %s"
    local_command: "echo local"
`, command)
	}
	writeBoundaryFixture(t, dir, config.ConfigFileName, cfg("base"))
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "base")
	gitBoundaryFixture(t, dir, "checkout", "-b", "head")
	writeBoundaryFixture(t, dir, config.ConfigFileName, cfg("head"))
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "head")

	t.Setenv("WAYPOST_CI_BASE", "")
	for _, base := range []string{"", strings.Repeat("0", 40), "missing"} {
		rec, err := Run(dir, Options{Mode: "ci", Base: base, All: true, Frozen: true})
		if err != nil || rec.Summary.Outcome != StatusFail || rec.Summary.Passed != 0 || rec.PlanComplete {
			t.Fatalf("invalid CI authority %q: %+v %v", base, rec, err)
		}
	}
	rec, err := Run(dir, Options{Mode: "ci", Base: "main", All: true, Frozen: true})
	if err != nil || rec.Summary.Outcome != StatusPass || len(rec.Checks) != 2 || !rec.PlanComplete ||
		rec.Checks[0].DefinitionSource != "base" || rec.Checks[0].OutputExcerpt != "base" ||
		rec.Checks[1].DefinitionSource != "head" || rec.Checks[1].OutputExcerpt != "head" ||
		rec.Checks[0].Lane != "full" || rec.Checks[1].Lane != "full" ||
		rec.Digests.TargetPolicyDigest == rec.Digests.HeadPolicyDigest || rec.Verifier.BinarySHA256 == "" {
		t.Fatalf("CI obligations were not proved: %+v %v", rec, err)
	}
	gitBoundaryFixture(t, dir, "update-index", "--assume-unchanged", config.ConfigFileName)
	rec, err = Run(dir, Options{Mode: "ci", Base: "main", All: true})
	if err != nil || rec.Summary.Outcome != StatusFail || !strings.Contains(strings.Join(rec.Policy.PreflightFailures, " "), "hides worktree changes") {
		t.Fatalf("unsafe Git index passed preflight: %+v %v", rec, err)
	}
}

func TestCIBootstrapRequiresCleanFirstAdoption(t *testing.T) {
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "pre-adoption")
	writeBoundaryFixture(t, dir, config.ConfigFileName, "schema_version: '1'\nchecks: [{id: proof, command: echo adopted}]\n")
	writeBoundaryLock(t, dir)
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "adopt")
	opts := Options{Mode: "ci", Base: strings.Repeat("0", 40), AllowBootstrap: true, Frozen: true}
	rec, err := Run(dir, opts)
	if err != nil || rec.Summary.Outcome != StatusPass || !rec.PlanComplete {
		t.Fatalf("first adoption failed %+v %v", rec, err)
	}
	gitBoundaryFixture(t, dir, "commit", "--allow-empty", "-m", "already adopted")
	rec, err = Run(dir, opts)
	if err != nil || rec.Summary.Outcome != StatusFail || rec.Summary.Passed != 0 {
		t.Fatalf("established policy bootstrap passed %+v %v", rec, err)
	}
}
