package verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func runGitR2(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Waypost Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Waypost Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func writeLockR2(t *testing.T, dir string) {
	t.Helper()
	resolved, err := config.Load(dir, config.LoadOptions{Mode: "ci", Offline: true})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	raw, err := lockfile.Marshal(lockfile.Generate(resolved))
	if err != nil {
		t.Fatalf("lockfile.Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, lockfile.LockFileName), raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
}

func TestBootstrapAllowsPRMergeCommitAndRejectsTargetPriorPolicy(t *testing.T) {
	dir := t.TempDir()
	runGitR2(t, dir, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "initial")
	targetSHA := runGitR2(t, dir, "rev-parse", "HEAD")

	// Multi-commit adoption PR merged onto main (target never had .waypost.yaml).
	runGitR2(t, dir, "checkout", "-b", "feat/adopt")
	cfg := `schema_version: "1"
name: boot-pr
extends: "builtin:base@1.1.0"
checks:
  - id: ok
    command: "true"
    paths: ["**"]
    required: true
`
	if err := os.WriteFile(filepath.Join(dir, ".waypost.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	writeLockR2(t, dir)
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "adopt waypost")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "follow-up commit in adoption PR")

	// Simulate GitHub PR merge commit onto target main.
	runGitR2(t, dir, "checkout", "main")
	runGitR2(t, dir, "merge", "--no-ff", "feat/adopt", "-m", "Merge PR #1")

	rec, err := Run(dir, Options{Mode: "ci", Frozen: true, Offline: true, AllowBootstrap: true, Base: targetSHA})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.Summary.Outcome != StatusPass {
		t.Fatalf("first adoption PR merge commit should PASS, got %s (preflight=%v checks=%+v)", rec.Summary.Outcome, rec.Policy.PreflightFailures, rec.Checks)
	}

	// Now drop .waypost.yaml on target main, then attempt to re-adopt via bootstrap: MUST FAIL.
	runGitR2(t, dir, "rm", ".waypost.yaml", ".waypost.lock")
	runGitR2(t, dir, "commit", "-m", "drop policy")
	droppedTarget := runGitR2(t, dir, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(dir, ".waypost.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	writeLockR2(t, dir)
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "re-adopt weakened")

	rec2, err := Run(dir, Options{Mode: "ci", Frozen: true, Offline: true, AllowBootstrap: true, Base: droppedTarget})
	if err != nil {
		t.Fatalf("Run re-adopt: %v", err)
	}
	if rec2.Summary.Outcome == StatusPass {
		t.Fatalf("re-adoption after target previously had policy MUST FAIL, got PASS")
	}
}

func TestOversizedUnownedAndPreexistingIgnoredVsNewlyPadded(t *testing.T) {
	dir := t.TempDir()
	runGitR2(t, dir, "init", "-b", "main")
	mustWrite := func(rel, content string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	big := "//" + strings.Repeat("a", archgraph.MaxSourceFileBytes+64) + "\n"

	// Case 1: unowned oversized dist/bundle.js with declared components passes CI cleanly.
	mustWrite("packages/a/index.ts", "export const a = 1;\n")
	mustWrite("dist/unowned-bundle.js", big)
	mustWrite("owned-dist/bundle.js", big)
	cfgBase := `schema_version: "1"
name: big-test
extends: "builtin:base@1.1.0"
boundaries:
  enabled: true
  mode: enforce
  no_cycles: true
  enforce_declared_deps: true
components:
  - id: a
    root: packages/a
    kind: package
    language: typescript
    paths: ["packages/a/**"]
  - id: root
    root: .
    kind: package
    language: typescript
    paths: ["owned-dist/**"]
checks:
  - id: ok
    command: "true"
    paths: ["**"]
    required: true
`
	mustWrite(".waypost.yaml", cfgBase)
	writeLockR2(t, dir)
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "base with pre-existing oversized owned and unowned files")
	baseSHA := runGitR2(t, dir, "rev-parse", "HEAD")

	// PR adds ignore_paths for the pre-existing oversized owned-dist/bundle.js -> MUST PASS
	// (and unowned dist/unowned-bundle.js is already ignored without scan error).
	cfgHead := strings.Replace(cfgBase, "  enforce_declared_deps: true\n", "  enforce_declared_deps: true\n  ignore_paths:\n    - \"owned-dist/**\"\n", 1)
	mustWrite(".waypost.yaml", cfgHead)
	writeLockR2(t, dir)
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "ignore pre-existing oversized owned bundle")

	rec, err := Run(dir, Options{Mode: "ci", Frozen: true, Offline: true, Base: baseSHA})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.Summary.Outcome != StatusPass {
		t.Fatalf("pre-existing oversized excluded in PR + unowned oversized should PASS, got %s (preflight=%v checks=%+v)", rec.Summary.Outcome, rec.Policy.PreflightFailures, rec.Checks)
	}

	// Case 2: PR introduces a NEW oversized file under component `a` and tries to exclude it via ignore_paths -> MUST FAIL!
	mustWrite("packages/a/padded-evil.ts", big)
	cfgBypass := strings.Replace(cfgHead, "    - \"owned-dist/**\"\n", "    - \"owned-dist/**\"\n    - \"packages/a/padded-evil.ts\"\n", 1)
	mustWrite(".waypost.yaml", cfgBypass)
	writeLockR2(t, dir)
	runGitR2(t, dir, "add", ".")
	runGitR2(t, dir, "commit", "-m", "attempt to hide newly added oversized file")

	rec2, err := Run(dir, Options{Mode: "ci", Frozen: true, Offline: true, Base: baseSHA})
	if err != nil {
		t.Fatalf("Run bypass: %v", err)
	}
	if rec2.Summary.Outcome == StatusPass {
		t.Fatalf("newly added oversized file hidden by PR ignore_paths MUST FAIL, got PASS")
	}
}
