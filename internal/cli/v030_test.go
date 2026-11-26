package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/history"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/presets"
)

func command(t *testing.T, want int, args ...string) []byte {
	t.Helper()
	var out, stderr bytes.Buffer
	if code := Run(args, &out, &stderr); code != want {
		t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", args, code, want, out.String(), stderr.String())
	}
	return out.Bytes()
}

func TestBuiltinVersionsAndFrozenFloatingRollback(t *testing.T) {
	for _, name := range presets.Names() {
		for _, version := range []string{"1.0.0", "1.1.0"} {
			ref := "builtin:" + name + "@" + version
			preset, err := presets.Resolve(ref)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.ParseBytes(preset.Raw, ref)
			if err != nil || cfg.PresetVersion != version {
				t.Fatalf("%s: %+v, %v", ref, cfg, err)
			}
			if name != "base" && cfg.Extends != "builtin:base@"+version {
				t.Fatalf("%s extends %s", ref, cfg.Extends)
			}
		}
	}
	if _, err := presets.Resolve("builtin:base@1.9.9"); err == nil {
		t.Fatal("unknown version resolved")
	}
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, config.ConfigFileName), "schema_version: '1'\nextends: builtin:base@latest\n")
	legacy, err := config.Load(dir, config.LoadOptions{PinnedBuiltins: map[string]string{"builtin:base": "builtin:base@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	lock := lockfile.Generate(legacy)
	if _, err := lockfile.Write(dir, lock); err != nil {
		t.Fatal(err)
	}
	command(t, 0, "verify", "--dir", dir, "--frozen", "--all", "--offline")
	command(t, 0, "sync", "--dir", dir, "--check", "--offline")
	command(t, 0, "upgrade", "--dir", dir, "--to", "builtin:base@1.1.0", "--apply")
	updated, err := config.Load(dir, config.LoadOptions{})
	if err != nil || updated.Chain[0].Version != "1.1.0" {
		t.Fatalf("upgrade: %+v %v", updated, err)
	}
	command(t, 0, "upgrade", "--dir", dir, "--to", "builtin:base@1.0.0", "--apply")
	command(t, 0, "verify", "--dir", dir, "--frozen", "--all", "--offline")
}

func TestContextWorkStateIsWorktreeIsolated(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, config.ConfigFileName), `schema_version: "1"
components: [{id: app, root: app}]
checks:
  - {id: app-check, command: 'echo verified', paths: [app/**]}
`)
	mustWriteFile(t, filepath.Join(dir, "app/main.go"), "package app\n")
	mustWriteFile(t, filepath.Join(dir, "app/main_test.go"), "package app\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "base")
	worktree := filepath.Join(t.TempDir(), "linked")
	mustGit(t, dir, "worktree", "add", "-b", "linked", worktree)
	mustWriteFile(t, filepath.Join(worktree, "app/main.go"), "package app\nvar v = 1\n")
	get := func(path string) ContextChanged {
		t.Helper()
		raw := command(t, 0, "context", "--dir", path, "--changed", "--base", "HEAD", "--recent", "0", "--format", "json")
		var out ContextChanged
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	state := get(worktree).WorkState
	if state == nil || state.Verification != "none" || !slices.Equal(state.UntestedComponents, []string{"app"}) {
		t.Fatalf("unexpected initial state %+v", state)
	}
	command(t, 0, "verify", "--dir", worktree, "--base", "HEAD")
	metadata := strings.TrimSpace(runGitOutput(t, worktree, "rev-parse", "--path-format=absolute", "--git-dir"))
	if records, err := filepath.Glob(filepath.Join(metadata, "waypost", "last-receipt-*.json")); err != nil || len(records) != 1 {
		t.Fatal(err)
	}
	if get(dir).WorkState != nil {
		t.Fatal("clean main worktree picked up linked verification")
	}
	if records, err := filepath.Glob(filepath.Join(dir, ".git", "waypost", "last-receipt-*.json")); err != nil || len(records) != 0 {
		t.Fatalf("linked verification wrote main metadata: %v", err)
	}
	if got := get(worktree).WorkState; got.Verification != "fresh" || got.Overall != "PASS" {
		t.Fatalf("unexpected recorded state %+v", got)
	}
	mustWriteFile(t, filepath.Join(worktree, "app/main_test.go"), "package app\n// test touched\n")
	if got := get(worktree).WorkState; got.Verification != "stale" || len(got.UntestedComponents) > 0 {
		t.Fatalf("unexpected edited state %+v", got)
	}
}

func TestHistoryStaticTraversalAttributionPaginationAndShallow(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	mustWriteFile(t, filepath.Join(dir, "old/a.ts"), "export const first = 1;\nexport const second = 2;\n")
	mustWriteFile(t, filepath.Join(dir, "old/delete.ts"), "export const deleted = 1;")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "Initial repository")
	mustWriteFile(t, filepath.Join(dir, config.ConfigFileName), `schema_version: "1"
extends: policy.yaml
components: [{id: old, root: old}, {id: new, root: new}]
providers:
  - {id: tripwire, tool: sh, command: 'touch should-not-run', authorized: true}
checks:
  - {id: check, command: 'touch should-not-run'}
`)
	mustWriteFile(t, filepath.Join(dir, "policy.yaml"), "schema_version: '1'\nrules: [{id: x, kind: invariant, summary: first}]\n")
	command(t, 0, "upgrade", "--dir", dir, "--apply")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "feat(policy): adopt")
	mustGit(t, dir, "checkout", "-b", "side")
	if err := os.Mkdir(filepath.Join(dir, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "mv", "old/a.ts", "new/a.ts")
	mustGit(t, dir, "rm", "old/delete.ts")
	mustGit(t, dir, "commit", "-m", "fix(new): Preserve <b>subject</b>")
	mustGit(t, dir, "checkout", "main")
	mustWriteFile(t, filepath.Join(dir, "policy.yaml"), "schema_version: '1'\nrules: [{id: x, kind: invariant, summary: second}]\n")
	command(t, 0, "upgrade", "--dir", dir, "--apply")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "Change inherited rule")
	mustGit(t, dir, "merge", "--no-ff", "side", "-m", "Merge side")
	get := func(path string, args ...string) history.Result {
		t.Helper()
		raw := command(t, 0, append([]string{"history", "--dir", path, "--format", "json"}, args...)...)
		var r history.Result
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := get(dir, "--limit", "1")
	if !first.Truncated || first.NextCursor == "" || first.Events[0].Subject != "Merge side" {
		t.Fatalf("first page %+v", first)
	}
	second := get(dir, "--limit", "1", "--cursor", first.NextCursor)
	if len(second.Events) != 1 || second.Events[0].Subject != "Change inherited rule" ||
		!slices.ContainsFunc(second.Events[0].Comparisons[0].Policy, func(delta history.Delta) bool { return delta.ID == "x" && delta.Kind == "rule" }) {
		t.Fatalf("second page %+v", second)
	}
	all := get(dir, "--all-parents", "--limit", "0")
	if len(all.Events) != 5 || len(all.Events[0].Comparisons) != 2 {
		t.Fatalf("unexpected DAG: %+v", all)
	}
	var renamed, deleted bool
	for _, event := range all.Events {
		if event.Type != "fix" || event.Scope != "new" {
			continue
		}
		for _, c := range event.Comparisons {
			for _, change := range c.Changes {
				switch change.Status {
				case "R":
					renamed = slices.Equal(change.OldOwners, []string{"old"}) && slices.Equal(change.NewOwners, []string{"new"})
				case "D":
					deleted = slices.Equal(change.OldOwners, []string{"old"}) && len(change.NewOwners) == 0
				}
			}
		}
	}
	if !renamed || !deleted {
		t.Fatalf("missing rename/delete attribution %+v", all)
	}
	if trust := get(dir, "--trust-only", "--limit", "0"); len(trust.Events) != 2 {
		t.Fatalf("unexpected trust events: %+v", trust.Events)
	}
	markdown := command(t, 0, "history", "--dir", dir, "--all-parents", "--format", "markdown")
	if bytes.Contains(markdown, []byte("<b>subject")) || !bytes.Contains(markdown, []byte("Preserve &lt;b&gt;subject")) {
		t.Fatalf("unescaped subject %s", markdown)
	}
	command(t, 0, "spec", "--dir", dir, "--ref", "HEAD", "--component", "new", "--history")
	command(t, 0, "context", "--dir", dir)
	if _, err := os.Stat(filepath.Join(dir, "should-not-run")); !os.IsNotExist(err) {
		t.Fatalf("read command executed repository code: %v", err)
	}
	shallow := filepath.Join(t.TempDir(), "shallow")
	mustGit(t, dir, "clone", "--depth", "1", "file://"+dir, shallow)
	if h := get(shallow); h.Complete || len(h.Diagnostics) == 0 {
		t.Fatalf("shallow interval not identified: %+v", h)
	}
}

func TestChangedContextHardByteBound(t *testing.T) {
	r := ContextChanged{
		Omitted: map[string]int{},
		Policy:  &contextReview{true, []changeplan.ReviewReason{{Code: "trust_path", Items: []string{strings.Repeat("<", 1024)}}}},
	}
	for range 100 {
		r.Impact.DirectComponents = append(r.Impact.DirectComponents, strings.Repeat("<", 1024))
		r.AffectedPaths = append(r.AffectedPaths, strings.Repeat("<", 1024))
		r.CoverageGaps = append(r.CoverageGaps, strings.Repeat("<", 1024))
	}
	r.bound()
	raw, err := json.Marshal(r)
	if err != nil || len(raw)+1 > changedContextBytes || r.Omitted["paths"]+len(r.AffectedPaths) != 100 {
		t.Fatalf("bad context limit (%d bytes): %+v", len(raw), r.Omitted)
	}
}
