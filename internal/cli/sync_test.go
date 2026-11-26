package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestSyncCommandsAndSparseContext(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, config.ConfigFileName), "schema_version: '1'\ncomponents: [{id: app, root: app}, {id: repo, root: ., paths: [package.json]}]\n")
	mustWriteFile(t, filepath.Join(dir, "app/index.ts"), "export const app = 1;")
	mustWriteFile(t, filepath.Join(dir, "new/index.ts"), "export const extra = 2;")
	mustWriteFile(t, filepath.Join(dir, "package.json"), `{"scripts":{"lint":"eslint ."}}`)
	run := func(want int, sub string, args ...string) string {
		t.Helper()
		var out, err bytes.Buffer
		if got := Run(append([]string{sub, "--dir", dir}, args...), &out, &err); got != want {
			t.Fatalf("%s %v exit %d, want %d; stdout=%s stderr=%s", sub, args, got, want, &out, &err)
		}
		return out.String()
	}
	for _, flag := range [][]string{{}, {"--format", "json"}} {
		if got := run(0, "sync", flag...); !strings.Contains(got, "unmapped_dir") {
			t.Fatalf("no dry-run drift: %s", got)
		}
	}
	run(1, "sync", "--check")
	drift := run(0, "context", "--format", "json")
	if !strings.Contains(drift, `"sync_drift"`) || strings.Contains(drift, `"unwired_script"`) ||
		!strings.Contains(drift, "run: waypost sync --apply") {
		t.Fatalf("wrong context drift: %s", drift)
	}
	if got := run(0, "context"); !strings.Contains(got, "Sync drift:") {
		t.Fatalf("text context omitted drift: %s", got)
	}
	run(0, "sync", "--apply")
	run(0, "sync", "--check")
	if got := run(0, "context", "--format", "json"); strings.Contains(got, `"sync_drift"`) {
		t.Fatalf("advisory-only drift added tokens to context: %s", got)
	}
	if got := run(0, "context"); strings.Contains(got, "Sync drift:") {
		t.Fatalf("clean text context showed drift: %s", got)
	}
	cfg := filepath.Join(dir, config.ConfigFileName)
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, cfg, string(raw)+"checks:\n  - {id: broken, command: 'pnpm run gone'}\n")
	if got := run(1, "sync", "--apply", "--format", "json"); !strings.Contains(got, "missing_script") ||
		!strings.Contains(got, `"lock_refreshed": true`) {
		t.Fatalf("manual drift or repaired lock missing: %s", got)
	}
}

func TestGraphUpdateBaselineSeedsAndSyncGraduates(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, config.ConfigFileName), `schema_version: '1'
boundaries: {enabled: true, mode: ratchet, enforce_declared_deps: true}
components: [{id: app, root: app}, {id: api, root: api}]
`)
	mustWriteFile(t, filepath.Join(dir, "app/index.ts"), "import '../api/index';")
	mustWriteFile(t, filepath.Join(dir, "api/index.ts"), "export const x = 1;")
	run := func(want int, args ...string) archgraph.Report {
		t.Helper()
		var out, stderr bytes.Buffer
		if got := Run(append([]string{"graph", "--dir", dir, "--format", "json"}, args...), &out, &stderr); got != want {
			t.Fatalf("graph %v exit %d, want %d; stdout=%s stderr=%s", args, got, want, &out, &stderr)
		}
		var report archgraph.Report
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	if got := run(1, "--check-boundaries"); len(got.ScanErrors) != 1 {
		t.Fatalf("missing baseline did not fail closed: %+v", got)
	}
	if got := run(0, "--update-baseline", "--check-boundaries"); got.GrandfatheredCount != 1 || len(got.Violations) != 0 {
		t.Fatalf("update did not seed debt: %+v", got)
	}
	run(0, "--check-boundaries")
	mustWriteFile(t, filepath.Join(dir, "app/index.ts"), "export const app = 1;")
	if err := os.Remove(filepath.Join(dir, config.DefaultBaselinePath)); err != nil {
		t.Fatal(err)
	}
	run(0, "--update-baseline")
	baseline, err := archgraph.LoadBaseline(dir, config.DefaultBaselinePath)
	if err != nil || len(baseline.Entries) != 0 {
		t.Fatalf("clean ratchet needs an empty baseline: %+v, %v", baseline, err)
	}
	runCLI := func(sub string, args ...string) string {
		t.Helper()
		var out, stderr bytes.Buffer
		if got := Run(append([]string{sub, "--dir", dir}, args...), &out, &stderr); got != 0 {
			t.Fatalf("%s %v exit %d; stdout=%s stderr=%s", sub, args, got, &out, &stderr)
		}
		return out.String()
	}
	runCLI("verify")
	if got := runCLI("sync"); !strings.Contains(got, "baseline_graduate") {
		t.Fatalf("sync did not report graduation: %s", got)
	}
	runCLI("sync", "--apply")
	if _, err := os.Stat(filepath.Join(dir, config.DefaultBaselinePath)); !os.IsNotExist(err) {
		t.Fatalf("graduation left the baseline in place: %v", err)
	}
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil || res.Effective.Boundaries.EffectiveMode() != "enforce" || !lockfile.Verify(dir, res).Valid {
		t.Fatalf("graduation did not publish a frozen enforce config: %+v, %v", res, err)
	}
	runCLI("sync", "--check")
}

func TestSyncRetainsComponentsWithLivePathsAndPolicy(t *testing.T) {
	dir := t.TempDir()
	const raw = `schema_version: "1"
components:
  - id: assets
    root: missing
    paths: [data/*.json]
    checks: [validate]
    trust_paths: [data/*.json]
  - id: paths-only
    root: missing-too
    paths: [data/*.txt]
  - id: file-root
    root: config.json
  - id: policy-only
    root: absent
    checks: [validate]
  - id: trust-only
    root: also-absent
    trust_paths: [docs/future.md]
checks:
  - id: validate
    command: echo validate
`
	for rel, content := range map[string]string{config.ConfigFileName: raw, "data/values.json": "{}", "data/info.txt": "asset", "config.json": "{}"} {
		mustWriteFile(t, filepath.Join(dir, rel), content)
	}
	for _, flag := range []string{"--apply", "--check"} {
		var out, stderr bytes.Buffer
		if got := Run([]string{"sync", "--dir", dir, flag}, &out, &stderr); got != 0 {
			t.Fatalf("sync %s exit %d; stdout=%s stderr=%s", flag, got, &out, &stderr)
		}
		if strings.Contains(out.String(), "stale_component") || !strings.Contains(out.String(), "policy-only") || !strings.Contains(out.String(), "trust-only") {
			t.Fatalf("expected advisory findings for policy-bearing components without files: %s", &out)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, config.ConfigFileName))
	if err != nil || string(got) != raw {
		t.Fatalf("sync changed component policy: %s, %v", got, err)
	}
}

func TestSyncPolyglotNativeScaffold(t *testing.T) {
	var out, stderr bytes.Buffer
	args := []string{"sync", "--check", "--offline", "--dir", filepath.Join("..", "..", "examples", "polyglot-native")}
	if got := Run(args, &out, &stderr); got != 0 || strings.Contains(out.String(), "stale_component") {
		t.Fatalf("config-only example reported actionable drift: exit=%d stdout=%s stderr=%s", got, &out, &stderr)
	}
}
