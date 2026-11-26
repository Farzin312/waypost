package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/presets"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/repowrite"
	"github.com/Farzin312/waypost/internal/syncer"
	"github.com/Farzin312/waypost/internal/upgrade"
	"github.com/Farzin312/waypost/internal/verify"
	"github.com/Farzin312/waypost/internal/version"
	"gopkg.in/yaml.v3"
)

const (
	agentsBeginMarker = "<!-- waypost:begin -->"
	agentsEndMarker   = "<!-- waypost:end -->"
)

// Run executes the waypost CLI with the given arguments and IO writers, returning an exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}
	sub := args[0]
	rest := args[1:]

	var err error
	switch sub {
	case "init":
		err = runInit(rest, stdout)
	case "spec":
		err = runSpec(rest, stdout)
	case "history":
		err = runHistory(rest, stdout)
	case "pins":
		err = runPins(rest, stdout)
	case "context":
		err = runContext(rest, stdout)
	case "graph":
		return runGraph(rest, stdout, stderr)
	case "sync":
		return runSync(rest, stdout, stderr)
	case "verify":
		return runVerify(rest, stdout, stderr)
	case "upgrade":
		err = runUpgrade(rest, stdout)
	case "version", "--version", "-v":
		err = runVersion(rest, stdout)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "waypost: unknown command %q\n\n", sub)
		printUsage(stderr)
		return 2
	}

	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "waypost %s: %v\n", sub, err)
		return 1
	}
	return 0
}

func parseCommandFlags(f *flag.FlagSet, args []string, help io.Writer) error {
	f.SetOutput(io.Discard)
	f.Usage = func() {
		fmt.Fprintf(help, "Usage of waypost %s:\n", f.Name())
		f.SetOutput(help)
		f.PrintDefaults()
		f.SetOutput(io.Discard)
	}
	return f.Parse(args)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `waypost — agent-first repository orientation, inheritable policy, and deterministic verification

Usage:
  waypost init    [--preset auto|base|app-ts|polyglot-native] [--from-bounds] [--claude-md] [--ci] [--dir .] [--force]
  waypost spec    [--component <id>] [--ref <ref>] [--history [--since YYYY-MM-DD] [--limit N]] [--receipt <path>] [--format text|markdown|json] [--dir .]
  waypost history [--ref <ref>] [--component <id>] [--since YYYY-MM-DD] [--trust-only] [--all-parents] [--limit N] [--cursor <token>] [--format text|markdown|json] [--dir .]
  waypost pins    [--repo <dir@ref> ...] [--format text|markdown|json] [--dir .]
  waypost context [--changed] [--base <ref>] [--recent N] [--offline] [--providers] [--format text|json] [--dir .]
  waypost graph   [--changed] [--base <ref>] [--check-boundaries] [--update-baseline] [--mermaid] [--offline] [--format text|json] [--dir .]
  waypost verify  [--mode local|ci] [--base <ref>] [--frozen] [--offline] [--all] [--jobs N] [--allow-bootstrap] [--providers] [--receipt <path>] [--markdown <path>] [--format text|json] [--dir .]
  waypost sync    [--apply | --check] [--ref <ref>] [--offline] [--format text|json] [--dir .]
  waypost upgrade [--to <ref> | --target <ref>] [--dry-run] [--apply] [--offline] [--format text|json] [--dir .]
  waypost version [--format text|json]

Docs & schemas: https://github.com/Farzin312/waypost`)
}

func runVersion(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text or json")
	if err := parseCommandFlags(fs, args, stdout); err != nil {
		return err
	}
	info := version.Current()
	if *format == "json" {
		return writeJSON(stdout, info)
	}
	fmt.Fprintf(stdout, "waypost %s (commit %s)\nschema_version: %s\nresolver_version: %s\ngo: %s (%s)\n",
		info.CLIVersion, info.Commit, info.SchemaVersion, info.ResolverVersion, info.GoVersion, info.Platform)
	return nil
}

func runInit(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root directory")
	presetName := fs.String("preset", "auto", "preset: auto, base, app-ts, or polyglot-native")
	fromBounds := fs.Bool("from-bounds", false, "migrate legacy .bounds/ manifests and rules natively into .waypost.yaml")
	claudeMD := fs.Bool("claude-md", false, "also create a minimal CLAUDE.md pointer to AGENTS.md if absent")
	ci := fs.Bool("ci", false, "generate a GitHub Actions workflow")
	force := fs.Bool("force", false, "overwrite existing Waypost configuration and generated workflow")
	if err := parseCommandFlags(fs, args, stdout); err != nil {
		return err
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	tx, close, err := repowrite.Acquire(absDir)
	if err != nil {
		return err
	}
	defer close()
	oldConfig, err := repowrite.Read(absDir, config.ConfigFileName)
	if err != nil {
		return err
	}
	if !*force && oldConfig != nil {
		return fmt.Errorf("%s already exists (use --force to overwrite)", filepath.Join(absDir, config.ConfigFileName))
	}
	oldLock, err := repowrite.Read(absDir, lockfile.LockFileName)
	if err != nil {
		return err
	}

	// Safely infer manifests and ecosystem without running any repo code.
	view, err := repoview.Working(absDir)
	if err != nil {
		return err
	}
	inferredMap, err := compmap.BuildWithOptions(absDir, nil, nil, compmap.BuildOptions{View: view})
	if err != nil {
		return err
	}

	chosen := *presetName
	if chosen == "" || chosen == "auto" {
		chosen = choosePreset(view, inferredMap)
	}
	pRef, err := presets.Resolve("builtin:" + chosen)
	if err != nil {
		return err
	}

	repoName := filepath.Base(absDir)
	initCfg := config.Config{
		SchemaVersion: version.SchemaVersion,
		Name:          repoName,
		Extends:       pRef.Ref,
	}

	// Seed inferred components, or translate legacy `.bounds/` cleanly when --from-bounds is set.
	boundsCount := 0
	var migrationWarnings []string
	migratedBounds := false
	if *fromBounds {
		bm, err := archgraph.MigrateFromBounds(absDir)
		if err != nil {
			return err
		}
		initCfg.Components = append(initCfg.Components, bm.Components...)
		initCfg.Boundaries = bm.Boundaries
		boundsCount = bm.Subsystems
		migrationWarnings = bm.Warnings
		migratedBounds = true
	} else {
		for _, c := range inferredMap.Components {
			if c.Provenance == compmap.ProvenanceToolObserved {
				boundsCount++
				continue
			}
			initCfg.Components = append(initCfg.Components, config.ComponentConfig{
				ID:          c.ID,
				Root:        c.Root,
				Kind:        c.Kind,
				Language:    c.Language,
				Description: c.Description,
				DependsOn:   c.DependsOn,
				Entrypoints: c.Entrypoints,
				Paths:       c.Paths,
			})
		}
	}
	initCfg.Checks = inferStarterChecks(view, inferredMap)
	if chosen == "app-ts" {
		for _, id := range []string{"ts-typecheck", "ts-test"} {
			if !slices.ContainsFunc(initCfg.Checks, func(c config.Check) bool { return c.ID == id }) {
				initCfg.DisableChecks = append(initCfg.DisableChecks, id)
			}
		}
	}
	var baseline []byte
	if !*fromBounds {
		if err := completeStarterOwnership(view, &initCfg); err != nil {
			return err
		}
		var warning string
		baseline, warning, err = starterBoundaries(view, &initCfg)
		if err != nil {
			return err
		}
		if warning != "" {
			migrationWarnings = append(migrationWarnings, warning)
		}
	}
	var workflow []byte
	if *ci {
		workflow, err = repowrite.Read(absDir, starterWorkflowPath)
		if err != nil {
			return err
		}
	}

	raw, err := yaml.Marshal(&initCfg)
	if err != nil {
		return err
	}
	header := "# Waypost v1 repository contract. See https://github.com/Farzin312/waypost\n"
	raw = append([]byte(header), raw...)
	resolved, err := config.Load(absDir, config.LoadOptions{Mode: "ci", HasRootBytes: true, OverrideRootRaw: raw})
	if err != nil {
		return err
	}
	lockBytes, err := lockfile.Marshal(lockfile.Generate(resolved))
	if err != nil {
		return err
	}
	_, lockDigest, err := lockfile.ParseBytes(lockBytes)
	if err != nil {
		return err
	}
	mutations := []repowrite.Mutation{
		{Path: config.ConfigFileName, Old: oldConfig, New: raw},
		{Path: lockfile.LockFileName, Old: oldLock, New: lockBytes},
	}
	if baseline != nil {
		rel := config.DefaultBaselinePath
		old, err := repowrite.Read(absDir, rel)
		if err != nil {
			return err
		}
		if old != nil && !*force {
			return fmt.Errorf("%s already exists (use --force to overwrite)", rel)
		}
		mutations = append(mutations, repowrite.Mutation{Path: rel, Old: old, New: baseline})
	}
	if err := tx.Commit(mutations...); err != nil {
		return err
	}
	if *ci && (workflow == nil || *force) {
		if err := tx.Commit(repowrite.Mutation{Path: starterWorkflowPath, Old: workflow, New: starterWorkflow(view, initCfg.Checks)}); err != nil {
			return err
		}
	}

	// Update or create compact AGENTS.md pointer block.
	agentsUpdated, err := ensureAgentsPointer(absDir)
	if err != nil {
		return err
	}
	claudeNote := ""
	if *claudeMD {
		claudePath := filepath.Join(absDir, "CLAUDE.md")
		if _, err := os.Lstat(claudePath); errors.Is(err, os.ErrNotExist) {
			f, err := os.OpenFile(claudePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			_, wErr := f.WriteString("@AGENTS.md\n")
			cErr := f.Close()
			if wErr != nil {
				return wErr
			}
			if cErr != nil {
				return cErr
			}
			claudeNote = "created (@AGENTS.md)"
		} else {
			claudeNote = "preserved existing CLAUDE.md"
		}
	}

	fmt.Fprintf(stdout, "Initialized waypost in %s\n", absDir)
	fmt.Fprintf(stdout, "  preset:     %s\n", pRef.Ref)
	fmt.Fprintf(stdout, "  components: %d declared", len(initCfg.Components))
	if migratedBounds {
		fmt.Fprintf(stdout, " (migrated %d subsystems + native boundaries from legacy .bounds/)", boundsCount)
	} else if boundsCount > 0 {
		fmt.Fprintf(stdout, " (+ %d legacy .bounds subsystems detected; run with --from-bounds to migrate natively)", boundsCount)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  config:     %s\n", config.ConfigFileName)
	fmt.Fprintf(stdout, "  lockfile:   %s (sha256: %s)\n", lockfile.LockFileName, shortHash(lockDigest))
	fmt.Fprintf(stdout, "  AGENTS.md:  %s\n", agentsUpdated)
	if initCfg.Boundaries.IsEnabled() {
		fmt.Fprintf(stdout, "  boundaries: %s\n", initCfg.Boundaries.EffectiveMode())
	}
	if *ci {
		fmt.Fprintf(stdout, "  workflow:   %s\n", starterWorkflowPath)
	}
	for _, warning := range migrationWarnings {
		fmt.Fprintf(stdout, "  Warning: %s\n", warning)
	}
	if claudeNote != "" {
		fmt.Fprintf(stdout, "  CLAUDE.md:  %s\n", claudeNote)
	}
	return nil
}

func choosePreset(view *repoview.View, cm *compmap.Map) string {
	var hasCPP, hasTS, hasPython bool
	for _, c := range cm.Components {
		switch c.Language {
		case "cpp":
			hasCPP = true
		case "python":
			hasPython = true
		case "typescript", "javascript":
			hasTS = true
		}
	}
	if hasCPP || hasPython && hasDirectory(view, "tools") {
		return "polyglot-native"
	}
	if hasTS {
		scripts := starterScripts(view, "package.json")
		if typecheckScript(scripts) != "" && scripts["test"] != "" {
			return "app-ts"
		}
	}
	return "base"
}

func starterScripts(view *repoview.View, name string) map[string]string {
	var pkg struct{ Scripts map[string]string }
	raw, err := view.Read(name, compmap.MaxStaticDiscoveryBytes)
	if err != nil || json.Unmarshal(raw, &pkg) != nil {
		return nil
	}
	return pkg.Scripts
}

func typecheckScript(scripts map[string]string) string {
	for _, script := range []string{"typecheck", "type-check", "check-types", "types"} {
		if strings.TrimSpace(scripts[script]) != "" {
			return script
		}
	}
	return ""
}

var pytestDependency = regexp.MustCompile(`(?i)\bpytest\b`)
var ruffTable = regexp.MustCompile(`(?m)^\s*\[tool\.ruff(?:[.\]])`)

func inferStarterChecks(view *repoview.View, cm *compmap.Map) []config.Check {
	var checks []config.Check
	used := make(map[string]int)
	add := func(dir, id, command, bin string, required bool, timeout int, patterns ...string) {
		used[id]++
		if used[id] > 1 {
			id = fmt.Sprintf("%s-%d", id, used[id])
		}
		paths := make([]string, len(patterns))
		for i, pattern := range patterns {
			paths[i] = path.Join(dir, pattern)
		}
		workdir := dir
		if workdir == "." {
			workdir = ""
		}
		checks = append(checks, config.Check{ID: id, Command: command, RequiresBin: bin, Paths: paths, Workdir: workdir, Required: config.BoolPtr(required), TimeoutSeconds: timeout})
	}
	roots := view.Paths()
	hasPython := slices.ContainsFunc(roots, func(rel string) bool { return strings.HasSuffix(rel, ".py") })
	pythonRoots := map[string]bool{}
	pm := starterPackageManager(view, ".", cm.Ecosystem.PackageManager)
	tsPaths := []string{"**/*.ts", "**/*.tsx", "**/*.mts", "**/*.cts", "tsconfig*.json", "package.json"}
	jsPaths := append(slices.Clone(tsPaths), "**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs")
	// Root checks keep their conventional IDs when multiple workspaces use the same runner.
	slices.SortStableFunc(roots, func(a, b string) int {
		if path.Dir(a) == "." && path.Dir(b) != "." {
			return -1
		}
		if path.Dir(b) == "." && path.Dir(a) != "." {
			return 1
		}
		return strings.Compare(a, b)
	})
	for _, rel := range roots {
		if !view.Files[rel].Regular() {
			continue
		}
		dir := path.Dir(rel)
		base := path.Base(rel)
		if !compmap.StaticComponentInput(rel) && base != "pytest.ini" && base != "setup.cfg" {
			continue
		}
		switch base {
		case "package.json":
			pm := starterPackageManager(view, dir, pm)
			scripts := starterScripts(view, rel)
			if script := typecheckScript(scripts); script != "" {
				add(dir, "ts-typecheck", pm+" run "+script, pm, true, 180, tsPaths...)
			}
			if strings.TrimSpace(scripts["test"]) != "" {
				command := pm + " test"
				if pm == "bun" {
					command = "bun run test"
				}
				add(dir, "ts-test", command, pm, true, 300, jsPaths...)
			}
			if strings.TrimSpace(scripts["lint"]) != "" {
				add(dir, "lint", pm+" run lint", pm, false, 180, jsPaths...)
			}
		case "go.mod":
			add(dir, "go-vet", "go vet ./...", "go", true, 120, "**/*.go", "go.mod", "go.sum")
			add(dir, "go-test", "go test ./...", "go", true, 180, "**/*.go", "go.mod", "go.sum")
		case "Cargo.toml":
			add(dir, "cargo-test", "cargo test", "cargo", true, 300, "**/*.rs", "Cargo.toml", "Cargo.lock")
		case "pyproject.toml", "pytest.ini", "setup.cfg":
			pythonRoots[dir] = true
		}
	}
	if hasPython {
		pythonRoots["."] = true
	}
	for _, dir := range sortedStarterRoots(pythonRoots) {
		exists := func(rel string) bool { return view.Files[path.Join(dir, rel)].Regular() }
		pyproject, _ := view.Read(path.Join(dir, "pyproject.toml"), compmap.MaxStaticDiscoveryBytes)
		setup, _ := view.Read(path.Join(dir, "setup.cfg"), compmap.MaxStaticDiscoveryBytes)
		switch {
		case exists("pytest.ini") || exists("conftest.py") || exists("tests/conftest.py") || pytestDependency.Match(pyproject) || strings.Contains(string(setup), "[tool:pytest]"):
			add(dir, "python-test", "pytest", "pytest", true, 180, "**/*.py", "pyproject.toml", "pytest.ini")
		case hasDirectory(view, path.Join(dir, "tests")):
			add(dir, "python-test", "python3 -m unittest discover -s tests", "python3", true, 180, "**/*.py", "pyproject.toml")
		}
		if exists("ruff.toml") || exists(".ruff.toml") || ruffTable.Match(pyproject) {
			add(dir, "ruff", "ruff check .", "ruff", false, 180, "**/*.py", "pyproject.toml", "ruff.toml", ".ruff.toml")
		}
	}
	return checks
}

func sortedStarterRoots(roots map[string]bool) []string {
	dirs := make([]string, 0, len(roots))
	for dir := range roots {
		dirs = append(dirs, dir)
	}
	slices.Sort(dirs)
	return dirs
}

func hasDirectory(view *repoview.View, dir string) bool {
	// A clone has files for each directory. Also handle an empty local scaffold.
	for name := range view.Files {
		if strings.HasPrefix(name, dir+"/") {
			return true
		}
	}
	info, err := os.Lstat(filepath.Join(view.Repo, filepath.FromSlash(dir)))
	return err == nil && info.IsDir()
}

func completeStarterOwnership(view *repoview.View, cfg *config.Config) error {
	cm, err := compmap.BuildWithOptions(view.Repo, cfg, nil, compmap.BuildOptions{View: view})
	if err != nil {
		return err
	}
	for rel, file := range view.Files {
		if !file.Regular() || !archgraph.IsSupportedSource(rel) || len(cm.OwnersOf(rel)) != 0 {
			continue
		}
		id := "source"
		for n := 2; slices.ContainsFunc(cfg.Components, func(c config.ComponentConfig) bool { return c.ID == id }); n++ {
			id = fmt.Sprintf("source-%d", n)
		}
		cfg.Components = append(cfg.Components, config.ComponentConfig{ID: id, Root: ".", Paths: []string{"**"}})
		break
	}
	return nil
}

func starterBoundaries(view *repoview.View, cfg *config.Config) ([]byte, string, error) {
	if len(cfg.Components) == 0 {
		return nil, "", nil
	}
	cm, err := compmap.BuildWithOptions(view.Repo, cfg, nil, compmap.BuildOptions{View: view})
	if err != nil {
		return nil, "", err
	}
	bounds := &config.BoundariesConfig{Enabled: config.BoolPtr(true), Mode: "enforce", NoCycles: config.BoolPtr(true), EnforceDeclaredDeps: config.BoolPtr(true)}
	report, err := archgraph.AnalyzeWithOptions(view.Repo, cm, bounds, archgraph.AnalyzeOptions{View: view})
	if err != nil {
		return nil, "", err
	}
	if len(report.ScanErrors) > 0 {
		return nil, "boundary scan incomplete: " + report.ScanErrors[0], nil
	}
	if report.FilesScanned == 0 {
		return nil, "", nil
	}
	cfg.Boundaries = bounds
	if len(report.Violations) == 0 {
		return nil, "", nil
	}
	bounds.Mode = "ratchet"
	cfg.Policy.TrustPaths = append(cfg.Policy.TrustPaths, config.DefaultBaselinePath)
	raw, err := archgraph.EncodeBaseline(report.Violations)
	return raw, "", err
}

func ensureAgentsPointer(repoDir string) (string, error) {
	agentsPath := filepath.Join(repoDir, "AGENTS.md")
	block := strings.Join([]string{
		agentsBeginMarker,
		"## Waypost Contract",
		"",
		"- Run `waypost context --changed` to orient and resume work.",
		"- Use `waypost spec --component ID` and `waypost history` for contracts and their changes.",
		"- Inspect architecture with `waypost graph` and reconcile policy with `waypost sync --apply`.",
		"- Run `waypost verify` before reporting completion. Policy lives in `.waypost.yaml` and `.waypost.lock`.",
		agentsEndMarker,
	}, "\n")

	existing, err := os.ReadFile(agentsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			content := "# AGENTS.md\n\n" + block + "\n"
			if err := os.WriteFile(agentsPath, []byte(content), 0o644); err != nil {
				return "", err
			}
			return "created with waypost pointer block", nil
		}
		return "", err
	}

	text := string(existing)
	startIdx := strings.Index(text, agentsBeginMarker)
	endIdx := strings.Index(text, agentsEndMarker)
	var updated string
	if startIdx >= 0 && endIdx > startIdx {
		updated = text[:startIdx] + block + text[endIdx+len(agentsEndMarker):]
	} else {
		sep := "\n\n"
		if strings.HasSuffix(text, "\n") {
			sep = "\n"
		}
		updated = text + sep + block + "\n"
	}
	if err := os.WriteFile(agentsPath, []byte(updated), 0o644); err != nil {
		return "", err
	}
	return "updated pointer block (existing instructions preserved)", nil
}

// ContextOutput is the versioned JSON payload emitted by `waypost context`.
type ContextOutput struct {
	Snapshot          repoview.Identity        `json:"snapshot"`
	SchemaVersion     string                   `json:"schema_version"`
	ResolverVersion   string                   `json:"resolver_version"`
	CLIVersion        string                   `json:"cli_version"`
	Configured        bool                     `json:"configured"`
	RepoName          string                   `json:"repo_name"`
	Extends           string                   `json:"extends,omitempty"`
	Chain             []config.InheritanceStep `json:"chain,omitempty"`
	PolicyDigest      string                   `json:"policy_digest,omitempty"`
	Lock              *lockfile.VerifyResult   `json:"lock,omitempty"`
	Rules             []config.Rule            `json:"rules,omitempty"`
	Components        []compmap.Component      `json:"components"`
	Pins              []config.CrossRepoPin    `json:"pins,omitempty"`
	Checks            []config.Check           `json:"checks,omitempty"`
	Skills            []config.SkillRef        `json:"skills,omitempty"`
	Ecosystem         compmap.EcosystemInfo    `json:"ecosystem"`
	Architecture      *ContextArchitecture     `json:"architecture,omitempty"`
	ProviderStatuses  []compmap.ProviderStatus `json:"provider_statuses,omitempty"`
	UnmappedPaths     []string                 `json:"unmapped_paths,omitempty"`
	UnmappedTruncated int                      `json:"unmapped_truncated,omitempty"`
	CoverageGaps      []string                 `json:"coverage_gaps,omitempty"`
	SyncDrift         []syncer.Item            `json:"sync_drift,omitempty"`
}

type ContextArchitecture struct {
	FilesScanned          int                    `json:"files_scanned"`
	ImportsScanned        int                    `json:"imports_scanned"`
	ObservedEdges         int                    `json:"observed_edges"`
	BoundariesMode        string                 `json:"boundaries_mode"`
	Hubs                  []string               `json:"hubs,omitempty"`
	CycleCount            int                    `json:"cycle_count"`
	ViolationCount        int                    `json:"violation_count"`
	GrandfatheredCount    int                    `json:"grandfathered_count,omitempty"`
	ResolvedBaselineCount int                    `json:"resolved_baseline_count,omitempty"`
	BlastRadius           *archgraph.BlastRadius `json:"blast_radius,omitempty"`
}

func runContext(args []string, stdout io.Writer) error {
	f := flag.NewFlagSet("context", flag.ContinueOnError)
	dir := f.String("dir", ".", "repository root directory")
	changed := f.Bool("changed", false, "show bounded change impact")
	base := f.String("base", "", "base ref for change attribution")
	recent := f.Int("recent", 2, "show N unique recent commit subjects")
	offline := f.Bool("offline", false, "restrict remote preset resolution to the verified cache")
	providers := f.Bool("providers", false, "explicitly enable authorized canonical legacy providers")
	format := f.String("format", "text", "text or json")
	if err := parseCommandFlags(f, args, stdout); err != nil {
		return err
	}
	if *recent < 0 || (*format != "text" && *format != "json") || f.NArg() != 0 {
		return errors.New("invalid context arguments")
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	view, err := repoview.Working(abs)
	if err != nil {
		return err
	}
	p, err := project.Load(view, config.LoadOptions{Mode: "local", Offline: *offline, RequirePinnedRemote: *offline, ReadOnly: true}, compmap.BuildOptions{})
	if err != nil {
		return err
	}
	var lock *lockfile.VerifyResult
	canonical := p.Policy
	if p.Policy != nil {
		if p.Policy.LocalOverrideApplied {
			canonical, err = config.Load(abs, config.LoadOptions{
				Mode: "ci", Offline: *offline, RequirePinnedRemote: *offline, ReadOnly: true,
				PinnedBuiltins: lockfile.PinnedBuiltins(p.Lock), PinnedRemoteSHAs: lockfile.PinnedRemoteSHAs(p.Lock),
			})
			if err != nil {
				return err
			}
		}
		status := lockfile.VerifyResult{}
		if p.Lock != nil {
			status = lockfile.VerifyParsed(p.Lock, p.LockDigest, canonical)
		} else {
			status.Mismatches = []string{"lockfile missing"}
		}
		lock = &status
	}
	if *changed {
		return changedContext(stdout, p, lock, *base, *recent, *format)
	}
	if *providers && lock != nil && lock.Valid && !p.Policy.LocalOverrideApplied {
		p.Map, err = compmap.BuildWithOptions(abs, p.Config(), view.Paths(), compmap.BuildOptions{View: view, AllowProviders: true})
		if err != nil {
			return err
		}
	}
	v := version.Current()
	out := ContextOutput{
		Snapshot: view.Identity, SchemaVersion: v.SchemaVersion, ResolverVersion: v.ResolverVersion,
		CLIVersion: v.CLIVersion, RepoName: filepath.Base(abs), Configured: p.Policy != nil, Lock: lock,
		Components: p.Map.Components, Pins: p.Map.Pins, Ecosystem: p.Map.Ecosystem, ProviderStatuses: p.Map.ProviderStatuses,
		CoverageGaps: p.Map.CoverageGaps, UnmappedPaths: p.Map.UnmappedPaths,
	}
	maxItems := 50
	if p.Policy != nil {
		cfg := p.Config()
		out.RepoName = nonEmpty(cfg.Name, out.RepoName)
		out.Extends, out.Chain, out.PolicyDigest = cfg.Extends, p.Policy.Chain, p.Policy.PolicyDigest
		out.Rules, out.Checks, out.Skills = cfg.Rules, cfg.Checks, cfg.Skills
		maxItems = cfg.Policy.MaxContextItems
	} else {
		out.CoverageGaps = append(out.CoverageGaps, ".waypost.yaml not found; showing static manifest inference")
	}
	if len(out.UnmappedPaths) > maxItems {
		out.UnmappedTruncated = len(out.UnmappedPaths) - maxItems
		out.UnmappedPaths = out.UnmappedPaths[:maxItems]
	}
	rep, err := p.Graph()
	if err != nil {
		out.CoverageGaps = append(out.CoverageGaps, "architecture scan: "+err.Error())
	} else {
		out.Architecture = &ContextArchitecture{
			FilesScanned: rep.FilesScanned, ImportsScanned: rep.ImportsScanned, ObservedEdges: len(rep.Edges),
			BoundariesMode: rep.BoundariesMode, Hubs: rep.Hubs, CycleCount: len(rep.Cycles), ViolationCount: len(rep.Violations),
			GrandfatheredCount: rep.GrandfatheredCount, ResolvedBaselineCount: rep.ResolvedBaselineCount,
		}
		out.CoverageGaps = append(out.CoverageGaps, rep.ScanErrors...)
	}
	if canonical != nil {
		cm := p.Map
		if canonical != p.Policy || *providers {
			rep, cm = nil, nil
		}
		items, err := syncer.Check(view, canonical, cm, rep)
		if err != nil {
			out.CoverageGaps = append(out.CoverageGaps, "sync drift inspection: "+err.Error())
		}
		for _, item := range items {
			if item.Actionable() && len(out.SyncDrift) < maxItems {
				out.SyncDrift = append(out.SyncDrift, item)
			}
		}
	}
	if *format == "json" {
		return writeJSON(stdout, &out)
	}
	renderContextText(stdout, &out)
	return nil
}

func renderContextText(w io.Writer, o *ContextOutput) {
	safe := func(s string) string { return safeText(clip(s, 512), true) }
	fmt.Fprintf(w, "Waypost Context: %s (configured=%v, schema=%s)\n", safe(o.RepoName), o.Configured, safe(o.SchemaVersion))
	if o.Extends != "" {
		fmt.Fprintf(w, "  extends: %s | policy_digest: %s\n", safe(o.Extends), safe(shortHash(o.PolicyDigest)))
	}
	if o.Lock != nil {
		fmt.Fprintf(w, "  lock:    valid=%v (sha256=%s)\n", o.Lock.Valid, safe(shortHash(o.Lock.LockDigest)))
	}

	var ecoTags []string
	if o.Ecosystem.HasAgentsMD {
		ecoTags = append(ecoTags, "AGENTS.md")
	}
	if o.Ecosystem.HasClaudeMD {
		ecoTags = append(ecoTags, "CLAUDE.md")
	}
	if o.Ecosystem.HasBounds {
		ecoTags = append(ecoTags, ".bounds")
	}
	if o.Ecosystem.HasGitleaks {
		ecoTags = append(ecoTags, "gitleaks")
	}
	if o.Ecosystem.HasGitHubWorkflows {
		ecoTags = append(ecoTags, "github-actions")
	}
	if o.Ecosystem.PackageManager != "" {
		ecoTags = append(ecoTags, "pm="+safe(o.Ecosystem.PackageManager))
	}
	if len(ecoTags) > 0 {
		fmt.Fprintf(w, "  ecosystem: %s\n", strings.Join(ecoTags, ", "))
	}
	if o.Architecture != nil {
		fmt.Fprintf(w, "  arch_graph: files=%d imports=%d edges=%d cycles=%d violations=%d (boundaries=%s)\n",
			o.Architecture.FilesScanned, o.Architecture.ImportsScanned, o.Architecture.ObservedEdges,
			o.Architecture.CycleCount, o.Architecture.ViolationCount, safe(o.Architecture.BoundariesMode))
		if o.Architecture.BoundariesMode == "ratchet" {
			fmt.Fprintf(w, "  baseline: %d grandfathered, %d resolved\n", o.Architecture.GrandfatheredCount, o.Architecture.ResolvedBaselineCount)
		}
		if len(o.Architecture.Hubs) > 0 {
			fmt.Fprintf(w, "  arch_hubs:  %s\n", safe(strings.Join(o.Architecture.Hubs, ", ")))
		}
	}

	fmt.Fprintf(w, "\nComponents (%d):\n", len(o.Components))
	if len(o.Components) == 0 {
		fmt.Fprintln(w, "  (none inferred or declared)")
	}
	for _, c := range o.Components {
		fmt.Fprintf(w, "  - %s [%s, %s, provenance=%s] root=%s\n", safe(c.ID), safe(nonEmpty(c.Kind, "component")), safe(nonEmpty(c.Language, "unknown")), safe(c.Provenance), safe(c.Root))
		if len(c.DependsOn) > 0 {
			fmt.Fprintf(w, "      depends_on:  %s\n", safe(strings.Join(c.DependsOn, ", ")))
		}
		if len(c.DependedBy) > 0 {
			fmt.Fprintf(w, "      depended_by: %s\n", safe(strings.Join(c.DependedBy, ", ")))
		}
		if len(c.Entrypoints) > 0 {
			fmt.Fprintf(w, "      entrypoints: %s\n", safe(strings.Join(c.Entrypoints, ", ")))
		}
		if len(c.Checks) > 0 {
			fmt.Fprintf(w, "      checks:      %s\n", safe(strings.Join(c.Checks, ", ")))
		}
	}

	if len(o.Pins) > 0 {
		fmt.Fprintf(w, "\nCross-Repo Pins (%d):\n", len(o.Pins))
		for _, p := range o.Pins {
			fmt.Fprintf(w, "  - %s: producer=%s artifact=%s -> consumer=%s", safe(p.ID), safe(p.Producer), safe(p.Artifact), safe(p.Consumer))
			if p.CompatibilityCheck != "" {
				fmt.Fprintf(w, " (check=%s)", safe(p.CompatibilityCheck))
			}
			fmt.Fprintln(w)
		}
	}

	if len(o.Rules) > 0 {
		fmt.Fprintf(w, "\nRules (%d):\n", len(o.Rules))
		for _, r := range o.Rules {
			fmt.Fprintf(w, "  - [%s] %s: %s\n", safe(r.Kind), safe(r.ID), safe(r.Summary))
		}
	}

	if len(o.Checks) > 0 {
		fmt.Fprintf(w, "\nChecks (%d):\n", len(o.Checks))
		for _, c := range o.Checks {
			fmt.Fprintf(w, "  - %s (required=%v): %s\n", safe(c.ID), c.IsRequired(), safe(c.Command))
		}
	}

	if len(o.Ecosystem.DiscoveredSkills) > 0 {
		fmt.Fprintf(w, "\nDiscovered Local Skills (.agents/skills, %d):\n", len(o.Ecosystem.DiscoveredSkills))
		for _, sk := range o.Ecosystem.DiscoveredSkills {
			if sk.Description != "" {
				fmt.Fprintf(w, "  - %s (%s): %s\n", safe(sk.Name), safe(sk.Path), safe(sk.Description))
			} else {
				fmt.Fprintf(w, "  - %s (%s)\n", safe(sk.Name), safe(sk.Path))
			}
		}
	}

	if len(o.ProviderStatuses) > 0 {
		fmt.Fprintf(w, "\nProviders (%d):\n", len(o.ProviderStatuses))
		for _, ps := range o.ProviderStatuses {
			fmt.Fprintf(w, "  - %s (%s): authorized=%v executed=%v — %s\n", safe(ps.ID), safe(ps.Tool), ps.Authorized, ps.Executed, safe(ps.Note))
		}
	}

	if len(o.UnmappedPaths) > 0 {
		fmt.Fprintf(w, "\nUnmapped Tracked Paths (%d shown", len(o.UnmappedPaths))
		if o.UnmappedTruncated > 0 {
			fmt.Fprintf(w, ", +%d more", o.UnmappedTruncated)
		}
		fmt.Fprintln(w, "):")
		for _, p := range o.UnmappedPaths {
			fmt.Fprintf(w, "  - %s\n", safe(p))
		}
	}

	if len(o.CoverageGaps) > 0 {
		fmt.Fprintf(w, "\nCoverage Gaps (%d):\n", len(o.CoverageGaps))
		for _, g := range o.CoverageGaps {
			fmt.Fprintf(w, "  - %s\n", safe(g))
		}
	}

	if len(o.SyncDrift) > 0 {
		fmt.Fprintln(w, "\nSync drift:")
		for _, item := range o.SyncDrift {
			fmt.Fprintf(w, "  - %s (%s)\n", safe(item.Detail), safe(item.Hint))
		}
	}

}

func runGraph(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root directory")
	changed := fs.Bool("changed", false, "compute file-level and component-level blast radius for git diff")
	base := fs.String("base", "", "base git ref for --changed")
	checkBounds := fs.Bool("check-boundaries", false, "enforce configured boundaries and exit non-zero on violations")
	updateBaseline := fs.Bool("update-baseline", false, "replace the baseline with live violations, including an empty baseline when clean")
	mermaid := fs.Bool("mermaid", false, "render live observed architecture as a Mermaid flowchart")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	format := fs.String("format", "text", "output format: text or json")
	if err := parseCommandFlags(fs, args, stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "waypost graph: %v\n", err)
		return 2
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "waypost graph: %v\n", err)
		return 1
	}

	var tx *repowrite.Transaction
	if *updateBaseline {
		var close func()
		tx, close, err = repowrite.Acquire(absDir)
		if err != nil {
			fmt.Fprintf(stderr, "waypost graph: %v\n", err)
			return 1
		}
		defer close()
	}

	var snap *gitdiff.Snapshot
	if *changed {
		snap, err = gitdiff.Inspect(absDir, *base, "local")
		if err != nil {
			fmt.Fprintf(stderr, "waypost graph: %v\n", err)
			return 1
		}
		if snap.MergeBaseError != "" {
			fmt.Fprintf(stderr, "waypost graph: %s\n", snap.MergeBaseError)
			return 1
		}
	}

	var cfgPtr *config.Config
	var bCfg *config.BoundariesConfig
	if _, err := os.Stat(filepath.Join(absDir, config.ConfigFileName)); err == nil {
		existingLock, _, _ := lockfile.Read(absDir)
		mode := "local"
		if *updateBaseline {
			mode = "ci"
		}
		res, err := config.Load(absDir, config.LoadOptions{
			Mode:                mode,
			PinnedRemoteSHAs:    lockfile.PinnedRemoteSHAs(existingLock),
			PinnedBuiltins:      lockfile.PinnedBuiltins(existingLock),
			RequirePinnedRemote: *offline,
			Offline:             *offline,
		})
		if err != nil {
			fmt.Fprintf(stderr, "waypost graph: %v\n", err)
			return 1
		}
		cfgPtr = &res.Effective
		bCfg = res.Effective.Boundaries
	}
	if *updateBaseline && !bCfg.IsEnabled() {
		fmt.Fprintln(stderr, "waypost graph: --update-baseline requires enabled boundaries")
		return 1
	}
	if *checkBounds && !bCfg.IsEnabled() {
		if bCfg == nil {
			bCfg = &config.BoundariesConfig{}
		}
		bCfg.Enabled = config.BoolPtr(true)
	}

	view, err := repoview.Working(absDir)
	if err != nil {
		fmt.Fprintf(stderr, "waypost graph: %v\n", err)
		return 1
	}
	cm, err := compmap.BuildWithOptions(absDir, cfgPtr, nil, compmap.BuildOptions{View: view})
	if err != nil {
		fmt.Fprintf(stderr, "waypost graph: %v\n", err)
		return 1
	}

	var rep *archgraph.Report
	if *updateBaseline {
		rep, err = updateGraphBaseline(view, cm, bCfg, tx, stderr)
	} else {
		rep, err = archgraph.AnalyzeWithOptions(absDir, cm, bCfg, archgraph.AnalyzeOptions{View: view})
	}
	if err != nil {
		fmt.Fprintf(stderr, "waypost graph: %v\n", err)
		return 1
	}

	if snap != nil {
		br := rep.ComputeBlastRadius(snap.AffectedPaths)
		rep.Blast = &br
	}

	switch {
	case *mermaid:
		fmt.Fprint(stdout, archgraph.RenderMermaid(rep))
		if *checkBounds {
			for _, v := range rep.Violations {
				fmt.Fprintf(stderr, "waypost graph: [%s] %s\n", v.Severity, v.Message)
			}
		}
	case *format == "json":
		if err := writeJSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "waypost graph: %v\n", err)
			return 1
		}
	default:
		fmt.Fprint(stdout, archgraph.RenderText(rep))
	}

	if *checkBounds && len(rep.Violations) > 0 && bCfg.EffectiveMode() != "warn" {
		return 1
	}
	return 0
}

func updateGraphBaseline(view *repoview.View, cm *compmap.Map, boundaries *config.BoundariesConfig, tx *repowrite.Transaction, stderr io.Writer) (*archgraph.Report, error) {
	repo := view.Repo
	rel := boundaries.BaselinePath()
	if err := config.ValidateBaselinePath(repo, rel); err != nil {
		return nil, err
	}
	old, err := repowrite.Read(repo, rel)
	if err != nil {
		return nil, err
	}
	report, err := archgraph.AnalyzeLive(repo, cm, boundaries, archgraph.AnalyzeOptions{View: view})
	if err != nil {
		return nil, err
	}
	if len(report.ScanErrors) > 0 {
		return nil, fmt.Errorf("cannot update baseline after an incomplete scan: %s", report.ScanErrors[0])
	}
	raw, err := archgraph.EncodeBaseline(report.Violations)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(repowrite.Mutation{Path: rel, Old: old, New: raw}); err != nil {
		return nil, err
	}
	baseline, err := archgraph.ParseBaseline(raw)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "waypost graph: wrote %d baseline entries to %s\n", len(baseline.Entries), rel)
	if report.BoundariesMode == "ratchet" {
		archgraph.EvaluateBoundariesWithBaseline(report, baseline)
	}
	return report, nil
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root directory")
	mode := fs.String("mode", "local", "verification authority: local or ci")
	base := fs.String("base", "", "base git ref for diff and policy floor")
	frozen := fs.Bool("frozen", false, "require committed .waypost.lock to match exactly")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	all := fs.Bool("all", false, "force full repository verification")
	jobs := fs.Int("jobs", min(2, runtime.NumCPU()), "maximum concurrent opted-in checks")
	bootstrap := fs.Bool("allow-bootstrap", false, "authorize first adoption without an event base")
	providers := fs.Bool("providers", false, "enable authorized legacy providers")
	receiptPath := fs.String("receipt", "", "optional path to write receipt.v1.json")
	markdownPath := fs.String("markdown", "", "optional path to write PR Markdown summary")
	format := fs.String("format", "text", "output format: text or json")
	if err := parseCommandFlags(fs, args, stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "waypost verify: %v\n", err)
		return 2
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "waypost verify: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *jobs < 1 || (*format != "text" && *format != "json") {
		fmt.Fprintln(stderr, "waypost verify: jobs must be positive and format must be text or json")
		return 2
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "waypost verify: %v\n", err)
		return 1
	}

	rec, err := verify.Run(absDir, verify.Options{
		Mode:    *mode,
		Base:    *base,
		Frozen:  *frozen,
		All:     *all,
		Offline: *offline,
		Jobs:    *jobs, AllowBootstrap: *bootstrap, Providers: *providers,
	})
	if err != nil {
		fmt.Fprintf(stderr, "waypost verify: %v\n", err)
		return 1
	}

	if *receiptPath != "" {
		if err := verify.WriteJSON(*receiptPath, rec); err != nil {
			fmt.Fprintf(stderr, "waypost verify: write receipt: %v\n", err)
			return 1
		}
	}
	if *markdownPath != "" {
		if err := verify.WriteArtifact(*markdownPath, []byte(verify.RenderMarkdown(rec))); err != nil {
			fmt.Fprintf(stderr, "waypost verify: write markdown: %v\n", err)
			return 1
		}
	}

	if *format == "json" {
		if err := writeJSON(stdout, rec); err != nil {
			fmt.Fprintf(stderr, "waypost verify: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprint(stdout, verify.RenderMarkdown(rec))
	}

	if rec.Summary.Outcome == verify.StatusFail {
		return 1
	}
	return 0
}

func runUpgrade(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root directory")
	to := fs.String("to", "", "new exact preset reference")
	target := fs.String("target", "", "optional new extends reference (e.g., builtin:app-ts@1.0.0, github:org/repo/preset.yaml@v1, or ../preset.yaml)")
	dryRun := fs.Bool("dry-run", true, "preview upgrade plan without modifying files")
	apply := fs.Bool("apply", false, "write updated .waypost.yaml and .waypost.lock")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	format := fs.String("format", "text", "output format: text or json")
	if err := parseCommandFlags(fs, args, stdout); err != nil {
		return err
	}
	_ = dryRun // --apply overrides default dry-run
	if *to != "" {
		if *target != "" && *target != *to {
			return errors.New("--to and --target differ")
		}
		*target = *to
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}

	plan, err := upgrade.Run(absDir, upgrade.Options{
		Target:  *target,
		Apply:   *apply,
		Offline: *offline,
	})
	if err != nil {
		return err
	}

	if *format == "json" {
		return writeJSON(stdout, plan)
	}

	modeLabel := "DRY-RUN"
	if plan.Applied {
		modeLabel = "APPLIED"
	}
	fmt.Fprintf(stdout, "Waypost Upgrade [%s] (changed=%v)\n", modeLabel, plan.Changed)
	fmt.Fprintf(stdout, "  extends:       %s -> %s\n", nonEmpty(plan.PreviousExtends, "(none)"), nonEmpty(plan.TargetExtends, "(none)"))
	fmt.Fprintf(stdout, "  policy_digest: %s -> %s\n", shortHash(plan.PreviousPolicyDigest), shortHash(plan.NewPolicyDigest))
	if plan.NewLockDigest != "" {
		fmt.Fprintf(stdout, "  lock_digest:   %s -> %s\n", shortHash(plan.PreviousLockDigest), shortHash(plan.NewLockDigest))
	}
	printList(stdout, "  added_rules", plan.AddedRules)
	printList(stdout, "  removed_rules", plan.RemovedRules)
	printList(stdout, "  changed_rules", plan.ChangedRules)
	printList(stdout, "  added_checks", plan.AddedChecks)
	printList(stdout, "  removed_checks", plan.RemovedChecks)
	printList(stdout, "  changed_checks", plan.ChangedChecks)
	if len(plan.Warnings) > 0 {
		fmt.Fprintln(stdout, "  Warnings:")
		for _, wn := range plan.Warnings {
			fmt.Fprintf(stdout, "    ! %s\n", wn)
		}
	}
	if len(plan.PermissionChanges) > 0 {
		fmt.Fprintln(stdout, "  WARNING — permission/authorization changes:")
		for _, pc := range plan.PermissionChanges {
			fmt.Fprintf(stdout, "    ! %s\n", pc)
		}
	}
	if !plan.Applied && plan.Changed {
		fmt.Fprintln(stdout, "\nRe-run with --apply to update .waypost.yaml and .waypost.lock.")
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printList(w io.Writer, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", label)
	for _, it := range items {
		fmt.Fprintf(w, "    - %s\n", it)
	}
}

func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "-"
	}
	return s
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
