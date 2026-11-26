package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/presets"
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
	case "context":
		err = runContext(rest, stdout)
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

	if err != nil {
		fmt.Fprintf(stderr, "waypost %s: %v\n", sub, err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `waypost — agent-first repository orientation, inheritable policy, and deterministic verification

Usage:
  waypost init    [--preset auto|base|app-ts|polyglot-native] [--claude-md] [--dir .] [--force]
  waypost context [--changed] [--base <ref>] [--offline] [--format text|json] [--dir .]
  waypost verify  [--mode local|ci] [--base <ref>] [--frozen] [--offline] [--all] [--receipt <path>] [--markdown <path>] [--format text|json] [--dir .]
  waypost upgrade [--target <ref>] [--dry-run] [--apply] [--offline] [--format text|json] [--dir .]
  waypost version [--format text|json]

Docs & schemas: https://github.com/Farzin312/waypost`)
}

func runVersion(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
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
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", ".", "repository root directory")
	presetName := fs.String("preset", "auto", "preset: auto, base, app-ts, or polyglot-native")
	claudeMD := fs.Bool("claude-md", false, "also create a minimal CLAUDE.md pointer to AGENTS.md if absent")
	force := fs.Bool("force", false, "overwrite existing .waypost.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(absDir, config.ConfigFileName)
	if !*force {
		if _, err := os.Stat(cfgPath); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", cfgPath)
		}
	}

	// Safely infer manifests and ecosystem without running any repo code.
	inferredMap, err := compmap.Build(absDir, nil, nil)
	if err != nil {
		return err
	}

	chosen := *presetName
	if chosen == "" || chosen == "auto" {
		chosen = choosePreset(absDir, inferredMap)
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

	// Seed inferred components (skip tool-observed `.bounds` subsystems so `.bounds/manifests/*.yaml`
	// remains the live single source of truth with zero duplication).
	hasGo := false
	hasRust := false
	boundsCount := 0
	for _, c := range inferredMap.Components {
		if c.Provenance == compmap.ProvenanceToolObserved {
			boundsCount++
			continue
		}
		if c.Language == "go" {
			hasGo = true
		}
		if c.Language == "rust" {
			hasRust = true
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

	// Seed checks accurately from real detected manifests without executing anything.
	initCfg.Checks = append(initCfg.Checks, inferStarterChecks(absDir, chosen, inferredMap, hasGo, hasRust)...)

	raw, err := yaml.Marshal(&initCfg)
	if err != nil {
		return err
	}
	header := "# Waypost v1 repository contract. See https://github.com/Farzin312/waypost\n"
	if err := os.WriteFile(cfgPath, append([]byte(header), raw...), 0o644); err != nil {
		return err
	}

	// Resolve & generate frozen .waypost.lock.
	resolved, err := config.Load(absDir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		return err
	}
	lockDigest, err := lockfile.Write(absDir, lockfile.Generate(resolved))
	if err != nil {
		return err
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
	if boundsCount > 0 {
		fmt.Fprintf(stdout, " (+ %d live .bounds subsystems auto-discovered)", boundsCount)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  config:     %s\n", config.ConfigFileName)
	fmt.Fprintf(stdout, "  lockfile:   %s (sha256: %s)\n", lockfile.LockFileName, shortHash(lockDigest))
	fmt.Fprintf(stdout, "  AGENTS.md:  %s\n", agentsUpdated)
	if claudeNote != "" {
		fmt.Fprintf(stdout, "  CLAUDE.md:  %s\n", claudeNote)
	}
	return nil
}

func choosePreset(absDir string, m *compmap.Map) string {
	hasCPP := false
	hasTS := false
	hasPython := false
	for _, c := range m.Components {
		switch c.Language {
		case "cpp":
			hasCPP = true
		case "python":
			hasPython = true
		case "typescript", "javascript":
			hasTS = true
		}
	}
	toolsInfo, toolsErr := os.Stat(filepath.Join(absDir, "tools"))
	hasToolsDir := toolsErr == nil && toolsInfo.IsDir()
	if hasCPP || (hasPython && hasToolsDir) {
		return "polyglot-native"
	}
	if hasTS {
		if pkgRaw, err := os.ReadFile(filepath.Join(absDir, "package.json")); err == nil {
			var pkg struct {
				Scripts map[string]string `json:"scripts"`
			}
			if json.Unmarshal(pkgRaw, &pkg) == nil {
				_, hasTC := pkg.Scripts["typecheck"]
				_, hasTest := pkg.Scripts["test"]
				if hasTC && hasTest {
					return "app-ts"
				}
			}
		}
	}
	return "base"
}

func inferStarterChecks(absDir, preset string, m *compmap.Map, hasGo, hasRust bool) []config.Check {
	var checks []config.Check

	// Inspect root package.json scripts so TypeScript/JS checks use the repo's real package manager & scripts.
	if pkgRaw, err := os.ReadFile(filepath.Join(absDir, "package.json")); err == nil {
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(pkgRaw, &pkg) == nil && len(pkg.Scripts) > 0 {
			pm := m.Ecosystem.PackageManager
			if pm == "" {
				pm = "npm"
			}
			runCmd := func(script string) string {
				if pm == "yarn" {
					return "yarn " + script
				}
				return pm + " run " + script
			}
			if _, ok := pkg.Scripts["typecheck"]; ok {
				checks = append(checks, config.Check{
					ID:             "ts-typecheck",
					Command:        runCmd("typecheck"),
					RequiresBin:    pm,
					Paths:          []string{"**/*.ts", "**/*.tsx", "tsconfig*.json", "package.json"},
					Required:       config.BoolPtr(true),
					TimeoutSeconds: 180,
					Description:    "TypeScript static type verification",
				})
			}
			if _, ok := pkg.Scripts["test"]; ok {
				testCmd := pm + " test"
				if pm == "bun" {
					testCmd = "bun run test"
				}
				checks = append(checks, config.Check{
					ID:             "ts-test",
					Command:        testCmd,
					RequiresBin:    pm,
					Paths:          []string{"**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "package.json"},
					Required:       config.BoolPtr(true),
					TimeoutSeconds: 300,
					Description:    "Unit and integration test suite",
				})
			}
			if _, ok := pkg.Scripts["lint"]; ok {
				checks = append(checks, config.Check{
					ID:             "lint",
					Command:        runCmd("lint"),
					RequiresBin:    pm,
					Paths:          []string{"**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "package.json"},
					Required:       config.BoolPtr(false),
					TimeoutSeconds: 180,
					Description:    "Static linter",
				})
			}
		}
	}

	if hasGo && preset == "base" {
		checks = append(checks,
			config.Check{
				ID:             "go-vet",
				Command:        "go vet ./...",
				RequiresBin:    "go",
				Paths:          []string{"**/*.go", "go.mod", "go.sum"},
				Required:       config.BoolPtr(true),
				TimeoutSeconds: 120,
				Description:    "Go static analysis",
			},
			config.Check{
				ID:             "go-test",
				Command:        "go test ./...",
				RequiresBin:    "go",
				Paths:          []string{"**/*.go", "go.mod", "go.sum"},
				Required:       config.BoolPtr(true),
				TimeoutSeconds: 180,
				Description:    "Go unit test suite",
			},
		)
	}

	if hasRust && preset == "base" {
		checks = append(checks, config.Check{
			ID:             "cargo-test",
			Command:        "cargo test",
			RequiresBin:    "cargo",
			Paths:          []string{"**/*.rs", "Cargo.toml", "Cargo.lock"},
			Required:       config.BoolPtr(true),
			TimeoutSeconds: 300,
			Description:    "Rust Cargo test suite",
		})
	}

	return checks
}

func ensureAgentsPointer(repoDir string) (string, error) {
	agentsPath := filepath.Join(repoDir, "AGENTS.md")
	block := strings.Join([]string{
		agentsBeginMarker,
		"## Waypost Contract",
		"",
		"This repository uses [waypost](https://github.com/Farzin312/waypost) for machine-readable architecture context and deterministic verification.",
		"",
		"- Orient before broad searches: `waypost context --changed`",
		"- Verify before claiming completion: `waypost verify`",
		"- Contract & inheritance: `.waypost.yaml` (locked in `.waypost.lock`)",
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
	ProviderStatuses  []compmap.ProviderStatus `json:"provider_statuses,omitempty"`
	UnmappedPaths     []string                 `json:"unmapped_paths,omitempty"`
	UnmappedTruncated int                      `json:"unmapped_truncated,omitempty"`
	CoverageGaps      []string                 `json:"coverage_gaps,omitempty"`
	Changed           *ContextChanged          `json:"changed,omitempty"`
}

type ContextChanged struct {
	BaseRef                 string         `json:"base_ref,omitempty"`
	BaseSHA                 string         `json:"base_sha,omitempty"`
	HeadSHA                 string         `json:"head_sha,omitempty"`
	Dirty                   bool           `json:"dirty"`
	AffectedPaths           []string       `json:"affected_paths,omitempty"`
	Impact                  compmap.Impact `json:"impact"`
	FailClosedWouldEscalate bool           `json:"fail_closed_would_escalate"`
}

func runContext(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("context", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", ".", "repository root directory")
	changed := fs.Bool("changed", false, "include git diff impact and reverse dependents")
	base := fs.String("base", "", "base git ref for --changed")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}

	vInfo := version.Current()
	out := ContextOutput{
		SchemaVersion:   vInfo.SchemaVersion,
		ResolverVersion: vInfo.ResolverVersion,
		CLIVersion:      vInfo.CLIVersion,
		RepoName:        filepath.Base(absDir),
	}

	var cfgPtr *config.Config
	maxItems := 50

	if _, err := os.Stat(filepath.Join(absDir, config.ConfigFileName)); err == nil {
		existingLock, _, _ := lockfile.Read(absDir)
		pinnedRemote := lockfile.PinnedRemoteSHAs(existingLock)
		loadOpts := config.LoadOptions{
			Mode:                "local",
			PinnedRemoteSHAs:    pinnedRemote,
			RequirePinnedRemote: *offline,
			Offline:             *offline,
		}
		res, err := config.Load(absDir, loadOpts)
		if err != nil {
			return err
		}
		out.Configured = true
		if res.Effective.Name != "" {
			out.RepoName = res.Effective.Name
		}
		out.Extends = res.Effective.Extends
		out.Chain = res.Chain
		out.PolicyDigest = res.PolicyDigest
		out.Rules = res.Effective.Rules
		out.Checks = res.Effective.Checks
		out.Skills = res.Effective.Skills
		cfgPtr = &res.Effective
		if res.Effective.Policy.MaxContextItems > 0 {
			maxItems = res.Effective.Policy.MaxContextItems
		}
		canonical := res
		if res.LocalOverrideApplied {
			ciLoadOpts := loadOpts
			ciLoadOpts.Mode = "ci"
			if c, err := config.Load(absDir, ciLoadOpts); err == nil {
				canonical = c
			}
		}
		lv := lockfile.Verify(absDir, canonical)
		out.Lock = &lv
	}

	tracked, _ := gitdiff.ListTrackedFiles(absDir)
	cm, err := compmap.BuildWithOptions(absDir, cfgPtr, tracked, compmap.BuildOptions{
		AllowProviders: out.Lock != nil && out.Lock.Valid,
	})
	if err != nil {
		return err
	}

	out.Components = cm.Components
	out.Pins = cm.Pins
	out.Ecosystem = cm.Ecosystem
	out.ProviderStatuses = cm.ProviderStatuses
	out.CoverageGaps = cm.CoverageGaps
	if !out.Configured {
		out.CoverageGaps = append(out.CoverageGaps,
			".waypost.yaml not found; showing safe static manifest inference only (run `waypost init` to declare policy, pins, and checks)")
	}

	if len(cm.UnmappedPaths) > maxItems {
		out.UnmappedPaths = cm.UnmappedPaths[:maxItems]
		out.UnmappedTruncated = len(cm.UnmappedPaths) - maxItems
	} else {
		out.UnmappedPaths = cm.UnmappedPaths
	}

	if *changed {
		snap, err := gitdiff.Inspect(absDir, *base, "local")
		if err != nil {
			return err
		}
		imp := cm.ImpactedByPaths(snap.AffectedPaths)
		failClosed := len(imp.UnmappedPaths) > 0 || snap.MergeBaseError != ""
		out.Changed = &ContextChanged{
			BaseRef:                 snap.BaseRef,
			BaseSHA:                 snap.BaseSHA,
			HeadSHA:                 snap.HeadSHA,
			Dirty:                   snap.Dirty,
			AffectedPaths:           snap.AffectedPaths,
			Impact:                  imp,
			FailClosedWouldEscalate: failClosed,
		}
	}

	if *format == "json" {
		return writeJSON(stdout, out)
	}
	renderContextText(stdout, &out)
	return nil
}

func renderContextText(w io.Writer, o *ContextOutput) {
	fmt.Fprintf(w, "Waypost Context: %s (configured=%v, schema=%s)\n", o.RepoName, o.Configured, o.SchemaVersion)
	if o.Extends != "" {
		fmt.Fprintf(w, "  extends: %s | policy_digest: %s\n", o.Extends, shortHash(o.PolicyDigest))
	}
	if o.Lock != nil {
		fmt.Fprintf(w, "  lock:    valid=%v (sha256=%s)\n", o.Lock.Valid, shortHash(o.Lock.LockDigest))
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
		ecoTags = append(ecoTags, "pm="+o.Ecosystem.PackageManager)
	}
	if len(ecoTags) > 0 {
		fmt.Fprintf(w, "  ecosystem: %s\n", strings.Join(ecoTags, ", "))
	}

	fmt.Fprintf(w, "\nComponents (%d):\n", len(o.Components))
	if len(o.Components) == 0 {
		fmt.Fprintln(w, "  (none inferred or declared)")
	}
	for _, c := range o.Components {
		fmt.Fprintf(w, "  - %s [%s, %s, provenance=%s] root=%s\n", c.ID, nonEmpty(c.Kind, "component"), nonEmpty(c.Language, "unknown"), c.Provenance, c.Root)
		if len(c.DependsOn) > 0 {
			fmt.Fprintf(w, "      depends_on:  %s\n", strings.Join(c.DependsOn, ", "))
		}
		if len(c.DependedBy) > 0 {
			fmt.Fprintf(w, "      depended_by: %s\n", strings.Join(c.DependedBy, ", "))
		}
		if len(c.Entrypoints) > 0 {
			fmt.Fprintf(w, "      entrypoints: %s\n", strings.Join(c.Entrypoints, ", "))
		}
		if len(c.Checks) > 0 {
			fmt.Fprintf(w, "      checks:      %s\n", strings.Join(c.Checks, ", "))
		}
	}

	if len(o.Pins) > 0 {
		fmt.Fprintf(w, "\nCross-Repo Pins (%d):\n", len(o.Pins))
		for _, p := range o.Pins {
			fmt.Fprintf(w, "  - %s: producer=%s artifact=%s -> consumer=%s", p.ID, p.Producer, p.Artifact, p.Consumer)
			if p.CompatibilityCheck != "" {
				fmt.Fprintf(w, " (check=%s)", p.CompatibilityCheck)
			}
			fmt.Fprintln(w)
		}
	}

	if len(o.Rules) > 0 {
		fmt.Fprintf(w, "\nRules (%d):\n", len(o.Rules))
		for _, r := range o.Rules {
			fmt.Fprintf(w, "  - [%s] %s: %s\n", r.Kind, r.ID, r.Summary)
		}
	}

	if len(o.Checks) > 0 {
		fmt.Fprintf(w, "\nChecks (%d):\n", len(o.Checks))
		for _, c := range o.Checks {
			fmt.Fprintf(w, "  - %s (required=%v): %s\n", c.ID, c.IsRequired(), c.Command)
		}
	}

	if len(o.Ecosystem.DiscoveredSkills) > 0 {
		fmt.Fprintf(w, "\nDiscovered Local Skills (.agents/skills, %d):\n", len(o.Ecosystem.DiscoveredSkills))
		for _, sk := range o.Ecosystem.DiscoveredSkills {
			if sk.Description != "" {
				fmt.Fprintf(w, "  - %s (%s): %s\n", sk.Name, sk.Path, sk.Description)
			} else {
				fmt.Fprintf(w, "  - %s (%s)\n", sk.Name, sk.Path)
			}
		}
	}

	if len(o.ProviderStatuses) > 0 {
		fmt.Fprintf(w, "\nProviders (%d):\n", len(o.ProviderStatuses))
		for _, ps := range o.ProviderStatuses {
			fmt.Fprintf(w, "  - %s (%s): authorized=%v executed=%v — %s\n", ps.ID, ps.Tool, ps.Authorized, ps.Executed, ps.Note)
		}
	}

	if len(o.UnmappedPaths) > 0 {
		fmt.Fprintf(w, "\nUnmapped Tracked Paths (%d shown", len(o.UnmappedPaths))
		if o.UnmappedTruncated > 0 {
			fmt.Fprintf(w, ", +%d more", o.UnmappedTruncated)
		}
		fmt.Fprintln(w, "):")
		for _, p := range o.UnmappedPaths {
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}

	if len(o.CoverageGaps) > 0 {
		fmt.Fprintf(w, "\nCoverage Gaps (%d):\n", len(o.CoverageGaps))
		for _, g := range o.CoverageGaps {
			fmt.Fprintf(w, "  - %s\n", g)
		}
	}

	if o.Changed != nil {
		fmt.Fprintf(w, "\nChanged Impact (base=%s, dirty=%v):\n", nonEmpty(o.Changed.BaseRef, "HEAD"), o.Changed.Dirty)
		fmt.Fprintf(w, "  changed_paths:        %d\n", len(o.Changed.AffectedPaths))
		fmt.Fprintf(w, "  direct_components:    %s\n", listOrNone(o.Changed.Impact.DirectComponents))
		fmt.Fprintf(w, "  transitive_dependents:%s\n", " "+listOrNone(o.Changed.Impact.TransitiveDependents))
		fmt.Fprintf(w, "  triggered_pins:       %s\n", listOrNone(o.Changed.Impact.TriggeredPins))
		fmt.Fprintf(w, "  unmapped_changed:     %s\n", listOrNone(o.Changed.Impact.UnmappedPaths))
		if o.Changed.FailClosedWouldEscalate {
			fmt.Fprintln(w, "  notice:               fail-closed policy would escalate to full repo verification")
		}
	}
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", ".", "repository root directory")
	mode := fs.String("mode", "local", "verification authority: local or ci")
	base := fs.String("base", "", "base git ref for diff and policy floor")
	frozen := fs.Bool("frozen", false, "require committed .waypost.lock to match exactly")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	all := fs.Bool("all", false, "force full repository verification")
	receiptPath := fs.String("receipt", "", "optional path to write receipt.v1.json")
	markdownPath := fs.String("markdown", "", "optional path to write PR Markdown summary")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "waypost verify: %v\n", err)
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
		if err := os.MkdirAll(filepath.Dir(*markdownPath), 0o755); err != nil {
			fmt.Fprintf(stderr, "waypost verify: mkdir markdown: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*markdownPath, []byte(verify.RenderMarkdown(rec)), 0o644); err != nil {
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
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", ".", "repository root directory")
	target := fs.String("target", "", "optional new extends reference (e.g., builtin:app-ts@1.0.0, github:org/repo/preset.yaml@v1, or ../preset.yaml)")
	dryRun := fs.Bool("dry-run", true, "preview upgrade plan without modifying files")
	apply := fs.Bool("apply", false, "write updated .waypost.yaml and .waypost.lock")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = dryRun // --apply overrides default dry-run

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
