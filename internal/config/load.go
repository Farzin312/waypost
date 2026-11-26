package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Farzin312/waypost/internal/presets"
	"github.com/Farzin312/waypost/internal/version"
	"gopkg.in/yaml.v3"
)

const (
	ConfigFileName      = ".waypost.yaml"
	LocalConfigFileName = ".waypost.local.yaml"
)

// ReadRepoFileFunc reads a repository-relative path from a trusted source (e.g., git commit).
type ReadRepoFileFunc func(relPath string) ([]byte, bool, error)

// LoadOptions configures how .waypost.yaml and its inheritance chain are resolved.
type LoadOptions struct {
	// Mode is "local" (default) or "ci". In "ci" mode, .waypost.local.yaml is never opened or applied.
	Mode string
	// OverrideRootRaw, when non-empty, parses this raw YAML instead of reading <repoDir>/.waypost.yaml.
	OverrideRootRaw []byte
	// OverrideLabel is used in error messages when OverrideRootRaw is set.
	OverrideLabel string
	// RepoFileReader, when non-nil, reads file-based `extends` ancestors from that trusted reader
	// (e.g. `git show <baseTip>:<relPath>`) instead of the live worktree.
	RepoFileReader ReadRepoFileFunc
}

// ParseBytes unmarshals and validates a single config YAML document.
func ParseBytes(raw []byte, label string) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	if err := validateSingle(&cfg, label); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Load resolves <repoDir>/.waypost.yaml (or OverrideRootRaw), walks its single-parent
// `extends` chain, optionally merges .waypost.local.yaml in local mode, and computes
// a deterministic effective policy digest.
func Load(repoDir string, opts LoadOptions) (*ResolvedConfig, error) {
	mode := opts.Mode
	if mode == "" {
		mode = "local"
	}
	if mode != "local" && mode != "ci" {
		return nil, fmt.Errorf("invalid mode %q (must be \"local\" or \"ci\")", mode)
	}

	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, fmt.Errorf("resolve repo dir: %w", err)
	}

	var rootRaw []byte
	rootPath := filepath.Join(absRepo, ConfigFileName)
	label := rootPath
	if len(opts.OverrideRootRaw) > 0 {
		rootRaw = opts.OverrideRootRaw
		if opts.OverrideLabel != "" {
			label = opts.OverrideLabel
		}
	} else {
		rootRaw, err = os.ReadFile(rootPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rootPath, err)
		}
	}

	rootCfg, err := ParseBytes(rootRaw, label)
	if err != nil {
		return nil, err
	}
	rootSum := sha256Hex(rootRaw)

	visited := map[string]bool{
		"file:" + filepath.Clean(rootPath): true,
		"repo:" + ConfigFileName:           true,
	}

	type layer struct {
		cfg  *Config
		step *InheritanceStep
	}
	var layers []layer
	layers = append(layers, layer{cfg: rootCfg})

	currDir := absRepo
	currRelDir := "."
	nextRef := strings.TrimSpace(rootCfg.Extends)
	var repoAncestorTrustPaths []string

	for nextRef != "" {
		parentCfg, step, parentDir, parentRelDir, visitKey, repoRelPath, err := resolveParent(nextRef, absRepo, currDir, currRelDir, mode, opts.RepoFileReader)
		if err != nil {
			return nil, err
		}
		if visited[visitKey] {
			return nil, fmt.Errorf("inheritance cycle detected at %q", nextRef)
		}
		visited[visitKey] = true
		if repoRelPath != "" {
			repoAncestorTrustPaths = append(repoAncestorTrustPaths, repoRelPath)
		}
		layers = append(layers, layer{cfg: parentCfg, step: step})
		currDir = parentDir
		currRelDir = parentRelDir
		nextRef = strings.TrimSpace(parentCfg.Extends)
	}

	// Merge from oldest ancestor to root config.
	var effective Config
	effective.SchemaVersion = version.SchemaVersion
	chain := make([]InheritanceStep, 0, len(layers)-1)
	for i := len(layers) - 1; i >= 0; i-- {
		if layers[i].step != nil {
			chain = append(chain, *layers[i].step)
		}
		effective = mergeConfigs(effective, *layers[i].cfg)
	}

	// Automatically treat any in-repo file-based `extends` ancestors as trust_paths.
	if len(repoAncestorTrustPaths) > 0 {
		effective.Policy.TrustPaths = mergeUniqueStrings(effective.Policy.TrustPaths, repoAncestorTrustPaths)
	}

	// Handle .waypost.local.yaml strictly according to mode:
	// In CI mode, never open or read .waypost.local.yaml (only Lstat to report ignored=true).
	localApplied := false
	localIgnored := false
	if len(opts.OverrideRootRaw) == 0 {
		localPath := filepath.Join(absRepo, LocalConfigFileName)
		if mode == "ci" {
			if _, statErr := os.Lstat(localPath); statErr == nil {
				localIgnored = true
			}
		} else {
			if localRaw, err := os.ReadFile(localPath); err == nil {
				localCfg, err := ParseBytes(localRaw, localPath)
				if err != nil {
					return nil, fmt.Errorf("invalid local override %s: %w", localPath, err)
				}
				if strings.TrimSpace(localCfg.Extends) != "" {
					return nil, fmt.Errorf("%s may not declare extends", localPath)
				}
				effective = mergeConfigs(effective, *localCfg)
				localApplied = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read %s: %w", localPath, err)
			}
		}
	}

	if effective.Policy.FailClosedOnUnmapped == nil {
		effective.Policy.FailClosedOnUnmapped = BoolPtr(true)
	}
	if effective.Policy.RequireFrozenLockInCI == nil {
		effective.Policy.RequireFrozenLockInCI = BoolPtr(true)
	}
	if effective.Policy.EnforceBaseFloorInCI == nil {
		effective.Policy.EnforceBaseFloorInCI = BoolPtr(true)
	}
	if effective.Policy.MaxContextItems <= 0 {
		effective.Policy.MaxContextItems = 50
	}

	if err := validateEffective(&effective); err != nil {
		return nil, err
	}

	digest, err := ComputeDigest(effective)
	if err != nil {
		return nil, err
	}

	return &ResolvedConfig{
		Effective:            effective,
		RootPath:             rootPath,
		Chain:                chain,
		PolicyDigest:         digest,
		LocalOverrideApplied: localApplied,
		LocalOverrideIgnored: localIgnored,
		RawRootSHA256:        rootSum,
	}, nil
}

func resolveParent(ref, absRepo, baseDir, baseRelDir, mode string, repoReader ReadRepoFileFunc) (*Config, *InheritanceStep, string, string, string, string, error) {
	if presets.IsBuiltin(ref) {
		b, err := presets.Resolve(ref)
		if err != nil {
			return nil, nil, "", "", "", "", err
		}
		cfg, err := ParseBytes(b.Raw, b.Ref)
		if err != nil {
			return nil, nil, "", "", "", "", err
		}
		step := &InheritanceStep{
			Ref:     b.Ref,
			Source:  "builtin",
			Version: b.Version,
			SHA256:  b.SHA256,
		}
		return cfg, step, baseDir, baseRelDir, "builtin:" + b.Name, "", nil
	}

	// Never allow inheriting from .waypost.local.yaml in CI mode.
	cleanRefBase := filepath.Base(filepath.Clean(ref))
	if mode == "ci" && cleanRefBase == LocalConfigFileName {
		return nil, nil, "", "", "", "", fmt.Errorf("extends may not reference %s in CI mode", LocalConfigFileName)
	}

	// Trusted repo reader path (e.g. resolving base-branch policy floor strictly from git commit).
	// Any in-repo ancestor MUST be read from git (never the PR worktree). External sibling presets
	// strictly outside the repository root (e.g. an adjacent org-presets checkout) may be read from
	// disk only after verifying their resolved path does not re-enter the PR repository via symlinks.
	if repoReader != nil {
		isExternal := filepath.IsAbs(ref)
		joinedRel := ""
		if !isExternal {
			joinedRel = filepath.ToSlash(filepath.Clean(filepath.Join(baseRelDir, ref)))
			if strings.HasPrefix(joinedRel, "../") || joinedRel == ".." {
				isExternal = true
			}
		}
		if !isExternal {
			raw, exists, err := repoReader(joinedRel)
			if err != nil {
				return nil, nil, "", "", "", "", fmt.Errorf("read extends preset %q from trusted ref: %w", joinedRel, err)
			}
			if !exists {
				return nil, nil, "", "", "", "", fmt.Errorf("extends preset %q not found in trusted git ref", joinedRel)
			}
			cfg, err := ParseBytes(raw, "git:"+joinedRel)
			if err != nil {
				return nil, nil, "", "", "", "", err
			}
			step := &InheritanceStep{
				Ref:     ref,
				Source:  "file",
				Version: cfg.PresetVersion,
				SHA256:  sha256Hex(raw),
			}
			return cfg, step, baseDir, filepath.ToSlash(filepath.Dir(joinedRel)), "repo:" + joinedRel, joinedRel, nil
		}
		// Verify external path truly resolves outside absRepo (no symlink back into PR checkout).
		extPath := ref
		if !filepath.IsAbs(extPath) {
			extPath = filepath.Join(baseDir, extPath)
		}
		realExt, err := filepath.EvalSymlinks(extPath)
		if err != nil {
			return nil, nil, "", "", "", "", fmt.Errorf("resolve external extends preset %q: %w", ref, err)
		}
		realRepo, err := filepath.EvalSymlinks(absRepo)
		if err == nil {
			if rel, relErr := filepath.Rel(realRepo, realExt); relErr == nil && !strings.HasPrefix(rel, "..") {
				return nil, nil, "", "", "", "", fmt.Errorf("external extends path %q symlinks back into PR repository", ref)
			}
		}
	}

	// Filesystem preset path.
	p := ref
	if !filepath.IsAbs(p) {
		p = filepath.Join(baseDir, p)
	}
	absPath, err := filepath.Abs(p)
	if err != nil {
		return nil, nil, "", "", "", "", fmt.Errorf("resolve extends path %q: %w", ref, err)
	}
	if mode == "ci" && filepath.Clean(absPath) == filepath.Clean(filepath.Join(absRepo, LocalConfigFileName)) {
		return nil, nil, "", "", "", "", fmt.Errorf("extends may not reference %s in CI mode", LocalConfigFileName)
	}

	raw, err := os.ReadFile(absPath)
	if err != nil {
		return nil, nil, "", "", "", "", fmt.Errorf("read extends preset %q (%s): %w", ref, absPath, err)
	}
	cfg, err := ParseBytes(raw, absPath)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	step := &InheritanceStep{
		Ref:     ref,
		Source:  "file",
		Version: cfg.PresetVersion,
		SHA256:  sha256Hex(raw),
	}

	repoRelPath := ""
	if rel, err := filepath.Rel(absRepo, absPath); err == nil {
		rel = filepath.ToSlash(filepath.Clean(rel))
		if !strings.HasPrefix(rel, "../") && rel != ".." {
			repoRelPath = rel
		}
	}

	return cfg, step, filepath.Dir(absPath), filepath.Dir(repoRelPath), "file:" + filepath.Clean(absPath), repoRelPath, nil
}

func validateSingle(cfg *Config, label string) error {
	if cfg.SchemaVersion != "" && cfg.SchemaVersion != version.SchemaVersion {
		return fmt.Errorf("%s: unsupported schema_version %q (supported: %q)", label, cfg.SchemaVersion, version.SchemaVersion)
	}
	if err := checkDuplicateIDs(label, "rule", len(cfg.Rules), func(i int) string { return cfg.Rules[i].ID }); err != nil {
		return err
	}
	for _, r := range cfg.Rules {
		if r.Kind != "invariant" && r.Kind != "crutch" {
			return fmt.Errorf("%s: rule %q has invalid kind %q (must be \"invariant\" or \"crutch\")", label, r.ID, r.Kind)
		}
		if strings.TrimSpace(r.Summary) == "" {
			return fmt.Errorf("%s: rule %q requires a non-empty summary", label, r.ID)
		}
	}
	if err := checkDuplicateIDs(label, "component", len(cfg.Components), func(i int) string { return cfg.Components[i].ID }); err != nil {
		return err
	}
	for _, c := range cfg.Components {
		if strings.TrimSpace(c.Root) == "" {
			return fmt.Errorf("%s: component %q requires a non-empty root", label, c.ID)
		}
	}
	if err := checkDuplicateIDs(label, "pin", len(cfg.Pins), func(i int) string { return cfg.Pins[i].ID }); err != nil {
		return err
	}
	for _, p := range cfg.Pins {
		if strings.TrimSpace(p.Producer) == "" || strings.TrimSpace(p.Artifact) == "" || strings.TrimSpace(p.Consumer) == "" {
			return fmt.Errorf("%s: pin %q requires non-empty producer, artifact, and consumer", label, p.ID)
		}
	}
	if err := checkDuplicateIDs(label, "check", len(cfg.Checks), func(i int) string { return cfg.Checks[i].ID }); err != nil {
		return err
	}
	for _, c := range cfg.Checks {
		if strings.TrimSpace(c.Command) == "" {
			return fmt.Errorf("%s: check %q requires a non-empty command", label, c.ID)
		}
	}
	if err := checkDuplicateIDs(label, "skill", len(cfg.Skills), func(i int) string { return cfg.Skills[i].ID }); err != nil {
		return err
	}
	for _, s := range cfg.Skills {
		if strings.TrimSpace(s.Source) == "" {
			return fmt.Errorf("%s: skill %q requires a non-empty source", label, s.ID)
		}
		if s.Kind != "" && s.Kind != "invariant" && s.Kind != "crutch" {
			return fmt.Errorf("%s: skill %q has invalid kind %q (must be \"invariant\" or \"crutch\")", label, s.ID, s.Kind)
		}
	}
	if err := checkDuplicateIDs(label, "provider", len(cfg.Providers), func(i int) string { return cfg.Providers[i].ID }); err != nil {
		return err
	}
	for _, p := range cfg.Providers {
		if strings.TrimSpace(p.Tool) == "" || strings.TrimSpace(p.Command) == "" {
			return fmt.Errorf("%s: provider %q requires non-empty tool and command", label, p.ID)
		}
	}
	return nil
}

func validateEffective(cfg *Config) error {
	for _, c := range cfg.Components {
		for _, dep := range c.DependsOn {
			if dep == c.ID {
				return fmt.Errorf("component %q cannot depend on itself", c.ID)
			}
		}
	}
	checkIDs := make(map[string]bool, len(cfg.Checks))
	for _, c := range cfg.Checks {
		checkIDs[c.ID] = true
	}
	for _, comp := range cfg.Components {
		for _, cid := range comp.Checks {
			if !checkIDs[cid] {
				return fmt.Errorf("component %q references unknown check %q", comp.ID, cid)
			}
		}
	}
	for _, pin := range cfg.Pins {
		if pin.CompatibilityCheck != "" && !checkIDs[pin.CompatibilityCheck] {
			return fmt.Errorf("pin %q references unknown compatibility_check %q", pin.ID, pin.CompatibilityCheck)
		}
	}
	return nil
}

func checkDuplicateIDs(label, kind string, n int, getID func(int) string) error {
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := strings.TrimSpace(getID(i))
		if id == "" {
			return fmt.Errorf("%s: %s at index %d has empty id", label, kind, i)
		}
		if seen[id] {
			return fmt.Errorf("%s: duplicate %s id %q", label, kind, id)
		}
		seen[id] = true
	}
	return nil
}

func mergeConfigs(parent, child Config) Config {
	out := parent
	if child.SchemaVersion != "" {
		out.SchemaVersion = child.SchemaVersion
	}
	if child.Name != "" {
		out.Name = child.Name
	}
	if child.PresetVersion != "" {
		out.PresetVersion = child.PresetVersion
	}
	if child.Description != "" {
		out.Description = child.Description
	}
	out.Extends = child.Extends

	if child.Policy.FailClosedOnUnmapped != nil {
		out.Policy.FailClosedOnUnmapped = child.Policy.FailClosedOnUnmapped
	}
	if child.Policy.RequireFrozenLockInCI != nil {
		out.Policy.RequireFrozenLockInCI = child.Policy.RequireFrozenLockInCI
	}
	if child.Policy.EnforceBaseFloorInCI != nil {
		out.Policy.EnforceBaseFloorInCI = child.Policy.EnforceBaseFloorInCI
	}
	if child.Policy.MaxContextItems > 0 {
		out.Policy.MaxContextItems = child.Policy.MaxContextItems
	}
	out.Policy.TrustPaths = mergeUniqueStrings(parent.Policy.TrustPaths, child.Policy.TrustPaths)

	out.Rules = mergeByID(parent.Rules, child.Rules, func(r Rule) string { return r.ID })
	out.Components = mergeByID(parent.Components, child.Components, func(c ComponentConfig) string { return c.ID })
	out.Pins = mergeByID(parent.Pins, child.Pins, func(p CrossRepoPin) string { return p.ID })
	out.Checks = mergeByID(parent.Checks, child.Checks, func(c Check) string { return c.ID })
	out.Skills = mergeByID(parent.Skills, child.Skills, func(s SkillRef) string { return s.ID })
	out.Providers = mergeByID(parent.Providers, child.Providers, func(p ProviderConfig) string { return p.ID })
	out.CoverageGaps = mergeUniqueStrings(parent.CoverageGaps, child.CoverageGaps)
	out.DisableChecks = mergeUniqueStrings(parent.DisableChecks, child.DisableChecks)
	out.DisableRules = mergeUniqueStrings(parent.DisableRules, child.DisableRules)

	if len(child.DisableRules) > 0 {
		disabled := toSet(child.DisableRules)
		filtered := out.Rules[:0]
		for _, r := range out.Rules {
			if !disabled[r.ID] {
				filtered = append(filtered, r)
			}
		}
		out.Rules = filtered
	}
	if len(child.DisableChecks) > 0 {
		disabled := toSet(child.DisableChecks)
		filtered := out.Checks[:0]
		for _, c := range out.Checks {
			if !disabled[c.ID] {
				filtered = append(filtered, c)
			}
		}
		out.Checks = filtered
	}

	return out
}

func mergeByID[T any](parent, child []T, idFn func(T) string) []T {
	out := make([]T, 0, len(parent)+len(child))
	idx := make(map[string]int, len(parent)+len(child))
	for _, item := range parent {
		id := idFn(item)
		idx[id] = len(out)
		out = append(out, item)
	}
	for _, item := range child {
		id := idFn(item)
		if pos, ok := idx[id]; ok {
			out[pos] = item
		} else {
			idx[id] = len(out)
			out = append(out, item)
		}
	}
	return out
}

func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// ComputeDigest returns a deterministic SHA-256 hex digest of a Config.
func ComputeDigest(cfg Config) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal config for digest: %w", err)
	}
	return sha256Hex(b), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
