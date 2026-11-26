package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Farzin312/waypost/internal/presets"
	"github.com/Farzin312/waypost/internal/remote"
	"github.com/Farzin312/waypost/internal/repopath"
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
	// HasRootBytes distinguishes a supplied empty document from a filesystem read.
	HasRootBytes bool
	// OverrideRootRaw contains the supplied YAML document.
	OverrideRootRaw []byte
	// OverrideLabel is used in error messages when OverrideRootRaw is set.
	OverrideLabel string
	// RepoFileReader, when non-nil, reads in-repo file-based `extends` ancestors from that trusted reader
	// (e.g. `git show <baseTip>:<relPath>`) instead of the live worktree.
	RepoFileReader ReadRepoFileFunc
	// PinnedRemoteSHAs maps remote `extends` refs to their expected SHA-256 digests from .waypost.lock.
	PinnedRemoteSHAs     map[string]string
	PinnedBuiltins       map[string]string
	RequireBuiltinAnchor bool
	// RequirePinnedRemote fails closed if a remote `extends` ref is not present in PinnedRemoteSHAs.
	RequirePinnedRemote bool
	// Offline restricts remote preset resolution to the verified local content-addressed cache.
	Offline bool
	// ReadOnly prevents remote downloads from updating the local cache.
	ReadOnly bool
}

// ParseBytes unmarshals and validates a single config YAML document.
func ParseBytes(raw []byte, label string) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return nil, fmt.Errorf("parse %s: expected one YAML document", label)
	}
	if err := validateSingle(&cfg, label); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Load resolves <repoDir>/.waypost.yaml (or OverrideRootRaw), walks its single-parent
// `extends` chain (builtin, local file, or SHA-256-verified remote HTTPS/GitHub),
// optionally merges .waypost.local.yaml in local mode, and computes a deterministic policy digest.
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
	if opts.HasRootBytes || opts.OverrideRootRaw != nil {
		rootRaw = opts.OverrideRootRaw
		if opts.OverrideLabel != "" {
			label = opts.OverrideLabel
		}
	} else {
		rootRaw, err = repopath.Read(absRepo, ConfigFileName, repopath.MaxPolicyBytes)
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
	fromRemote := false
	nextRef := strings.TrimSpace(rootCfg.Extends)
	var repoAncestorTrustPaths []string

	for nextRef != "" {
		if len(layers) >= 64 {
			return nil, fmt.Errorf("preset inheritance exceeds 64 layers")
		}
		parentCfg, step, parentDir, parentRelDir, visitKey, repoRelPath, isRemoteParent, err := resolveParent(
			nextRef, absRepo, currDir, currRelDir, mode, fromRemote, opts,
		)
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
		fromRemote = fromRemote || isRemoteParent
		nextRef = strings.TrimSpace(parentCfg.Extends)
	}

	var effective Config
	effective.SchemaVersion = version.SchemaVersion
	chain := make([]InheritanceStep, 0, len(layers)-1)
	origins := make(map[string]RuleOrigin)
	recordOrigins := func(cfg *Config, source string) {
		for _, rule := range cfg.Rules {
			origins[rule.ID] = RuleOrigin{Source: source, Overrides: origins[rule.ID].Source}
		}
		for _, id := range cfg.DisableRules {
			delete(origins, id)
		}
	}
	for i := len(layers) - 1; i >= 0; i-- {
		source := ConfigFileName
		if layers[i].step != nil {
			source = layers[i].step.Ref
		}
		recordOrigins(layers[i].cfg, source)
		if layers[i].step != nil {
			chain = append(chain, *layers[i].step)
		}
		effective = mergeConfigs(effective, *layers[i].cfg)
	}

	if len(repoAncestorTrustPaths) > 0 {
		effective.Policy.TrustPaths = mergeUniqueStrings(effective.Policy.TrustPaths, repoAncestorTrustPaths)
	}

	// In CI mode, never open or read .waypost.local.yaml (only Lstat to report ignored=true).
	localApplied := false
	localIgnored := false
	if !opts.HasRootBytes && opts.OverrideRootRaw == nil {
		localPath := filepath.Join(absRepo, LocalConfigFileName)
		if mode == "ci" {
			if _, statErr := os.Lstat(localPath); statErr == nil {
				localIgnored = true
			}
		} else {
			if localRaw, err := repopath.Read(absRepo, LocalConfigFileName, repopath.MaxPolicyBytes); err == nil {
				localCfg, err := ParseBytes(localRaw, localPath)
				if err != nil {
					return nil, fmt.Errorf("invalid local override %s: %w", localPath, err)
				}
				if strings.TrimSpace(localCfg.Extends) != "" {
					return nil, fmt.Errorf("%s may not declare extends", localPath)
				}
				recordOrigins(localCfg, LocalConfigFileName)
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

	if b := effective.Boundaries; b != nil && (b.Baseline != "" || b.EffectiveMode() == "ratchet") && opts.RepoFileReader == nil {
		if err := ValidateBaselinePath(absRepo, b.BaselinePath()); err != nil {
			return nil, err
		}
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
		RuleOrigins:          origins,
	}, nil
}

func resolveParent(ref, absRepo, baseDir, baseRelDir, mode string, fromRemote bool, opts LoadOptions) (*Config, *InheritanceStep, string, string, string, string, bool, error) {
	if presets.IsBuiltin(ref) {
		anchored := presets.Anchor(ref, opts.PinnedBuiltins)
		if opts.RequireBuiltinAnchor && presets.Floating(anchored) {
			return nil, nil, "", "", "", "", false, fmt.Errorf("historical builtin %q requires an exact lock anchor", ref)
		}
		b, err := presets.Resolve(anchored)
		if err != nil {
			return nil, nil, "", "", "", "", false, err
		}
		cfg, err := ParseBytes(b.Raw, b.Ref)
		if err != nil {
			return nil, nil, "", "", "", "", false, err
		}
		if cfg.PresetVersion != b.Version {
			return nil, nil, "", "", "", "", false, fmt.Errorf("builtin %s version is %q", b.Ref, cfg.PresetVersion)
		}
		step := &InheritanceStep{
			Ref:     b.Ref,
			Source:  "builtin",
			Version: b.Version,
			SHA256:  b.SHA256,
		}
		return cfg, step, baseDir, baseRelDir, b.Ref, "", false, nil
	}

	if remote.IsRemote(ref) {
		expectedSHA := ""
		if opts.PinnedRemoteSHAs != nil {
			expectedSHA = strings.ToLower(strings.TrimSpace(opts.PinnedRemoteSHAs[strings.TrimSpace(ref)]))
		}
		if opts.RequirePinnedRemote && !remote.IsValidSHA256Hex(expectedSHA) {
			return nil, nil, "", "", "", "", true, fmt.Errorf("remote preset %q is not validly SHA-256 pinned in .waypost.lock (run `waypost upgrade --apply`)", ref)
		}
		fetch := remote.Fetch
		if opts.ReadOnly {
			fetch = remote.FetchReadOnly
		}
		r, err := fetch(ref, expectedSHA, opts.Offline)
		if err != nil {
			return nil, nil, "", "", "", "", true, err
		}
		cfg, err := ParseBytes(r.Raw, r.Ref)
		if err != nil {
			return nil, nil, "", "", "", "", true, err
		}
		step := &InheritanceStep{
			Ref:     r.Ref,
			Source:  "remote",
			URL:     r.URL,
			Version: cfg.PresetVersion,
			SHA256:  r.SHA256,
		}
		return cfg, step, baseDir, baseRelDir, "remote:" + r.URL, "", true, nil
	}

	// Security boundary: a remote preset may NEVER extend a local filesystem path!
	if fromRemote {
		return nil, nil, "", "", "", "", false, fmt.Errorf("remote preset cannot extend local file path %q (only builtin: or remote refs allowed)", ref)
	}

	cleanRefBase := filepath.Base(filepath.Clean(ref))
	if mode == "ci" && cleanRefBase == LocalConfigFileName {
		return nil, nil, "", "", "", "", false, fmt.Errorf("extends may not reference %s in CI mode", LocalConfigFileName)
	}

	// Trusted repo reader path (resolving base-branch policy floor strictly from git commit).
	if opts.RepoFileReader != nil {
		isExternal := filepath.IsAbs(ref)
		joinedRel := ""
		if !isExternal {
			joinedRel = filepath.ToSlash(filepath.Clean(filepath.Join(baseRelDir, ref)))
			if strings.HasPrefix(joinedRel, "../") || joinedRel == ".." {
				isExternal = true
			}
		}
		if !isExternal {
			raw, exists, err := opts.RepoFileReader(joinedRel)
			if err != nil {
				return nil, nil, "", "", "", "", false, fmt.Errorf("read extends preset %q from trusted ref: %w", joinedRel, err)
			}
			if !exists {
				return nil, nil, "", "", "", "", false, fmt.Errorf("extends preset %q not found in trusted git ref", joinedRel)
			}
			cfg, err := ParseBytes(raw, "git:"+joinedRel)
			if err != nil {
				return nil, nil, "", "", "", "", false, err
			}
			step := &InheritanceStep{
				Ref:     ref,
				Source:  "file",
				Version: cfg.PresetVersion,
				SHA256:  sha256Hex(raw),
			}
			return cfg, step, baseDir, filepath.ToSlash(filepath.Dir(joinedRel)), "repo:" + joinedRel, joinedRel, false, nil
		}
		return nil, nil, "", "", "", "", false, fmt.Errorf("external extends path %q is not permitted for a trusted snapshot", ref)
	}

	p := ref
	if !filepath.IsAbs(p) {
		p = filepath.Join(baseDir, p)
	}
	absPath, err := filepath.Abs(p)
	if err != nil {
		return nil, nil, "", "", "", "", false, fmt.Errorf("resolve extends path %q: %w", ref, err)
	}
	if mode == "ci" && filepath.Clean(absPath) == filepath.Clean(filepath.Join(absRepo, LocalConfigFileName)) {
		return nil, nil, "", "", "", "", false, fmt.Errorf("extends may not reference %s in CI mode", LocalConfigFileName)
	}

	rel, relErr := filepath.Rel(absRepo, absPath)
	inRepo := relErr == nil && repopath.Valid(filepath.ToSlash(rel))
	if mode == "ci" && !inRepo {
		return nil, nil, "", "", "", "", false, fmt.Errorf("external extends path %q is not permitted in CI", ref)
	}
	readRoot, readPath := absRepo, filepath.ToSlash(rel)
	if !inRepo {
		readRoot, readPath = filepath.Dir(absPath), filepath.Base(absPath)
	}
	raw, err := repopath.Read(readRoot, readPath, repopath.MaxPolicyBytes)
	if err != nil {
		return nil, nil, "", "", "", "", false, fmt.Errorf("read extends preset %q (%s): %w", ref, absPath, err)
	}
	cfg, err := ParseBytes(raw, absPath)
	if err != nil {
		return nil, nil, "", "", "", "", false, err
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

	return cfg, step, filepath.Dir(absPath), filepath.Dir(repoRelPath), "file:" + filepath.Clean(absPath), repoRelPath, false, nil
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func validateSingle(cfg *Config, label string) error {
	if cfg.SchemaVersion != "" && cfg.SchemaVersion != version.SchemaVersion {
		return fmt.Errorf("%s: unsupported schema_version %q (supported: %q)", label, cfg.SchemaVersion, version.SchemaVersion)
	}
	for _, entry := range cfg.Rules {
		if !safeID.MatchString(entry.ID) {
			return fmt.Errorf("%s: invalid rule ID %q", label, entry.ID)
		}
	}
	if err := checkDuplicateIDs(label, "rule", len(cfg.Rules), func(i int) string { return cfg.Rules[i].ID }); err != nil {
		return err
	}
	for _, r := range cfg.Rules {
		if r.ReviewAfter != "" {
			if _, err := time.Parse(time.DateOnly, r.ReviewAfter); err != nil {
				return fmt.Errorf("%s: rule %q has invalid review_after: %w", label, r.ID, err)
			}
		}
		if r.Kind != "invariant" && r.Kind != "crutch" {
			return fmt.Errorf("%s: rule %q has invalid kind %q (must be \"invariant\" or \"crutch\")", label, r.ID, r.Kind)
		}
		if r.VerifiedBy != nil {
			proof := r.VerifiedBy
			if len(proof.Checks)+len(proof.Tests) == 0 {
				return fmt.Errorf("%s: rule %q requires at least one verified_by link", label, r.ID)
			}
			for _, links := range [][]string{proof.Checks, proof.Tests} {
				if err := checkDuplicateIDs(label, "proof link", len(links), func(i int) string {
					return strings.TrimPrefix(links[i], "./")
				}); err != nil {
					return err
				}
			}
			for _, glob := range proof.Tests {
				if err := repopath.ValidateGlob(glob); err != nil {
					return fmt.Errorf("rule %q: %w", r.ID, err)
				}
			}
		}
		if strings.TrimSpace(r.Summary) == "" {
			return fmt.Errorf("%s: rule %q requires a non-empty summary", label, r.ID)
		}
	}
	for _, entry := range cfg.Components {
		if !safeID.MatchString(entry.ID) {
			return fmt.Errorf("%s: invalid component ID %q", label, entry.ID)
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
	for _, entry := range cfg.Pins {
		if !safeID.MatchString(entry.ID) {
			return fmt.Errorf("%s: invalid pin ID %q", label, entry.ID)
		}
	}
	if err := checkDuplicateIDs(label, "pin", len(cfg.Pins), func(i int) string { return cfg.Pins[i].ID }); err != nil {
		return err
	}
	for _, p := range cfg.Pins {
		if p.Role != "" && p.Role != "producer" && p.Role != "consumer" {
			return fmt.Errorf("pin %q has invalid role %q", p.ID, p.Role)
		}
		if src := p.Source; src != nil {
			if !repopath.Valid(src.Manifest) ||
				(src.Kind != "npm-package-version" && src.Kind != "npm-dependency") ||
				(src.Kind == "npm-dependency" && strings.TrimSpace(src.Package) == "") ||
				(src.Kind == "npm-package-version" && src.Package != "") {
				return fmt.Errorf("pin %q has invalid source", p.ID)
			}
		}
		if strings.TrimSpace(p.Producer) == "" || strings.TrimSpace(p.Artifact) == "" || strings.TrimSpace(p.Consumer) == "" {
			return fmt.Errorf("%s: pin %q requires non-empty producer, artifact, and consumer", label, p.ID)
		}
	}
	for _, entry := range cfg.Checks {
		if !safeID.MatchString(entry.ID) {
			return fmt.Errorf("%s: invalid check ID %q", label, entry.ID)
		}
	}
	if err := checkDuplicateIDs(label, "check", len(cfg.Checks), func(i int) string { return cfg.Checks[i].ID }); err != nil {
		return err
	}
	for _, c := range cfg.Checks {
		if c.TimeoutSeconds < 0 || (c.Workdir != "" && c.Workdir != "." && !repopath.Valid(c.Workdir)) {
			return fmt.Errorf("check %q has invalid timeout or workdir", c.ID)
		}
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
	if bounds := cfg.Boundaries; bounds != nil {
		if bounds.Mode != "" && bounds.Mode != "enforce" && bounds.Mode != "ratchet" && bounds.Mode != "warn" {
			return fmt.Errorf("%s: boundaries.mode %q must be enforce, ratchet, or warn", label, bounds.Mode)
		}
		if err := checkDuplicateIDs(label, "boundary rule", len(bounds.Rules), func(i int) string { return bounds.Rules[i].ID }); err != nil {
			return err
		}
		for _, rule := range bounds.Rules {
			from := strings.TrimSpace(rule.From) != ""
			target := strings.TrimSpace(rule.Target) != ""
			dependencies := rule.AllowDependsOn != nil || rule.DenyDependsOn != nil
			entrypoints := rule.PublicEntrypoints != nil
			switch {
			case dependencies && !from:
				return fmt.Errorf("%s: boundary rule %q with allow_depends_on or deny_depends_on requires from", label, rule.ID)
			case entrypoints && !target:
				return fmt.Errorf("%s: boundary rule %q with public_entrypoints requires target", label, rule.ID)
			case rule.DenyDependsOn != nil && len(rule.DenyDependsOn) == 0:
				return fmt.Errorf("%s: boundary rule %q requires a non-empty deny_depends_on list", label, rule.ID)
			case entrypoints && len(rule.PublicEntrypoints) == 0:
				return fmt.Errorf("%s: boundary rule %q requires a non-empty public_entrypoints list", label, rule.ID)
			case !dependencies && !entrypoints:
				return fmt.Errorf("%s: boundary rule %q requires a dependency or public entrypoint constraint", label, rule.ID)
			}
		}
	}
	return validateGlobs(cfg)
}

func validateGlobs(cfg *Config) error {
	groups := [][]string{cfg.Policy.TrustPaths}
	for _, c := range cfg.Components {
		if c.Root != "." && !repopath.Valid(c.Root) {
			return fmt.Errorf("component %q has invalid root %q", c.ID, c.Root)
		}
		groups = append(groups, c.Paths, c.Entrypoints, c.TrustPaths)
	}
	for _, c := range cfg.Checks {
		groups = append(groups, c.Paths)
	}
	for _, p := range cfg.Pins {
		groups = append(groups, p.Paths)
	}
	if b := cfg.Boundaries; b != nil {
		groups = append(groups, b.IgnorePaths)
		for _, r := range b.Rules {
			groups = append(groups, r.PublicEntrypoints, r.DenyDependsOn)
			if r.AllowDependsOn != nil {
				groups = append(groups, *r.AllowDependsOn)
			}
			for _, pattern := range []string{r.From, r.Target} {
				if pattern != "" {
					groups = append(groups, []string{pattern})
				}
			}
		}
	}
	for _, group := range groups {
		for _, pattern := range group {
			if err := repopath.ValidateGlob(pattern); err != nil {
				return err
			}
		}
	}
	return nil
}

func validBaselinePath(rel string) bool {
	if !fs.ValidPath(rel) || strings.ContainsAny(rel, "\\:\x00") {
		return false
	}
	first, _, _ := strings.Cut(strings.ToLower(rel), "/")
	switch first {
	case ".", ".git", ConfigFileName, LocalConfigFileName, ".waypost.lock":
		return false
	default:
		return true
	}
}

// ValidateBaselinePath accepts a missing file but rejects an existing path that
// resolves outside the repository, including a symlink in a parent directory.
func ValidateBaselinePath(repo, rel string) error {
	if !validBaselinePath(rel) || !filepath.IsLocal(rel) {
		return fmt.Errorf("boundaries.baseline %q must be a repository-relative file path", rel)
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		return err
	}
	defer root.Close()
	for prefix := filepath.FromSlash(rel); prefix != "."; prefix = filepath.Dir(prefix) {
		_, err := root.Stat(prefix)
		if errors.Is(err, os.ErrNotExist) {
			// Lstat distinguishes a broken link from a missing path.
			if _, linkErr := root.Lstat(prefix); errors.Is(linkErr, os.ErrNotExist) {
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("boundaries.baseline %q: %w", rel, err)
		}
		break
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
	for _, rule := range cfg.Rules {
		if rule.VerifiedBy != nil {
			for _, id := range rule.VerifiedBy.Checks {
				if !checkIDs[id] {
					return fmt.Errorf("rule %q references unknown verified_by check %q", rule.ID, id)
				}
			}
		}
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

	out.Boundaries = mergeBoundaries(parent.Boundaries, child.Boundaries)

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

func mergeBoundaries(parent, child *BoundariesConfig) *BoundariesConfig {
	if child == nil {
		return parent
	}
	if parent == nil {
		parent = &BoundariesConfig{}
	}
	out := *parent
	if child.Enabled != nil {
		out.Enabled = child.Enabled
	}
	if child.Mode != "" {
		out.Mode = child.Mode
	}
	if child.Baseline != "" {
		out.Baseline = child.Baseline
	}
	if child.NoCycles != nil {
		out.NoCycles = child.NoCycles
	}
	if child.EnforceDeclaredDeps != nil {
		out.EnforceDeclaredDeps = child.EnforceDeclaredDeps
	}
	out.IgnorePaths = mergeUniqueStrings(parent.IgnorePaths, child.IgnorePaths)
	out.Rules = mergeByID(parent.Rules, child.Rules, func(r BoundaryRule) string { return r.ID })
	return &out
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
