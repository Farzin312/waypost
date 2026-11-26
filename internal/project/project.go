// Package project loads repository policy and static discovery from one snapshot.
package project

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/pins"
	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repoview"
)

type Snapshot struct {
	View       *repoview.View
	Policy     *config.ResolvedConfig
	Map        *compmap.Map
	Lock       *lockfile.Lockfile
	LockDigest string
}

func Load(view *repoview.View, options config.LoadOptions, providers compmap.BuildOptions) (*Snapshot, error) {
	p := &Snapshot{View: view}
	raw, exists, err := view.Lookup(config.ConfigFileName, repopath.MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	var cfg *config.Config
	if exists {
		lockRaw, present, err := view.Lookup(lockfile.LockFileName, repopath.MaxPolicyBytes)
		if err != nil {
			return nil, err
		}
		if present {
			p.Lock, p.LockDigest, err = lockfile.ParseBytes(lockRaw)
			if err != nil {
				return nil, err
			}
		}
		options.PinnedBuiltins = lockfile.PinnedBuiltins(p.Lock)
		options.PinnedRemoteSHAs = lockfile.PinnedRemoteSHAs(p.Lock)
		if view.Kind == "commit" {
			options.Mode = "ci"
			options.HasRootBytes = true
			options.OverrideRootRaw = raw
			options.RequireBuiltinAnchor = true
			options.OverrideLabel = view.SHA + ":" + config.ConfigFileName
			options.RequirePinnedRemote = true
		}
		options.RepoFileReader = func(rel string) ([]byte, bool, error) { return view.Lookup(rel, repopath.MaxPolicyBytes) }
		p.Policy, err = config.Load(view.Repo, options)
		if err != nil {
			return nil, err
		}
		cfg = &p.Policy.Effective
	}
	providers.View = view
	var paths []string
	if !providers.SkipInventoryOwnership {
		paths = view.Paths()
	}
	p.Map, err = compmap.BuildWithOptions(view.Repo, cfg, paths, providers)
	if err != nil {
		return nil, err
	}
	if cfg != nil && len(cfg.Pins) > 0 {
		p.Map.PinInputs = make(map[string][]string)
		for _, pin := range cfg.Pins {
			p.Map.PinInputs[pin.ID] = pins.InputPaths(view, pin)
		}
	}
	return p, nil
}

func (p *Snapshot) Baseline(rel string) (*archgraph.BaselineFile, error) {
	var cached *archgraph.BaselineFile
	if p.View.CachedParse(rel, "waypost-baseline", &cached) {
		return cached, nil
	}
	raw, err := p.View.Read(rel, archgraph.MaxBaselineBytes)
	if err != nil {
		return nil, err
	}
	parsed, err := archgraph.ParseBaseline(raw)
	if err == nil {
		p.View.CacheParse(rel, "waypost-baseline", parsed)
	}
	return parsed, err
}

func (p *Snapshot) Boundaries() *config.BoundariesConfig {
	if p.Policy == nil {
		return nil
	}
	return p.Policy.Effective.Boundaries
}

func (p *Snapshot) Graph() (*archgraph.Report, error) {
	return archgraph.AnalyzeWithOptions(p.View.Repo, p.Map, p.Boundaries(), archgraph.AnalyzeOptions{
		View: p.View, BaselineReader: p.Baseline,
	})
}

func ValidateProofs(view *repoview.View, cfg *config.Config) error {
	var failures []error
	for _, rule := range cfg.Rules {
		if rule.VerifiedBy == nil {
			continue
		}
		for _, glob := range rule.VerifiedBy.Tests {
			matcher := compmap.CompileGlobs([]string{glob})
			found := false
			for name, file := range view.Files {
				if !file.Tracked || !compmap.MatchCompiled(matcher, name) {
					continue
				}
				if !file.Regular() {
					failures = append(failures, fmt.Errorf("rule %q verified_by test %q matches non-regular tracked path %q", rule.ID, glob, name))
					continue
				}
				if view.Kind == "worktree" {
					if err := repopath.CheckRegular(view.Repo, name); err != nil {
						failures = append(failures, fmt.Errorf("rule %q verified_by test %q: %w", rule.ID, glob, err))
						continue
					}
				}
				found = true
			}
			if !found {
				failures = append(failures, fmt.Errorf("rule %q verified_by test %q has no regular tracked match", rule.ID, glob))
			}
		}
	}
	slices.SortFunc(failures, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return errors.Join(failures...)
}

var sourceExtensions = []string{".go", ".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".c", ".cpp", ".h", ".hpp", ".java", ".kt", ".swift", ".rb", ".php", ".cs", ".vue", ".svelte"}

func TestFile(rel string) bool {
	name := strings.ToLower(rel)
	if !supportedSource(name) {
		return false
	}
	parts := strings.Split(name, "/")
	base := parts[len(parts)-1]
	return strings.HasSuffix(base, "_test.go") || (strings.HasSuffix(base, ".py") && (strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py"))) ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		slices.Contains(parts[:len(parts)-1], "__tests__") || slices.Contains(parts[:len(parts)-1], "tests")
}

func ProductionFile(rel string) bool {
	rel = strings.ToLower(rel)
	base := path.Base(rel)
	for _, dir := range strings.Split(path.Dir(rel), "/") {
		if dir == "docs" || dir == "doc" || dir == ".github" {
			return false
		}
	}
	return supportedSource(rel) && !TestFile(rel) && !strings.Contains(base, ".config.") && base != "conftest.py"
}

func supportedSource(rel string) bool {
	return archgraph.IsSupportedSource(rel) || slices.Contains(sourceExtensions, path.Ext(rel))
}

func (p *Snapshot) RecordedBaseline() (*archgraph.BaselineFile, error) {
	if p.Boundaries() == nil {
		return nil, nil
	}
	b, err := p.Baseline(p.Boundaries().BaselinePath())
	if errors.Is(err, fs.ErrNotExist) && p.Boundaries().EffectiveMode() != "ratchet" {
		return nil, nil
	}
	return b, err
}

func (p *Snapshot) Config() *config.Config {
	if p == nil || p.Policy == nil {
		return nil
	}
	return &p.Policy.Effective
}

func ValidateReferences(cfg *config.Config, cm *compmap.Map) error {
	var failures []error
	components := make(map[string]bool)
	for _, component := range cm.Components {
		components[component.ID] = true
	}
	for _, component := range cfg.Components {
		for _, id := range component.DependsOn {
			if !components[id] {
				failures = append(failures, fmt.Errorf("component %q depends on unknown component %q", component.ID, id))
			}
		}
	}
	for _, check := range cfg.Checks {
		for _, id := range check.Components {
			if !components[id] {
				failures = append(failures, fmt.Errorf("check %q references unknown component %q", check.ID, id))
			}
		}
	}
	for _, pin := range cfg.Pins {
		if pin.ConsumerComponent != "" && !components[pin.ConsumerComponent] {
			failures = append(failures, fmt.Errorf("pin %q references unknown consumer_component %q", pin.ID, pin.ConsumerComponent))
		}
	}
	if b := cfg.Boundaries; b.IsEnabled() {
		for _, r := range b.Rules {
			patterns := append([]string{r.From, r.Target}, r.DenyDependsOn...)
			if r.AllowDependsOn != nil {
				patterns = append(patterns, *r.AllowDependsOn...)
			}
			for _, pattern := range patterns {
				if pattern != "" && !strings.ContainsAny(pattern, "*?[") && !components[pattern] {
					failures = append(failures, fmt.Errorf("boundary rule %q references unknown component %q", r.ID, pattern))
				}
			}
		}
	}
	return errors.Join(failures...)
}
