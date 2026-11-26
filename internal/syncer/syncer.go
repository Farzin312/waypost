// Package syncer checks the live repository for drift and applies reviewable config changes.
package syncer

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/repowrite"
)

const applyHint = "run: waypost sync --apply"

type Item struct {
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Detail   string `json:"detail"`
	Hint     string `json:"hint"`
	Severity string `json:"severity"`
	Fixable  bool   `json:"fixable"`
	Applied  bool   `json:"applied,omitempty"`
}

func (i Item) Actionable() bool { return i.Severity == "blocking" }

type Report struct {
	Items         []Item `json:"items"`
	LockRefreshed bool   `json:"lock_refreshed,omitempty"`
}

func (r Report) Pending() bool {
	for _, item := range r.Items {
		if item.Actionable() && !item.Applied {
			return true
		}
	}
	return false
}

type Options struct {
	Apply   bool
	Offline bool
	Ref     string
}

type inspection struct {
	Report
	additions   map[string]config.ComponentConfig
	pinVersions map[string]string
	baseline    *archgraph.Report
	view        *repoview.View
	baselineRaw []byte
	lockRaw     []byte
}

func (s *inspection) add(kind, subject, detail, hint string) {
	severity := "blocking"
	switch kind {
	case "unwired_script", "empty_component", "expired_crutch", "script_unknown", "boundary_violation":
		severity = "advisory"
	}
	s.Items = append(s.Items, Item{Kind: kind, Subject: subject, Detail: detail, Hint: hint, Severity: severity, Fixable: hint == applyHint})
}

// Check reports drift from an existing repository view and canonical policy.
// The caller may reuse its static component map and graph.
func Check(view *repoview.View, resolved *config.ResolvedConfig, cm *compmap.Map, graph *archgraph.Report) ([]Item, error) {
	result, err := inspect(view, resolved, cm, graph, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func inspect(view *repoview.View, resolved *config.ResolvedConfig, cm *compmap.Map, graph *archgraph.Report, now time.Time) (*inspection, error) {
	state := &inspection{
		Report:      Report{Items: []Item{}},
		additions:   make(map[string]config.ComponentConfig),
		pinVersions: make(map[string]string),
	}
	cfg := &resolved.Effective
	repo := view.Repo
	state.view = view
	var err error
	if cm == nil {
		cm, err = compmap.BuildWithOptions(repo, cfg, nil, compmap.BuildOptions{View: view})
		if err != nil {
			return nil, err
		}
	}

	for _, diagnostic := range cm.DiscoveryErrors {
		// Package manifests are checked separately for script and pin wiring.
		if filepath.Base(diagnostic.Path) != "package.json" {
			state.add("manifest_error", diagnostic.Path, diagnostic.Error(), "fix the discovery manifest")
		}
	}
	if err := project.ValidateProofs(view, cfg); err != nil {
		for _, failure := range strings.Split(err.Error(), "\n") {
			state.add("proof_link_error", "verified_by", failure, "link a regular tracked test file")
		}
	}
	if err := project.ValidateReferences(cfg, cm); err != nil {
		for _, failure := range strings.Split(err.Error(), "\n") {
			state.add("reference_error", "policy", failure, "repair the component reference")
		}
	}
	for _, rule := range cfg.Rules {
		if rule.Kind != "crutch" || rule.ReviewAfter == "" {
			continue
		}
		date, err := time.Parse(time.DateOnly, rule.ReviewAfter)
		if err != nil {
			continue
		}
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		if date.Before(today) {
			state.add("expired_crutch", rule.ID, fmt.Sprintf("rule %q passed its review date %s", rule.ID, rule.ReviewAfter), "review whether the crutch is still needed")
		}
	}
	if err := state.inspectComponents(cfg, cm); err != nil {
		return nil, err
	}
	state.inspectManifests(repo, cfg)
	if cfg.Boundaries != nil {
		rel := cfg.Boundaries.BaselinePath()
		state.baselineRaw, _, err = view.Lookup(rel, archgraph.MaxBaselineBytes)
		var baseline *archgraph.BaselineFile
		if err == nil && state.baselineRaw != nil {
			baseline, err = archgraph.ParseBaseline(state.baselineRaw)
		}
		if err == nil && baseline == nil && cfg.Boundaries.IsEnabled() && cfg.Boundaries.EffectiveMode() == "ratchet" {
			err = fmt.Errorf("ratchet requires a baseline: %s", rel)
		}
		if err != nil {
			state.add("baseline_error", rel, err.Error(), "restore a valid regular baseline")
		}
		if cfg.Boundaries.IsEnabled() && err == nil {
			if graph == nil {
				graph, err = archgraph.AnalyzeWithOptions(repo, cm, cfg.Boundaries, archgraph.AnalyzeOptions{
					View:           view,
					BaselineReader: func(string) (*archgraph.BaselineFile, error) { return baseline, nil },
				})
				if err != nil {
					return nil, err
				}
			}
			state.baseline = graph
			switch {
			case len(graph.ScanErrors) > 0:
				state.add("baseline_error", rel, graph.ScanErrors[0], "fix the boundary scan")
			case len(graph.Violations) > 0:
				state.add("boundary_violation", rel, fmt.Sprintf("%d live boundary violation(s)", len(graph.Violations)), "run: waypost graph --check-boundaries")
			case cfg.Boundaries.EffectiveMode() != "ratchet":
			case graph.GrandfatheredCount == 0:
				state.add("baseline_graduate", rel, "no boundary violations remain; promote to enforce", applyHint)
			default:
				encoded, err := archgraph.EncodeBaseline(graph.Grandfathered())
				if err != nil {
					return nil, err
				}
				candidate, err := archgraph.ParseBaseline(encoded)
				if err != nil {
					return nil, err
				}
				if archgraph.BaselineExpansion(candidate, baseline) > 0 {
					state.add("baseline_shrink", rel, "live cycles or violation counts are smaller than the recorded allowance", applyHint)
				}
			}
		}
	}
	expected, err := lockfile.Marshal(lockfile.Generate(resolved))
	if err != nil {
		return nil, err
	}
	rawLock, present, err := view.Lookup(lockfile.LockFileName, repopath.MaxPolicyBytes)
	if present && rawLock == nil {
		rawLock = []byte{}
	}
	state.lockRaw = rawLock
	if err != nil {
		state.add("lock_stale", lockfile.LockFileName, err.Error(), "restore a regular lockfile")
	} else if !bytes.Equal(rawLock, expected) && !state.blockAuthorizationChanges(rawLock, resolved) {
		state.add("lock_stale", lockfile.LockFileName, "frozen lock is missing or out of sync", applyHint)
	}
	return state, nil
}

func (s *inspection) blockAuthorizationChanges(raw []byte, resolved *config.ResolvedConfig) bool {
	const hint = "review and publish through waypost upgrade --apply"
	add := func(detail string) { s.add("authorization_changed", lockfile.LockFileName, detail, hint) }
	if raw == nil {
		if slices.ContainsFunc(resolved.Effective.Providers, func(p config.ProviderConfig) bool { return p.Authorized }) ||
			slices.ContainsFunc(resolved.Effective.Skills, func(s config.SkillRef) bool { return s.Authorized }) {
			add("missing lock for authorized providers or skills")
			return true
		}
		return false
	}
	locked, digest, err := lockfile.ParseBytes(raw)
	if err != nil {
		s.add("lock_stale", lockfile.LockFileName, err.Error(), "restore the previous lockfile")
		return true
	}
	validation := lockfile.VerifyParsed(locked, digest, resolved)
	if len(validation.AuthorizationEscalation) > 0 {
		for _, finding := range validation.AuthorizationEscalation {
			add(finding)
		}
		return true
	}
	candidate := lockfile.Generate(resolved)
	providersChanged := !slices.Equal(locked.Providers, candidate.Providers)
	skillsChanged := !slices.Equal(locked.Skills, candidate.Skills)
	if providersChanged {
		add("provider definitions changed")
	}
	if skillsChanged {
		add("skill definitions changed")
	}
	return providersChanged || skillsChanged
}

func Run(repo string, opts Options) (Report, error) {
	abs, err := filepath.Abs(repo)
	if err != nil {
		return Report{}, err
	}
	repo, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return Report{}, err
	}
	if opts.Apply && opts.Ref != "" {
		return Report{}, errors.New("--ref is read-only")
	}
	var tx *repowrite.Transaction
	if opts.Apply {
		var close func()
		tx, close, err = repowrite.Acquire(repo)
		if err != nil {
			return Report{}, err
		}
		defer close()
	} else if opts.Ref == "" {
		if err := repowrite.CheckReady(repo); err != nil {
			return Report{}, err
		}
	}
	var view *repoview.View
	if opts.Ref == "" {
		view, err = repoview.Working(repo)
	} else {
		store := repoview.NewStore(repo)
		defer store.Close()
		view, err = store.Commit(opts.Ref)
	}
	if err != nil {
		return Report{}, err
	}
	raw, err := view.Read(config.ConfigFileName, repopath.MaxPolicyBytes)
	if err != nil {
		return Report{}, err
	}
	rawLock, _, lockErr := view.Lookup(lockfile.LockFileName, repopath.MaxPolicyBytes)
	lock, _, _ := lockfile.ParseBytes(rawLock)
	load := config.LoadOptions{
		Mode: "ci", HasRootBytes: true, OverrideRootRaw: raw, PinnedRemoteSHAs: lockfile.PinnedRemoteSHAs(lock),
		PinnedBuiltins: lockfile.PinnedBuiltins(lock), RequirePinnedRemote: opts.Offline || opts.Ref != "", RequireBuiltinAnchor: opts.Ref != "", Offline: opts.Offline, ReadOnly: !opts.Apply,
	}
	load.RepoFileReader = func(rel string) ([]byte, bool, error) { return view.Lookup(rel, repopath.MaxPolicyBytes) }
	res, err := config.Load(repo, load)
	if err != nil {
		return Report{}, err
	}
	state, err := inspect(view, res, nil, nil, time.Now().UTC())
	if err != nil {
		return Report{}, err
	}
	if lockErr == nil && !repowrite.Same(rawLock, state.lockRaw) {
		return Report{}, errors.New("lock changed during sync")
	}
	if !opts.Apply || !state.Pending() {
		return state.Report, nil
	}
	err = state.apply(repo, tx, raw, res, load)
	return state.Report, err
}

func (s *inspection) apply(repo string, tx *repowrite.Transaction, raw []byte, res *config.ResolvedConfig, load config.LoadOptions) error {
	var mutations []repowrite.Mutation
	initial := raw
	for _, item := range s.Items {
		switch item.Kind {
		case "baseline_error", "proof_link_error", "reference_error", "manifest_error", "pin_source_error", "authorization_changed":
			return nil
		}
	}
	refreshLock := false
	for _, item := range s.Items {
		if item.Kind == "lock_stale" {
			if item.Hint != applyHint {
				return nil
			}
			refreshLock = true
		}
	}
	doc, err := parseDocument(raw)
	if err != nil {
		return err
	}
	var edited []int
	for i := range s.Items {
		item := &s.Items[i]
		if item.Hint != applyHint {
			continue
		}
		switch item.Kind {
		case "stale_component":
			if doc.removeComponent(item.Subject) {
				edited = append(edited, i)
			} else {
				item.Hint = "remove the component from its source config"
				item.Fixable = false
			}
		case "pin_drift":
			if doc.updatePin(item.Subject, s.pinVersions[item.Subject]) {
				edited = append(edited, i)
			} else {
				item.Hint = "update the pin in its source config"
				item.Fixable = false
			}
		}
	}

	if len(s.additions) > 0 {
		seq, ok := doc.sequence("components")
		if !ok {
			for i := range s.Items {
				if _, found := s.additions[s.Items[i].Subject]; s.Items[i].Kind == "unmapped_dir" && found {
					s.Items[i].Hint = "declare this component in an editable components list"
					s.Items[i].Fixable = false
				}
			}
		} else {
			candidate := res.Effective
			for _, i := range edited {
				if s.Items[i].Kind == "stale_component" {
					id := s.Items[i].Subject
					candidate.Components = withoutComponent(candidate.Components, id)
				}
			}
			candidate.Components = slices.Clone(candidate.Components)
			for _, rel := range sortedKeys(s.additions) {
				candidate.Components = append(candidate.Components, s.additions[rel])
			}
			if err := inferDependencies(s.view, candidate, s.additions); err != nil {
				return err
			}
			for i, item := range s.Items {
				if c, found := s.additions[item.Subject]; item.Kind == "unmapped_dir" && found {
					if err := appendComponent(seq, c); err != nil {
						return err
					}
					edited = append(edited, i)
				}
			}
		}
	}

	// Recheck before changing a baseline if this sync will also change ownership.
	var baselineItem *Item
	for i := range s.Items {
		if s.Items[i].Kind == "baseline_shrink" || s.Items[i].Kind == "baseline_graduate" {
			baselineItem = &s.Items[i]
			break
		}
	}
	if baselineItem != nil && len(edited) > 0 {
		load.OverrideRootRaw, err = doc.marshal()
		if err != nil {
			return err
		}
		candidate, err := config.Load(repo, load)
		if err != nil {
			return err
		}
		s.baseline, err = analyze(repo, &candidate.Effective)
		if err != nil {
			return err
		}
		if len(s.baseline.ScanErrors) > 0 || len(s.baseline.Violations) > 0 {
			baselineItem.Hint = "run: waypost graph --check-boundaries after the config changes"
			baselineItem.Fixable = false
			baselineItem = nil
		}
	}
	graduate := baselineItem != nil && s.baseline.GrandfatheredCount == 0
	if graduate && !doc.graduate() {
		baselineItem.Hint = "promote to enforce in the source config"
		baselineItem.Fixable = false
		baselineItem = nil
		graduate = false
	}

	if len(edited) > 0 || graduate {
		raw, err = doc.marshal()
		if err != nil {
			return err
		}
	}
	load.OverrideRootRaw = raw
	candidate, err := config.Load(repo, load)
	if err != nil {
		return err
	}
	// Inherited inputs may have changed during planning. Compare the final
	// candidate against the same previously authorized lock before publication.
	if s.blockAuthorizationChanges(s.lockRaw, candidate) {
		return nil
	}

	if err := project.ValidateProofs(s.view, &candidate.Effective); err != nil {
		return err
	}
	cm, err := compmap.BuildWithOptions(repo, &candidate.Effective, nil, compmap.BuildOptions{View: s.view})
	if err != nil {
		return err
	}
	if err := project.ValidateReferences(&candidate.Effective, cm); err != nil {
		return err
	}
	if !bytes.Equal(initial, raw) {
		mutations = append(mutations, repowrite.Mutation{Path: config.ConfigFileName, Old: initial, New: raw})
	}
	if len(edited) > 0 || graduate || refreshLock {
		data, err := lockfile.Marshal(lockfile.Generate(candidate))
		if err != nil {
			return err
		}
		parsed, digest, err := lockfile.ParseBytes(data)
		if err != nil {
			return err
		}
		if !lockfile.VerifyParsed(parsed, digest, candidate).Valid {
			return errors.New("sync candidate lock failed validation")
		}
		if !repowrite.Same(data, s.lockRaw) {
			mutations = append(mutations, repowrite.Mutation{Path: lockfile.LockFileName, Old: s.lockRaw, New: data})
		}
	}
	if baselineItem != nil {
		rel := res.Effective.Boundaries.BaselinePath()
		previous, err := archgraph.ParseBaseline(s.baselineRaw)
		if err != nil {
			return err
		}
		var data []byte
		if !graduate {
			data, err = archgraph.EncodeBaseline(s.baseline.Grandfathered())
			if err != nil {
				return err
			}
			parsed, err := archgraph.ParseBaseline(data)
			if err != nil {
				return err
			}
			if archgraph.BaselineExpansion(previous, parsed) > 0 {
				return errors.New("sync candidate would expand the baseline")
			}
		}
		mutations = append(mutations, repowrite.Mutation{Path: rel, Old: s.baselineRaw, New: data})
	}
	for _, input := range []repowrite.Mutation{{Path: config.ConfigFileName, Old: initial}, {Path: lockfile.LockFileName, Old: s.lockRaw}} {
		live, err := repowrite.Read(repo, input.Path)
		if err != nil || !repowrite.Same(live, input.Old) {
			return fmt.Errorf("%s changed during sync", input.Path)
		}
	}
	if res.Effective.Boundaries != nil {
		rel := res.Effective.Boundaries.BaselinePath()
		live, err := repowrite.Read(repo, rel)
		if err != nil || !repowrite.Same(live, s.baselineRaw) {
			return fmt.Errorf("%s changed during sync", rel)
		}
	}
	if err := tx.Commit(mutations...); err != nil {
		return err
	}
	for _, i := range edited {
		s.Items[i].Applied = true
	}
	for _, m := range mutations {
		if m.Path == lockfile.LockFileName {
			s.LockRefreshed = true
		}
	}
	if refreshLock {
		for i := range s.Items {
			if s.Items[i].Kind == "lock_stale" {
				s.Items[i].Applied = true
			}
		}
	}
	if baselineItem != nil {
		baselineItem.Applied = true
	}
	return nil
}

func analyze(repo string, cfg *config.Config) (*archgraph.Report, error) {
	cm, err := compmap.Build(repo, cfg, nil)
	if err != nil {
		return nil, err
	}
	return archgraph.Analyze(repo, cm, cfg.Boundaries)
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func withoutComponent(components []config.ComponentConfig, id string) []config.ComponentConfig {
	return slices.DeleteFunc(slices.Clone(components), func(c config.ComponentConfig) bool { return c.ID == id })
}
