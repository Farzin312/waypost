// Package syncer checks the live repository for drift and applies reviewable config changes.
package syncer

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/upgrade"
)

const applyHint = "run: waypost sync --apply"

type Item struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	Hint    string `json:"hint"`
	Applied bool   `json:"applied,omitempty"`
}

func (i Item) Actionable() bool { return i.Kind != "unwired_script" && i.Kind != "empty_component" }

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
}

type inspection struct {
	Report
	additions   map[string]config.ComponentConfig
	pinVersions map[string]string
	baseline    *archgraph.Report
}

func (s *inspection) add(kind, subject, detail, hint string) {
	s.Items = append(s.Items, Item{Kind: kind, Subject: subject, Detail: detail, Hint: hint})
}

// Check reports drift against the canonical resolved config. A caller can reuse
// a graph already collected from the same static map and boundary config.
func Check(repo string, resolved *config.ResolvedConfig, graph *archgraph.Report) ([]Item, error) {
	result, err := inspect(repo, resolved, graph)
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func inspect(repo string, resolved *config.ResolvedConfig, graph *archgraph.Report) (*inspection, error) {
	state := &inspection{
		Report:      Report{Items: []Item{}},
		additions:   make(map[string]config.ComponentConfig),
		pinVersions: make(map[string]string),
	}
	cfg := &resolved.Effective
	cm, err := compmap.Build(repo, cfg, nil)
	if err != nil {
		return nil, err
	}
	if err := state.inspectComponents(repo, cfg, cm); err != nil {
		return nil, err
	}
	state.inspectManifests(repo, cfg)
	if cfg.Boundaries.IsEnabled() && cfg.Boundaries.EffectiveMode() == "ratchet" {
		if graph == nil {
			graph, err = archgraph.Analyze(repo, cm, cfg.Boundaries)
			if err != nil {
				return nil, err
			}
		}
		state.baseline = graph
		rel := cfg.Boundaries.BaselinePath()
		switch {
		case len(graph.ScanErrors) > 0:
			state.add("baseline_error", rel, graph.ScanErrors[0], "fix the boundary scan and ensure the baseline is valid")
		case len(graph.Violations) > 0:
			// Verification reports new violations. Sync may only shrink resolved debt.
		case graph.GrandfatheredCount == 0:
			state.add("baseline_graduate", rel, "no boundary violations remain; promote to enforce", applyHint)
		case graph.ResolvedBaselineCount > 0:
			state.add("baseline_shrink", rel, fmt.Sprintf("%d baseline violation occurrence(s) are resolved", graph.ResolvedBaselineCount), applyHint)
		}
	}
	expected, err := lockfile.Marshal(lockfile.Generate(resolved))
	if err != nil {
		return nil, err
	}
	rawLock, err := readLock(repo)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		state.add("lock_stale", lockfile.LockFileName, err.Error(), "restore a regular lockfile or remove it and rerun sync")
	case !bytes.Equal(rawLock, expected):
		state.add("lock_stale", lockfile.LockFileName, "frozen lock is missing or out of sync", applyHint)
	}
	return state, nil
}

func Run(repo string, opts Options) (Report, error) {
	raw, err := readSyncFile(repo, config.ConfigFileName)
	if err != nil {
		return Report{}, err
	}
	if len(raw) == 0 {
		return Report{}, fmt.Errorf("%s is empty", config.ConfigFileName)
	}
	rawLock, _ := readLock(repo)
	lock, _, _ := lockfile.ParseBytes(rawLock)
	load := config.LoadOptions{
		Mode: "ci", OverrideRootRaw: raw, PinnedRemoteSHAs: lockfile.PinnedRemoteSHAs(lock),
		RequirePinnedRemote: opts.Offline, Offline: opts.Offline,
	}
	res, err := config.Load(repo, load)
	if err != nil {
		return Report{}, err
	}
	state, err := inspect(repo, res, nil)
	if err != nil {
		return Report{}, err
	}
	if !opts.Apply || !state.Pending() {
		return state.Report, nil
	}
	err = state.apply(repo, raw, res, load)
	return state.Report, err
}

func readLock(repo string) ([]byte, error) {
	return readSyncFile(repo, lockfile.LockFileName)
}

func readSyncFile(repo, rel string) ([]byte, error) {
	return compmap.ReadBoundedRegularFile(repo, filepath.Join(repo, rel), compmap.MaxStaticDiscoveryBytes)
}

func (s *inspection) apply(repo string, raw []byte, res *config.ResolvedConfig, load config.LoadOptions) error {
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
			}
		case "pin_drift":
			if doc.updatePin(item.Subject, s.pinVersions[item.Subject]) {
				edited = append(edited, i)
			} else {
				item.Hint = "update the pin in its source config"
			}
		}
	}

	if len(s.additions) > 0 {
		seq, ok := doc.sequence("components")
		if !ok {
			for i := range s.Items {
				if _, found := s.additions[s.Items[i].Subject]; s.Items[i].Kind == "unmapped_dir" && found {
					s.Items[i].Hint = "declare this component in an editable components list"
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
			if err := inferDependencies(repo, candidate, s.additions); err != nil {
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
			baselineItem = nil
		}
	}
	graduate := baselineItem != nil && s.baseline.GrandfatheredCount == 0
	if graduate && !doc.graduate() {
		baselineItem.Hint = "promote to enforce in the source config"
		baselineItem = nil
		graduate = false
	}

	if len(edited) > 0 || graduate {
		raw, err = doc.marshal()
		if err != nil {
			return err
		}
	}
	if len(edited) > 0 || graduate || refreshLock {
		updated, err := upgrade.Run(repo, upgrade.Options{
			Apply: true, Offline: load.Offline, CandidateConfig: raw, ExpectedConfigSHA: res.RawRootSHA256,
			ReadFile: readSyncFile,
		})
		if err != nil {
			return err
		}
		s.LockRefreshed = updated.Applied
		for _, i := range edited {
			s.Items[i].Applied = true
		}
		for i := range s.Items {
			if s.Items[i].Kind == "lock_stale" {
				s.Items[i].Applied = true
			}
		}
	}
	if baselineItem != nil {
		rel := res.Effective.Boundaries.BaselinePath()
		if graduate {
			err = archgraph.RemoveBaseline(repo, rel)
		} else {
			err = shrinkBaseline(repo, rel, s.baseline)
		}
		baselineItem.Applied = err == nil
	}
	return err
}

func analyze(repo string, cfg *config.Config) (*archgraph.Report, error) {
	cm, err := compmap.Build(repo, cfg, nil)
	if err != nil {
		return nil, err
	}
	return archgraph.Analyze(repo, cm, cfg.Boundaries)
}

func shrinkBaseline(repo, rel string, report *archgraph.Report) error {
	current, err := archgraph.LoadBaseline(repo, rel)
	if err != nil {
		return err
	}
	existing := make(map[string]int, len(current.Entries))
	for _, e := range current.Entries {
		existing[e.Fingerprint] = e.Occurrences()
	}
	for _, v := range report.Grandfathered() {
		key := archgraph.ViolationFingerprint(v)
		if existing[key] == 0 {
			return errors.New("baseline changed during sync; rerun waypost sync")
		}
		existing[key]--
	}
	return archgraph.SaveBaseline(repo, rel, report.Grandfathered())
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func withoutComponent(components []config.ComponentConfig, id string) []config.ComponentConfig {
	return slices.DeleteFunc(slices.Clone(components), func(c config.ComponentConfig) bool { return c.ID == id })
}
