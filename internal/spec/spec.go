// Package spec builds a living specification from repository facts.
package spec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/history"
	"github.com/Farzin312/waypost/internal/pins"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/verify"
)

type Report struct {
	Version      string             `json:"spec_version"`
	Snapshot     repoview.Identity  `json:"snapshot"`
	PolicyDigest string             `json:"policy_digest"`
	Components   []Component        `json:"components"`
	Rules        []Rule             `json:"rules"`
	Checks       []config.Check     `json:"checks"`
	Pins         []pins.Observation `json:"pins"`
	Boundaries   Boundaries         `json:"boundaries"`
	CoverageGaps []string           `json:"coverage_gaps,omitempty"`
	Diagnostics  []string           `json:"diagnostics"`
	History      *history.Result    `json:"history,omitempty"`
	Receipt      *Receipt           `json:"receipt,omitempty"`
}

type Fact struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

type Rule struct {
	config.Rule
	config.RuleOrigin
}

type Component struct {
	ID                string   `json:"id"`
	Root              string   `json:"root"`
	Paths             []string `json:"paths"`
	Source            string   `json:"source"`
	Entrypoints       []Fact   `json:"entrypoints"`
	PublicEntrypoints []Fact   `json:"public_entrypoints"`
	DependsOn         []Fact   `json:"depends_on"`
	DependedBy        []Fact   `json:"depended_by"`
	Tests             []Fact   `json:"tests"`
	Rules             []string `json:"rules,omitempty"`
	Checks            []string `json:"checks,omitempty"`
}

type Boundaries struct {
	Policy              *config.BoundariesConfig  `json:"policy,omitempty"`
	Mode                string                    `json:"mode"`
	ScanComplete        bool                      `json:"scan_complete"`
	FilesScanned        int                       `json:"files_scanned"`
	Violations          int                       `json:"violations"`
	Grandfathered       int                       `json:"grandfathered"`
	BaselineEntries     int                       `json:"baseline_entries"`
	BaselineOccurrences int                       `json:"baseline_occurrences"`
	Baseline            []archgraph.BaselineEntry `json:"baseline,omitempty"`
}

type Receipt struct {
	HeadSHA string               `json:"head_sha"`
	Outcome string               `json:"outcome"`
	Checks  []verify.CheckResult `json:"checks"`
}

func Build(p *project.Snapshot, filter string) (Report, error) {
	out := Report{Version: "1", Snapshot: p.View.Identity, Components: []Component{}, Rules: []Rule{}, Checks: []config.Check{}, Pins: []pins.Observation{}, Diagnostics: []string{}, CoverageGaps: p.Map.CoverageGaps}
	if filter != "" && !slices.ContainsFunc(p.Map.Components, func(c compmap.Component) bool { return c.ID == filter }) {
		return out, fmt.Errorf("unknown component %q", filter)
	}
	cfg := p.Config()
	if cfg == nil {
		cfg = &config.Config{}
		out.Diagnostics = append(out.Diagnostics, "no Waypost policy in this snapshot")
	} else {
		out.PolicyDigest = p.Policy.PolicyDigest
		if err := project.ValidateProofs(p.View, cfg); err != nil {
			out.Diagnostics = append(out.Diagnostics, strings.Split(err.Error(), "\n")...)
		}
		if err := project.ValidateReferences(cfg, p.Map); err != nil {
			out.Diagnostics = append(out.Diagnostics, strings.Split(err.Error(), "\n")...)
		}
		for _, r := range cfg.Rules {
			out.Rules = append(out.Rules, Rule{r, p.Policy.RuleOrigins[r.ID]})
		}
	}
	graph, err := p.Graph()
	out.Boundaries = Boundaries{Policy: cfg.Boundaries, Mode: "off"}
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, err.Error())
	}
	if graph != nil {
		out.Boundaries.Mode = graph.BoundariesMode
		out.Boundaries.ScanComplete = len(graph.ScanErrors) == 0
		out.Boundaries.FilesScanned = graph.FilesScanned
		out.Boundaries.Violations = len(graph.Violations)
		out.Boundaries.Grandfathered = graph.GrandfatheredCount
		out.Diagnostics = append(out.Diagnostics, graph.ScanErrors...)
	}
	baseline, err := p.RecordedBaseline()
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, err.Error())
	}
	if baseline != nil {
		out.Boundaries.BaselineEntries = len(baseline.Entries)

		for _, entry := range baseline.Entries {
			out.Boundaries.BaselineOccurrences += entry.Occurrences()
			if filter == "" || entry.From == filter || entry.To == filter || slices.Contains(entry.CycleMembers, filter) {
				out.Boundaries.Baseline = append(out.Boundaries.Baseline, entry)
			}
		}
	}

	tests := make(map[string][]Fact)
	paths := make(map[string][]gitdiff.Change)
	for _, rel := range p.View.Paths() {
		test := p.View.Files[rel].Regular() && project.TestFile(rel)
		for _, owner := range p.Map.OwnersOf(rel) {
			if filter != "" && owner != filter {
				continue
			}
			paths[owner] = append(paths[owner], gitdiff.Change{Status: "M", Path: rel})
			if test {
				tests[owner] = append(tests[owner], Fact{rel, "test_convention"})
			}
		}
	}
	imports, importers := make(map[string][]Fact), make(map[string][]Fact)
	if graph != nil {
		for _, edge := range graph.Edges {
			imports[edge.From] = append(imports[edge.From], Fact{edge.To, "import"})
			importers[edge.To] = append(importers[edge.To], Fact{edge.From, "import"})
		}
	}
	declared := make(map[string]config.ComponentConfig)
	for _, c := range cfg.Components {
		declared[c.ID] = c
	}
	allChecks := make(map[string]bool)
	for _, c := range p.Map.Components {
		if filter != "" && c.ID != filter {
			continue
		}
		source := "manifest"
		if c.Provenance == compmap.ProvenanceDeclared {
			source = "declared"
		}
		item := Component{ID: c.ID, Root: c.Root, Paths: c.Paths, Source: source, Entrypoints: []Fact{}, PublicEntrypoints: []Fact{}, DependsOn: []Fact{}, DependedBy: []Fact{}, Tests: []Fact{}}
		item.Tests = append(item.Tests, tests[c.ID]...)
		for _, r := range cfg.Rules {
			item.Rules = append(item.Rules, r.ID)
		}
		for _, entry := range c.Entrypoints {
			origin := "manifest"
			if slices.Contains(declared[c.ID].Entrypoints, entry) {
				origin = "declared"
			}
			item.Entrypoints = append(item.Entrypoints, Fact{entry, origin})
		}
		for _, dep := range c.DependsOn {
			origin := "manifest"
			if slices.Contains(declared[c.ID].DependsOn, dep) {
				origin = "declared"
			}
			item.DependsOn = append(item.DependsOn, Fact{dep, origin})
		}
		for _, dep := range c.DependedBy {
			origin := "manifest"
			if slices.Contains(declared[dep].DependsOn, c.ID) {
				origin = "declared"
			}
			item.DependedBy = append(item.DependedBy, Fact{dep, origin})
		}
		item.DependsOn = append(item.DependsOn, imports[c.ID]...)
		item.DependedBy = append(item.DependedBy, importers[c.ID]...)
		if cfg.Boundaries != nil {
			for _, rule := range cfg.Boundaries.Rules {
				if archgraph.MatchesComponentPattern(rule.Target, c.ID) {
					for _, ep := range rule.PublicEntrypoints {
						item.PublicEntrypoints = append(item.PublicEntrypoints, Fact{ep, "declared"})
					}
				}
			}
		}
		side := changeplan.Side{Config: cfg, Map: p.Map}
		scope := changeplan.ComponentChecks(side, c.ID, paths[c.ID])
		for _, check := range scope {
			if check.Selected || slices.Contains(c.Checks, check.Check.ID) || slices.Contains(check.Check.Components, c.ID) {
				item.Checks = append(item.Checks, check.Check.ID)
			}
		}
		for _, id := range item.Checks {
			allChecks[id] = true
		}
		out.Components = append(out.Components, item)
	}
	for _, c := range cfg.Checks {
		if filter == "" || allChecks[c.ID] {
			out.Checks = append(out.Checks, c)
		}
	}
	for _, pin := range cfg.Pins {
		consumer := pin.ConsumerComponent
		if consumer == "" {
			consumer = pin.Consumer
		}
		if filter == "" || consumer == filter || slices.Contains(out.Components[0].Checks, pin.CompatibilityCheck) {
			out.Pins = append(out.Pins, pins.Inspect(p.View, pin))
		}
	}

	slices.Sort(out.Diagnostics)
	out.Diagnostics = slices.Compact(out.Diagnostics)
	return out, nil
}

func (r *Report) AttachReceipt(receipt verify.Receipt) error {
	if r.Snapshot.Kind != "commit" || receipt.Git.Dirty || receipt.Git.HeadSHA != r.Snapshot.SHA ||
		receipt.Digests.HeadPolicyDigest != r.PolicyDigest {
		return fmt.Errorf("verification receipt does not match the selected immutable snapshot")
	}
	r.Receipt = &Receipt{HeadSHA: receipt.Git.HeadSHA, Outcome: receipt.Summary.Outcome, Checks: receipt.Checks}
	return nil
}
