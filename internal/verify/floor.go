package verify

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
)

func checkArchitecture(target, head *project.Snapshot, enforce bool, baseline *archgraph.BaselineFile, blockingFloor []string) (CheckResult, bool) {
	start := time.Now()
	hasBase := enforce && target.Boundaries().IsEnabled()
	hasHead := head.Boundaries().IsEnabled()
	check := CheckResult{ID: "waypost-boundaries", Command: "waypost graph --check-boundaries (built-in)",
		Lane: "full", DefinitionSource: "head", SelectionReason: "architecture policy", FromBaseFloor: hasBase}
	if hasBase {
		check.DefinitionSource = "base"
		if hasHead {
			check.DefinitionSource = "both"
		}
	}
	var baseReport, headReport *archgraph.Report
	var diagnostics []string
	scanFailed := false
	var live []archgraph.Violation
	analyze := func(bounds *config.BoundariesConfig, components *compmap.Map, read func(string) (*archgraph.BaselineFile, error), definitionView *repoview.View) *archgraph.Report {
		report, err := archgraph.AnalyzeWithOptions(head.View.Repo, components, bounds, archgraph.AnalyzeOptions{View: head.View, BaselineReader: read, ResolutionView: definitionView})
		if err != nil {
			scanFailed = true
			diagnostics = append(diagnostics, "boundary analysis error: "+err.Error())
		}
		return report
	}
	if hasBase {
		b := baseBoundariesForFloor(target, head)
		check.Required = b.EffectiveMode() != "warn"
		read := func(string) (*archgraph.BaselineFile, error) { return baseline, nil }
		cm := architectureFloorMap(target, head)
		baseReport = analyze(b, cm, read, nil)
		if baseReport != nil && (check.Required || !hasHead || head.Boundaries().EffectiveMode() == "warn") {
			live = append(live, baseReport.Violations...)
			// Alias chains can extend arbitrary filenames. Always resolve the
			// candidate imports again with the trusted target's chain.
			if target.View.SHA != head.View.SHA {
				trustedAliases := analyze(b, cm, read, target.View)
				if trustedAliases != nil {
					scanFailed = scanFailed || len(trustedAliases.ScanErrors) > 0
					live = mergeViolations(live, trustedAliases.Violations)
				}
			}
		}
	}
	if hasHead {
		b := head.Boundaries()
		check.Required = check.Required || b.EffectiveMode() != "warn"
		matchesBase := hasBase && reflect.DeepEqual(b, target.Boundaries()) && reflect.DeepEqual(head.Map.Components, target.Map.Components)
		if matchesBase {
			own, _ := head.RecordedBaseline()
			matchesBase = reflect.DeepEqual(own, baseline)
		}
		if matchesBase {
			headReport = baseReport
		} else {
			headReport = analyze(b, head.Map, head.Baseline, nil)
			if headReport != nil {
				live = mergeViolations(live, headReport.Violations)
			}
		}
	}
	report := headReport
	if report == nil {
		report = baseReport
	}
	for _, finding := range blockingFloor {
		if strings.Contains(finding, "boundar") {
			diagnostics = append(diagnostics, finding)
			check.Required = true
		}
	}
	check.DurationMS = time.Since(start).Milliseconds()
	check.Status = StatusPass
	if len(live) > 0 || len(diagnostics) > 0 {
		check.ExitCode = 1
		check.Status = StatusWarn
		if check.Required || len(diagnostics) > 0 {
			check.Status = StatusFail
		}
		check.Reason = fmt.Sprintf("%d boundary violation(s)", len(live))
		if len(diagnostics) > 0 {
			check.Reason += "; boundary policy preflight failed"
		}
		for i, v := range live {
			if i == 12 {
				diagnostics = append(diagnostics, fmt.Sprintf("... +%d more violations", len(live)-i))
				break
			}
			diagnostics = append(diagnostics, fmt.Sprintf("[%s] %s", v.RuleID, v.Message))
		}
		check.OutputExcerpt = RedactAndTrim(strings.Join(diagnostics, "\n"), maxExcerptBytes)
	} else if report != nil {
		check.Reason = fmt.Sprintf("0 violations (%d files, %d imports, %d edges)", report.FilesScanned, report.ImportsScanned, len(report.Edges))
	}
	if report != nil && report.BoundariesMode == "ratchet" {
		check.Reason += fmt.Sprintf("; %d grandfathered, %d resolved", report.GrandfatheredCount, report.ResolvedBaselineCount)
	}
	return check, !scanFailed && (baseReport == nil || len(baseReport.ScanErrors) == 0) &&
		(headReport == nil || len(headReport.ScanErrors) == 0)
}

func mergeViolations(base, head []archgraph.Violation) []archgraph.Violation {
	type key struct {
		fingerprint, spec string
		line              int
	}
	keyOf := func(v archgraph.Violation) key {
		spec, line := v.Specifier, v.Line
		if v.Kind == "cycle" {
			spec, line = "", 0
		}
		if v.Kind == "scan-error" {
			spec = v.Message
		}
		return key{archgraph.ViolationFingerprint(v), spec, line}
	}
	count := make(map[key]int)
	for _, v := range base {
		count[keyOf(v)]++
	}
	for _, v := range head {
		k := keyOf(v)
		if count[k] > 0 {
			count[k]--
		} else {
			base = append(base, v)
		}
	}
	return base
}

// Newly declared components can enter the floor's graph only under entirely
// new roots. Existing ownership and dependency edges stay governed by base.
func architectureFloorMap(target, head *project.Snapshot) *compmap.Map {
	components := slices.Clone(target.Map.Components)
	oldIDs := make(map[string]bool)
	for _, c := range components {
		oldIDs[c.ID] = true
	}
	additions := make(map[string]bool)
	for _, c := range head.Map.Components {
		if oldIDs[c.ID] || c.Root == "." || c.Provenance != compmap.ProvenanceDeclared {
			continue
		}
		if slices.ContainsFunc(c.Paths, func(p string) bool { return p != c.Root && !strings.HasPrefix(p, c.Root+"/") }) {
			continue
		}
		if owner := target.Map.PrimaryOwner(c.Root + "/.waypost-ownership-probe"); owner != "" {
			if slices.ContainsFunc(components, func(prior compmap.Component) bool {
				return prior.ID == owner && (prior.Root != "." || prior.Provenance == compmap.ProvenanceDeclared)
			}) {
				continue
			}
		}
		exists := false
		for rel := range target.View.Files {
			if rel == c.Root || strings.HasPrefix(rel, c.Root+"/") {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		additions[c.ID] = true
		components = append(components, c)
	}
	if len(additions) == 0 {
		return target.Map
	}
	for i := range components {
		c := &components[i]
		if additions[c.ID] {
			continue
		}
		for _, candidate := range head.Map.Components {
			if candidate.ID != c.ID {
				continue
			}
			for _, dep := range candidate.DependsOn {
				if additions[dep] {
					c.DependsOn = append(slices.Clone(c.DependsOn), dep)
				}
			}
			break
		}
	}
	return &compmap.Map{Components: components}
}

// baseBoundariesForFloor retains the trusted target's exclusions while permitting
// a reviewed head ignore_paths entry to exclude a file that was ALREADY oversized
// (>MaxSourceFileBytes) in the target tree. Newly added or newly padded files
// remain governed strictly by target exclusions.
func baseBoundariesForFloor(target, head *project.Snapshot) *config.BoundariesConfig {
	b := target.Boundaries()
	if b == nil || head == nil || head.Boundaries() == nil || len(head.Boundaries().IgnorePaths) == 0 || target.View == nil || head.View == nil {
		return b
	}
	headIgnore := compmap.CompileGlobs(head.Boundaries().IgnorePaths)
	baseIgnore := compmap.CompileGlobs(b.IgnorePaths)
	var extra []string
	for rel, headEntry := range head.View.Files {
		if !headEntry.Regular() || headEntry.Size <= archgraph.MaxSourceFileBytes || !archgraph.IsSupportedSource(rel) {
			continue
		}
		if compmap.MatchCompiled(baseIgnore, rel) || !compmap.MatchCompiled(headIgnore, rel) {
			continue
		}
		oldEntry, ok := target.View.Files[rel]
		if ok && oldEntry.Regular() && oldEntry.Size > archgraph.MaxSourceFileBytes {
			extra = append(extra, rel)
		}
	}
	if len(extra) == 0 {
		return b
	}
	slices.Sort(extra)
	cp := *b
	cp.IgnorePaths = append(slices.Clone(b.IgnorePaths), extra...)
	return &cp
}
