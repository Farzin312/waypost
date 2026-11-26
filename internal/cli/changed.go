package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/history"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/workstate"
)

const changedContextBytes = 16 << 10

type ContextChanged struct {
	SchemaVersion           string                 `json:"schema_version"`
	Snapshot                repoview.Identity      `json:"snapshot"`
	BaseRef                 string                 `json:"base_ref,omitempty"`
	BaseSHA                 string                 `json:"base_sha,omitempty"`
	HeadSHA                 string                 `json:"head_sha,omitempty"`
	Dirty                   bool                   `json:"dirty"`
	Impact                  compmap.Impact         `json:"impact"`
	Invariants              []contextRule          `json:"invariants,omitempty"`
	SelectedChecks          []string               `json:"selected_checks,omitempty"`
	CoverageGaps            []string               `json:"coverage_gaps,omitempty"`
	WorkState               *workstate.Status      `json:"work_state,omitempty"`
	RecentCommits           []history.RecentCommit `json:"recent_commits,omitempty"`
	AffectedPaths           []string               `json:"affected_paths,omitempty"`
	FailClosedWouldEscalate bool                   `json:"fail_closed_would_escalate"`
	PlanComplete            bool                   `json:"plan_complete"`
	SyncDrift               []string               `json:"sync_drift,omitempty"`
	Policy                  *contextReview         `json:"policy,omitempty"`
	Omitted                 map[string]int         `json:"omitted,omitempty"`
}

type contextReview struct {
	Recommended bool                      `json:"review_recommended"`
	Reasons     []changeplan.ReviewReason `json:"review_reasons"`
}

type contextRule struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

func changedContext(w io.Writer, p *project.Snapshot, lock *lockfile.VerifyResult, base string, recent int, format string) error {
	snap := &gitdiff.Snapshot{}
	var err error
	if p.View.GitDir != "" {
		snap, err = gitdiff.InspectWorktree(p.View.Repo, base, "local", p.View.SHA)
	}
	if err != nil {
		return err
	}
	result := ContextChanged{
		SchemaVersion: "1", Snapshot: p.View.Identity, BaseRef: clip(snap.BaseRef, 160), BaseSHA: snap.BaseSHA, HeadSHA: snap.HeadSHA,
		Dirty: snap.Dirty, AffectedPaths: slices.Clone(snap.AffectedPaths), CoverageGaps: slices.Clone(p.Map.CoverageGaps),
		Omitted: make(map[string]int),
	}
	store := repoview.NewStore(p.View.Repo)
	defer store.Close()
	var old changeplan.Side
	if snap.MergeBaseError != "" {
		result.CoverageGaps = append(result.CoverageGaps, snap.MergeBaseError)
	} else if snap.BaseSHA != "" {
		view, err := store.Tree(snap.BaseSHA)
		if err == nil {
			var prior *project.Snapshot
			prior, err = project.Load(view, config.LoadOptions{Offline: true}, compmap.BuildOptions{})
			if err == nil {
				old = changeplan.Side{Map: prior.Map, Config: prior.Config()}
				result.PlanComplete = true
			}
		}
		if err != nil {
			result.CoverageGaps = append(result.CoverageGaps, "base snapshot unavailable: "+err.Error())
		}
	}
	side := changeplan.Side{Map: p.Map, Config: p.Config()}
	plan := changeplan.Create(old, side, snap.Changes, false, result.PlanComplete, false)
	result.Impact = plan.Impact
	result.FailClosedWouldEscalate = plan.Full
	if len(plan.Review) > 0 {
		result.Policy = &contextReview{true, plan.Review}
	}
	for _, rule := range plan.Invariants {
		result.Invariants = append(result.Invariants, contextRule{clip(rule.ID, 96), clip(rule.Summary, 220)})
	}
	for _, check := range plan.Checks {
		if check.Selected {
			result.SelectedChecks = append(result.SelectedChecks, check.Check.ID)
		}
	}
	if lock != nil && !lock.Valid {
		result.SyncDrift = append(result.SyncDrift, "frozen lock is missing or out of sync")
	}
	if p.Config() == nil {
		result.CoverageGaps = append(result.CoverageGaps, "no Waypost policy")
	}
	if p.Boundaries().EffectiveMode() == "ratchet" {
		if _, err := p.RecordedBaseline(); err != nil {
			result.SyncDrift = append(result.SyncDrift, "boundary baseline: "+err.Error())
		}
	}
	state := workstate.Read(p.View, workstate.Selection{BaseSHA: snap.BaseSHA, TargetSHA: snap.TargetSHA, PlanDigest: plan.Digest()})
	state.Diagnostic = clip(state.Diagnostic, 200)
	state.UntestedComponents = changeplan.Untested(plan.Changes, project.ProductionFile, project.TestFile)
	state.Overall = clip(state.Overall, 32)
	if len(snap.Changes) > 0 || snap.Dirty || state.Verification == "stale" || state.Diagnostic != "" || state.Overall != "" && state.Overall != "PASS" {
		result.WorkState = &state
	}
	if recent > 0 {
		result.RecentCommits, err = history.Recent(p.View.Repo, p.View.SHA, p.Map, plan.Impact.DirectComponents, min(20, recent))
		if err != nil {
			result.CoverageGaps = append(result.CoverageGaps, "recent history unavailable: "+err.Error())
		}
	}
	result.bound()
	if format == "json" {
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(raw))
		return err
	}
	renderChanged(w, result)
	return nil
}

func (r *ContextChanged) bound() {
	groups := []struct {
		name         string
		list         *[]string
		limit, width int
	}{
		{"paths", &r.AffectedPaths, 24, 160}, {"unmapped_paths", &r.Impact.UnmappedPaths, 12, 160},
		{"components", &r.Impact.DirectComponents, 16, 96}, {"dependents", &r.Impact.TransitiveDependents, 16, 96},
		{"checks", &r.SelectedChecks, 16, 96}, {"coverage_gaps", &r.CoverageGaps, 8, 200},
		{"pins", &r.Impact.TriggeredPins, 8, 96}, {"sync_drift", &r.SyncDrift, 4, 160},
	}
	if r.WorkState != nil {
		for _, item := range []struct {
			name         string
			list         *[]string
			limit, width int
		}{
			{"untested_components", &r.WorkState.UntestedComponents, 12, 96},
			{"failing_checks", &r.WorkState.Failing, 12, 96}, {"unrun_required_checks", &r.WorkState.Unrun, 12, 96},
		} {
			groups = append(groups, item)
		}
	}
	for _, group := range groups {
		if n := len(*group.list) - group.limit; n > 0 {
			r.Omitted[group.name] = n
			*group.list = (*group.list)[:group.limit]
		}
		for i, value := range *group.list {
			(*group.list)[i] = clip(value, group.width)
		}
	}
	trim := func(name string, size int, reduce func()) bool {
		if size == 0 {
			return false
		}
		r.Omitted[name]++
		reduce()
		return true
	}
	for len(r.Invariants) > 12 {
		trim("invariants", len(r.Invariants), func() { r.Invariants = r.Invariants[:len(r.Invariants)-1] })
	}
	for i := range r.RecentCommits {
		r.RecentCommits[i].Component = clip(r.RecentCommits[i].Component, 96)
		r.RecentCommits[i].Subject = clip(r.RecentCommits[i].Subject, 160)
	}
	if r.Policy != nil {
		for i := range r.Policy.Reasons {
			for j, s := range r.Policy.Reasons[i].Items {
				r.Policy.Reasons[i].Items[j] = clip(s, 120)
			}
		}
	}
	for {
		raw, _ := json.Marshal(r)
		if len(raw)+1 <= changedContextBytes {
			break
		}
		switch {
		case trim("paths", len(r.AffectedPaths), func() { r.AffectedPaths = r.AffectedPaths[:len(r.AffectedPaths)-1] }):
		case trim("unmapped_paths", len(r.Impact.UnmappedPaths), func() { r.Impact.UnmappedPaths = r.Impact.UnmappedPaths[:len(r.Impact.UnmappedPaths)-1] }):
		case trim("recent_commits", len(r.RecentCommits), func() { r.RecentCommits = r.RecentCommits[:len(r.RecentCommits)-1] }):
		case trim("invariants", len(r.Invariants), func() { r.Invariants = r.Invariants[:len(r.Invariants)-1] }):
		case r.Policy != nil:
			r.Omitted["review_reasons"] += len(r.Policy.Reasons)
			r.Policy = nil
		default:
			for i := range groups {
				group := &groups[i]
				if trim(group.name, len(*group.list), func() { *group.list = (*group.list)[:len(*group.list)-1] }) {
					break
				}
			}
		}
	}
}

func clip(value string, width int) string {
	value = history.EscapeControls(value)
	if len(value) <= width {
		return value
	}
	end := 0
	for i := range value {
		if i > width-3 {
			break
		}
		end = i
	}
	return value[:end] + "..."
}

func renderChanged(w io.Writer, r ContextChanged) {
	fmt.Fprintf(w, "Waypost change context · base %s · dirty %t\n", shortHash(r.BaseSHA), r.Dirty)
	for _, group := range []struct {
		name string
		list []string
	}{
		{"Touched components", r.Impact.DirectComponents}, {"Reverse impact", r.Impact.TransitiveDependents},
		{"Selected checks", r.SelectedChecks}, {"Coverage gaps", r.CoverageGaps},
	} {
		if len(group.list) > 0 {
			fmt.Fprintf(w, "%s %s\n", group.name, strings.Join(group.list, ", "))
		}
	}
	for _, rule := range r.Invariants {
		fmt.Fprintf(w, "- %s %s\n", rule.ID, rule.Summary)
	}
	if r.WorkState != nil {
		fmt.Fprintf(w, "Verification %s %s\n", r.WorkState.Verification, r.WorkState.Overall)
		if r.WorkState.Diagnostic != "" {
			fmt.Fprintln(w, r.WorkState.Diagnostic)
		}
		if len(r.WorkState.Failing) > 0 {
			fmt.Fprintf(w, "Failing checks %s\n", strings.Join(r.WorkState.Failing, ", "))
		}
		if len(r.WorkState.Unrun) > 0 {
			fmt.Fprintf(w, "Required checks unrun %s\n", strings.Join(r.WorkState.Unrun, ", "))
		}
		if len(r.WorkState.UntestedComponents) > 0 {
			fmt.Fprintf(w, "Untested changes %s\n", strings.Join(r.WorkState.UntestedComponents, ", "))
		}
	}
	for _, commit := range r.RecentCommits {
		fmt.Fprintf(w, "- %s %s %s\n", shortHash(commit.SHA), commit.Component, commit.Subject)
	}
	for _, drift := range r.SyncDrift {
		fmt.Fprintln(w, drift)
	}
	if r.Policy != nil {
		for _, reason := range r.Policy.Reasons {
			fmt.Fprintf(w, "Review %s %s\n", reason.Code, strings.Join(reason.Items, ", "))
		}
	}
	if r.FailClosedWouldEscalate {
		fmt.Fprintln(w, "Full verification selected")
	}
	if len(r.Omitted) > 0 {
		var names []string
		for name := range r.Omitted {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			fmt.Fprintf(w, "Omitted %d %s\n", r.Omitted[name], name)
		}
	}
}
