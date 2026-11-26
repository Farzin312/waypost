package policy

import (
	"fmt"
	"sort"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
)

// SelectedCheck binds a check to whether it will run and why.
type SelectedCheck struct {
	Check    config.Check `json:"check"`
	Selected bool         `json:"selected"`
	Reason   string       `json:"reason"`
	FromBase bool         `json:"from_base,omitempty"`
}

// PlanResult captures policy authority decisions, trust-boundary escalations,
// base-branch policy floor enforcement, and the final check execution plan.
type PlanResult struct {
	TrustBoundaryTriggered bool             `json:"trust_boundary_triggered"`
	PolicyFloorEnforced    bool             `json:"policy_floor_enforced"`
	FullRepoEscalated      bool             `json:"full_repo_escalated"`
	EscalationReasons      []string         `json:"escalation_reasons,omitempty"`
	TamperingFindings      []string         `json:"tampering_findings,omitempty"`
	Impact                 compmap.Impact   `json:"impact"`
	Checks                 []SelectedCheck  `json:"checks"`
}

// Plan determines which checks must run under the active policy and mode.
// In "ci" mode, it enforces a base-branch policy floor via `git show <base>:.waypost.yaml`,
// escalates on trust-boundary edits (evaluating both sides of renames & deletions),
// and fails closed to the full repo gate on unmapped paths or missing merge-bases.
func Plan(repoDir, mode string, resolved *config.ResolvedConfig, cm *compmap.Map, snap *gitdiff.Snapshot, runAll bool) (*PlanResult, error) {
	cfg := resolved.Effective
	res := &PlanResult{}

	// Collect effective trust paths (global + component-level + hardcoded policy files).
	trustPaths := append([]string{
		config.ConfigFileName,
		".waypost.lock",
		".github/workflows/**",
	}, cfg.Policy.TrustPaths...)
	for _, c := range cm.Components {
		trustPaths = append(trustPaths, c.TrustPaths...)
	}

	effectiveChecks := append([]config.Check(nil), cfg.Checks...)
	effectiveByID := make(map[string]config.Check, len(effectiveChecks))
	for _, c := range effectiveChecks {
		effectiveByID[c.ID] = c
	}

	// Base-branch policy floor in CI mode.
	if mode == "ci" && config.BoolVal(cfg.Policy.EnforceBaseFloorInCI, true) && snap != nil && snap.IsGitRepo && snap.BaseSHA != "" {
		baseRaw, exists, err := gitdiff.ReadFileAtRef(repoDir, snap.BaseSHA, config.ConfigFileName)
		if err != nil {
			res.FullRepoEscalated = true
			res.EscalationReasons = append(res.EscalationReasons, fmt.Sprintf("unable to read base policy floor: %v", err))
		} else if exists {
			baseRes, loadErr := config.Load(repoDir, config.LoadOptions{
				Mode:            "ci",
				OverrideRootRaw: baseRaw,
				OverrideLabel:   snap.BaseSHA + ":" + config.ConfigFileName,
			})
			if loadErr != nil {
				res.FullRepoEscalated = true
				res.EscalationReasons = append(res.EscalationReasons, fmt.Sprintf("base policy floor failed to parse: %v", loadErr))
			} else {
				res.PolicyFloorEnforced = true
				// Union base trust paths so a PR cannot remove itself from trust_paths.
				trustPaths = append(trustPaths, baseRes.Effective.Policy.TrustPaths...)

				// Detect weakening or removal of required base checks.
				for _, baseChk := range baseRes.Effective.Checks {
					if !baseChk.IsRequired() {
						continue
					}
					headChk, ok := effectiveByID[baseChk.ID]
					if !ok {
						res.TamperingFindings = append(res.TamperingFindings,
							fmt.Sprintf("required base check %q was removed or disabled in PR; enforced from base policy floor", baseChk.ID))
						effectiveChecks = append(effectiveChecks, baseChk)
						effectiveByID[baseChk.ID] = baseChk
						continue
					}
					if !headChk.IsRequired() {
						res.TamperingFindings = append(res.TamperingFindings,
							fmt.Sprintf("required base check %q was downgraded to optional in PR; enforced as required", baseChk.ID))
						headChk.Required = config.BoolPtr(true)
						replaceCheck(effectiveChecks, headChk)
						effectiveByID[headChk.ID] = headChk
					}
					if headChk.Command != baseChk.Command {
						res.TamperingFindings = append(res.TamperingFindings,
							fmt.Sprintf("required base check %q command changed in PR (%q -> %q); trust-boundary review required",
								baseChk.ID, baseChk.Command, headChk.Command))
					}
				}
				if len(res.TamperingFindings) > 0 {
					res.TrustBoundaryTriggered = true
					res.FullRepoEscalated = true
					res.EscalationReasons = append(res.EscalationReasons, "base-branch policy floor detected check tampering or modification")
				}
			}
		}
	}

	// Merge-base failure in CI or explicit base: fail closed to full gate.
	if snap != nil && snap.MergeBaseError != "" {
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons, "merge-base unavailable: "+snap.MergeBaseError)
	}

	var changed []string
	if snap != nil {
		changed = snap.AffectedPaths
	}
	res.Impact = cm.ImpactedByPaths(changed)

	// Check trust-boundary paths against ALL affected paths (both sides of renames + deletions).
	var trustHits []string
	for _, p := range changed {
		if compmap.MatchAnyGlob(trustPaths, p) {
			trustHits = append(trustHits, p)
		}
	}
	if len(trustHits) > 0 {
		res.TrustBoundaryTriggered = true
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons, fmt.Sprintf("trust-boundary paths modified: %v", trustHits))
	}

	// Fail closed on unmapped changed paths.
	if len(res.Impact.UnmappedPaths) > 0 && config.BoolVal(cfg.Policy.FailClosedOnUnmapped, true) {
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons,
			fmt.Sprintf("unmapped changed paths escalated to full repo gate: %v", res.Impact.UnmappedPaths))
	}

	if runAll {
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons, "--all flag requested full repository verification")
	}

	// Build impacted component set (direct + transitive reverse dependents) and pin checks.
	impactedComps := make(map[string]bool)
	for _, id := range res.Impact.DirectComponents {
		impactedComps[id] = true
	}
	for _, id := range res.Impact.TransitiveDependents {
		impactedComps[id] = true
	}

	compBoundChecks := make(map[string]bool)
	for _, c := range cm.Components {
		if impactedComps[c.ID] {
			for _, cid := range c.Checks {
				compBoundChecks[cid] = true
			}
		}
	}

	pinChecks := make(map[string]bool)
	triggeredPinSet := make(map[string]bool, len(res.Impact.TriggeredPins))
	for _, id := range res.Impact.TriggeredPins {
		triggeredPinSet[id] = true
	}
	for _, pin := range cm.Pins {
		if triggeredPinSet[pin.ID] && pin.CompatibilityCheck != "" {
			pinChecks[pin.CompatibilityCheck] = true
		}
	}

	// Determine check selection.
	baseAdded := make(map[string]bool)
	origSet := make(map[string]bool, len(cfg.Checks))
	for _, c := range cfg.Checks {
		origSet[c.ID] = true
	}
	for _, c := range effectiveChecks {
		if !origSet[c.ID] {
			baseAdded[c.ID] = true
		}
	}

	for _, chk := range effectiveChecks {
		sc := SelectedCheck{
			Check:    chk,
			FromBase: baseAdded[chk.ID],
		}
		switch {
		case res.FullRepoEscalated:
			sc.Selected = true
			sc.Reason = "full repo verification escalated"
		case len(changed) == 0 && (snap == nil || !snap.IsGitRepo || snap.BaseSHA == ""):
			// No git base to scope against: fail closed by running all checks.
			sc.Selected = true
			sc.Reason = "no git diff base available; running full check set"
		case pinChecks[chk.ID]:
			sc.Selected = true
			sc.Reason = "triggered by cross-repo pin compatibility requirement"
		case compBoundChecks[chk.ID]:
			sc.Selected = true
			sc.Reason = "bound to directly or transitively impacted component"
		case checkMatchesComponents(chk, impactedComps):
			sc.Selected = true
			sc.Reason = "check targets impacted component"
		case len(chk.Paths) == 0:
			// Unscoped global check runs whenever anything changed.
			if len(changed) > 0 {
				sc.Selected = true
				sc.Reason = "global repository check"
			} else {
				sc.Selected = false
				sc.Reason = "no changed paths"
			}
		case anyPathMatches(chk.Paths, changed):
			sc.Selected = true
			sc.Reason = "changed path matched check glob"
		default:
			sc.Selected = false
			sc.Reason = "no changed paths or impacted components matched"
		}
		res.Checks = append(res.Checks, sc)
	}

	sort.Strings(res.EscalationReasons)
	sort.Strings(res.TamperingFindings)
	return res, nil
}

func checkMatchesComponents(chk config.Check, impacted map[string]bool) bool {
	for _, cid := range chk.Components {
		if impacted[cid] {
			return true
		}
	}
	return false
}

func anyPathMatches(globs, paths []string) bool {
	for _, p := range paths {
		if compmap.MatchAnyGlob(globs, p) {
			return true
		}
	}
	return false
}

func replaceCheck(checks []config.Check, updated config.Check) {
	for i := range checks {
		if checks[i].ID == updated.ID {
			checks[i] = updated
			return
		}
	}
}
