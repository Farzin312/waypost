package policy

import (
	"fmt"
	"reflect"
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

// BaseFloor holds the trusted base-branch policy resolved strictly from git.
type BaseFloor struct {
	Enforced                 bool
	Loaded                   bool
	BaseConfig               *config.ResolvedConfig
	RequireFrozenLockInCI    bool
	FailClosedOnUnmapped     bool
	AllowedProviderCommands  map[string]string
	LoadError                string
}

// LoadBaseFloor resolves the trusted target base branch's .waypost.yaml and all of
// its file-based `extends` ancestors strictly from `git show <TargetSHA>:<path>`
// (never touching the PR worktree). In CI mode, this runs BEFORE planning, provider
// execution, or check execution so a PR cannot disable its own CI policy floor.
func LoadBaseFloor(repoDir, mode string, headRes *config.ResolvedConfig, snap *gitdiff.Snapshot) BaseFloor {
	bf := BaseFloor{
		RequireFrozenLockInCI: config.BoolVal(headRes.Effective.Policy.RequireFrozenLockInCI, true),
		FailClosedOnUnmapped:  config.BoolVal(headRes.Effective.Policy.FailClosedOnUnmapped, true),
	}
	if mode != "ci" || snap == nil || !snap.IsGitRepo {
		return bf
	}
	ref := snap.TargetSHA
	if ref == "" {
		ref = snap.BaseSHA
	}
	if ref == "" {
		return bf
	}

	reader := func(relPath string) ([]byte, bool, error) {
		return gitdiff.ReadFileAtRef(repoDir, ref, relPath)
	}
	baseRaw, exists, err := reader(config.ConfigFileName)
	if err != nil {
		bf.LoadError = fmt.Sprintf("unable to read base policy floor at %s: %v", ref, err)
		return bf
	}
	if !exists {
		return bf
	}

	baseRes, loadErr := config.Load(repoDir, config.LoadOptions{
		Mode:            "ci",
		OverrideRootRaw: baseRaw,
		OverrideLabel:   ref + ":" + config.ConfigFileName,
		RepoFileReader:  reader,
	})
	if loadErr != nil {
		bf.LoadError = fmt.Sprintf("base policy floor at %s failed to resolve: %v", ref, loadErr)
		return bf
	}

	bf.Loaded = true
	bf.BaseConfig = baseRes
	bf.Enforced = config.BoolVal(baseRes.Effective.Policy.EnforceBaseFloorInCI, true)
	if bf.Enforced {
		// Base policy controls take precedence over PR attempts to weaken CI enforcement.
		if config.BoolVal(baseRes.Effective.Policy.RequireFrozenLockInCI, true) {
			bf.RequireFrozenLockInCI = true
		}
		if config.BoolVal(baseRes.Effective.Policy.FailClosedOnUnmapped, true) {
			bf.FailClosedOnUnmapped = true
		}
		bf.AllowedProviderCommands = make(map[string]string)
		for _, p := range baseRes.Effective.Providers {
			if p.Authorized {
				bf.AllowedProviderCommands[p.ID] = p.Command
			}
		}
	}
	return bf
}

// PlanResult captures policy authority decisions, trust-boundary escalations,
// base-branch policy floor enforcement, and the final check execution plan.
type PlanResult struct {
	TrustBoundaryTriggered bool            `json:"trust_boundary_triggered"`
	PolicyFloorEnforced    bool            `json:"policy_floor_enforced"`
	FullRepoEscalated      bool            `json:"full_repo_escalated"`
	EscalationReasons      []string        `json:"escalation_reasons,omitempty"`
	TamperingFindings      []string        `json:"tampering_findings,omitempty"`
	Impact                 compmap.Impact  `json:"impact"`
	Checks                 []SelectedCheck `json:"checks"`
	EffectivePolicyDigest  string          `json:"effective_policy_digest"`
}

// Plan determines which checks must run under the active policy, trusted BaseFloor, and mode.
func Plan(repoDir, mode string, resolved *config.ResolvedConfig, bf BaseFloor, cm *compmap.Map, snap *gitdiff.Snapshot, runAll bool) (*PlanResult, error) {
	cfg := resolved.Effective
	res := &PlanResult{
		EffectivePolicyDigest: resolved.PolicyDigest,
	}

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

	baseEnforcedIDs := make(map[string]bool)

	if bf.LoadError != "" {
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons, bf.LoadError)
	}

	// Enforce trusted base-branch policy floor in CI mode.
	if mode == "ci" && bf.Loaded && bf.Enforced && bf.BaseConfig != nil {
		res.PolicyFloorEnforced = true
		baseEff := bf.BaseConfig.Effective

		// Retain both global AND component trust paths from the trusted base policy.
		trustPaths = append(trustPaths, baseEff.Policy.TrustPaths...)
		for _, bc := range baseEff.Components {
			trustPaths = append(trustPaths, bc.TrustPaths...)
		}

		// Detect PR weakening of CI policy flags.
		if !config.BoolVal(cfg.Policy.EnforceBaseFloorInCI, true) {
			res.TamperingFindings = append(res.TamperingFindings,
				"PR attempted to set enforce_base_floor_in_ci=false; base policy floor remains enforced")
		}
		if config.BoolVal(baseEff.Policy.RequireFrozenLockInCI, true) && !config.BoolVal(cfg.Policy.RequireFrozenLockInCI, true) {
			res.TamperingFindings = append(res.TamperingFindings,
				"PR attempted to set require_frozen_lock_in_ci=false; base policy floor requires frozen lock")
		}
		if config.BoolVal(baseEff.Policy.FailClosedOnUnmapped, true) && !config.BoolVal(cfg.Policy.FailClosedOnUnmapped, true) {
			res.TamperingFindings = append(res.TamperingFindings,
				"PR attempted to set fail_closed_on_unmapped=false; base policy floor enforces fail-closed unmapped escalation")
		}

		// Compare complete check definitions for every required base check.
		// If removed, downgraded, or altered in command/workdir/requires_bin/timeout/scope,
		// restore the trusted base check definition so the PR cannot substitute or weaken it.
		for _, baseChk := range baseEff.Checks {
			if !baseChk.IsRequired() {
				continue
			}
			headChk, ok := effectiveByID[baseChk.ID]
			if !ok {
				res.TamperingFindings = append(res.TamperingFindings,
					fmt.Sprintf("required base check %q was removed or disabled in PR; enforced from base policy floor", baseChk.ID))
				effectiveChecks = append(effectiveChecks, baseChk)
				effectiveByID[baseChk.ID] = baseChk
				baseEnforcedIDs[baseChk.ID] = true
				continue
			}
			if !checksEquivalent(baseChk, headChk) {
				res.TamperingFindings = append(res.TamperingFindings,
					fmt.Sprintf("required base check %q was modified or weakened in PR; trusted base definition enforced", baseChk.ID))
				replaceCheck(effectiveChecks, baseChk)
				effectiveByID[baseChk.ID] = baseChk
				baseEnforcedIDs[baseChk.ID] = true
			}
		}

		if len(res.TamperingFindings) > 0 {
			res.TrustBoundaryTriggered = true
			res.FullRepoEscalated = true
			res.EscalationReasons = append(res.EscalationReasons, "base-branch policy floor detected policy or check tampering")
		}
	}

	// Recompute effective policy digest over the actually enforced check set.
	enforcedCfg := cfg
	enforcedCfg.Checks = effectiveChecks
	enforcedCfg.Policy.TrustPaths = trustPaths
	if d, err := config.ComputeDigest(enforcedCfg); err == nil {
		res.EffectivePolicyDigest = d
	}

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

	// Fail closed on unmapped changed paths using trusted policy flag.
	if len(res.Impact.UnmappedPaths) > 0 && bf.FailClosedOnUnmapped {
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons,
			fmt.Sprintf("unmapped changed paths escalated to full repo gate: %v", res.Impact.UnmappedPaths))
	}

	if runAll {
		res.FullRepoEscalated = true
		res.EscalationReasons = append(res.EscalationReasons, "--all flag requested full repository verification")
	}

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

	for _, chk := range effectiveChecks {
		sc := SelectedCheck{
			Check:    chk,
			FromBase: baseEnforcedIDs[chk.ID],
		}
		switch {
		case res.FullRepoEscalated:
			sc.Selected = true
			sc.Reason = "full repo verification escalated"
		case len(changed) == 0 && (snap == nil || !snap.IsGitRepo || snap.BaseSHA == ""):
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

func checksEquivalent(a, b config.Check) bool {
	return a.Command == b.Command &&
		a.Workdir == b.Workdir &&
		a.IsRequired() == b.IsRequired() &&
		a.TimeoutSeconds == b.TimeoutSeconds &&
		a.RequiresBin == b.RequiresBin &&
		reflect.DeepEqual(a.Paths, b.Paths) &&
		reflect.DeepEqual(a.Components, b.Components)
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
