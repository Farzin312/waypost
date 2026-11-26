package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/project"
)

// CompareFloor detects weakening against an independently resolved target snapshot.
func CompareFloor(target, head, lineage *project.Snapshot) (findings, blocking []string, baseline *archgraph.BaselineFile) {
	base, next := target.Config(), head.Config()
	fork := lineage.Config()
	if fork == nil {
		fork = base
	}
	forkChecks := make(map[string]config.Check)
	for _, check := range fork.Checks {
		forkChecks[check.ID] = check
	}
	block := func(message string) { findings = append(findings, message); blocking = append(blocking, message) }
	for _, flag := range []struct {
		name     string
		old, new *bool
	}{
		{"enforce_base_floor_in_ci", base.Policy.EnforceBaseFloorInCI, next.Policy.EnforceBaseFloorInCI},
		{"require_frozen_lock_in_ci", base.Policy.RequireFrozenLockInCI, next.Policy.RequireFrozenLockInCI},
		{"fail_closed_on_unmapped", base.Policy.FailClosedOnUnmapped, next.Policy.FailClosedOnUnmapped},
	} {
		if config.BoolVal(flag.old, true) && !config.BoolVal(flag.new, true) {
			block(fmt.Sprintf("PR attempted to set %s=false; trusted policy floor remains enforced", flag.name))
		}
	}
	headChecks := make(map[string]config.Check)
	for _, c := range next.Checks {
		headChecks[c.ID] = c
	}
	for _, c := range base.Checks {
		if !c.IsRequired() {
			continue
		}
		candidate, ok := headChecks[c.ID]
		prior, existed := forkChecks[c.ID]
		switch {
		case !ok && !existed:
			// The target introduced a check after the branches diverged.
			// There is no head removal, but the target command must still run.
		case ok && !candidate.IsRequired() && existed && !prior.IsRequired():
		case !ok:
			block(fmt.Sprintf("required base check %q was removed or disabled", c.ID))
		case !candidate.IsRequired():
			block(fmt.Sprintf("required base check %q was made optional", c.ID))
		case !reflect.DeepEqual(c, candidate):
			findings = append(findings, fmt.Sprintf("required base check %q was modified; both obligations retained", c.ID))
		}
	}
	old, new := base.Boundaries, next.Boundaries
	strict := map[string]int{"warn": 1, "ratchet": 2, "enforce": 3}
	if old.IsEnabled() {
		if !new.IsEnabled() {
			block("PR disabled built-in architecture boundaries")
		}
		if strict[old.EffectiveMode()] > strict[new.EffectiveMode()] {
			block(fmt.Sprintf("PR downgraded boundaries.mode from %s to %s", old.EffectiveMode(), new.EffectiveMode()))
		}
		if new != nil {
			for _, p := range new.IgnorePaths {
				if !slices.Contains(old.IgnorePaths, p) {
					findings = append(findings, fmt.Sprintf("PR added boundaries.ignore_paths exclusion %q; trusted exclusions remain enforced", p))
				}
			}
			if config.BoolVal(old.NoCycles, true) && !config.BoolVal(new.NoCycles, true) {
				block("PR disabled boundaries.no_cycles")
			}
			if config.BoolVal(old.EnforceDeclaredDeps, false) && !config.BoolVal(new.EnforceDeclaredDeps, false) {
				block("PR disabled boundaries.enforce_declared_deps")
			}
		}
		if old.EffectiveMode() == "ratchet" {
			var err error
			baseline, err = target.RecordedBaseline()
			if err != nil {
				block(fmt.Sprintf("trusted base boundary baseline: %v", err))
			}
			if baseline != nil {
				paths := []string{old.BaselinePath()}
				if new != nil && new.EffectiveMode() == "ratchet" && !slices.Contains(paths, new.BaselinePath()) {
					paths = append(paths, new.BaselinePath())
				}
				for _, p := range paths {
					current, err := head.Baseline(p)
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					if err != nil {
						block(fmt.Sprintf("PR boundary baseline %q is invalid: %v", p, err))
						continue
					}
					if n := archgraph.BaselineExpansion(baseline, current); n > 0 {
						block(fmt.Sprintf("PR expanded boundary baseline %q by %d violation occurrence(s)", p, n))
					}
				}
			}
		}
	}
	return findings, blocking, baseline
}
