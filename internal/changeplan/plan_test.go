package changeplan

import (
	"slices"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
)

func TestPlanSeparatesAttributionFromBothPoliciesObligations(t *testing.T) {
	baseCheck := config.Check{ID: "retained", Command: "true", Paths: []string{"base-only/**"}}
	headCheck := config.Check{ID: "candidate", Command: "true", Paths: []string{"head-only/**"}}
	pin := config.CrossRepoPin{ID: "contract", Paths: []string{"app/added.ts"}, CompatibilityCheck: "compat"}
	compat := config.Check{ID: "compat", Command: "true", Paths: []string{"pin-only/**"}}
	old := Side{
		Config: &config.Config{Checks: []config.Check{baseCheck, compat}, Pins: []config.CrossRepoPin{pin}},
		Map: &compmap.Map{
			Components: []compmap.Component{{ID: "base", Paths: []string{"app/**"}, Checks: []string{baseCheck.ID}}},
			Pins:       []config.CrossRepoPin{pin},
		},
	}
	head := Side{
		Config: &config.Config{Checks: []config.Check{headCheck}},
		Map:    &compmap.Map{Components: []compmap.Component{{ID: "head", Paths: []string{"legacy/**", "app/**"}, Checks: []string{headCheck.ID}}}},
	}
	changes := []gitdiff.Change{{Path: "app/added.ts", Status: "A"}, {OldPath: "legacy/old.ts", Path: "app/new.ts", Status: "R"}}
	plan := Create(old, head, changes, false, true, true)
	if len(plan.Changes[0].OldOwners) != 0 || !slices.Equal(plan.Changes[0].NewOwners, []string{"head"}) {
		t.Fatalf("addition attribution: %+v", plan.Changes[0])
	}
	for _, id := range []string{"retained", "compat", "candidate"} {
		if !slices.ContainsFunc(plan.Checks, func(c Check) bool { return c.Selected && c.Check.ID == id }) {
			t.Fatalf("missing obligation %q: %+v", id, plan.Checks)
		}
	}
	if !slices.Equal(plan.Impact.TriggeredPins, []string{"contract"}) {
		t.Fatalf("pin scope: %+v", plan.Impact)
	}
	old.Config.Policy.TrustPaths = []string{"app/added.ts"}
	plan = Create(old, head, changes, false, true, true)
	if !plan.Full || !slices.Contains(plan.TrustHits, "app/added.ts") {
		t.Fatalf("target trust path did not escalate: %+v", plan)
	}
}
