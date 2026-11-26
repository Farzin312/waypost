// Package changeplan attributes changes and selects checks without I/O.
package changeplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
)

type Side struct {
	Config *config.Config
	Map    *compmap.Map
}

type Ownership struct {
	gitdiff.Change
	OldOwners []string `json:"old_owners,omitempty"`
	NewOwners []string `json:"new_owners,omitempty"`
}

type ReviewReason struct {
	Code    string   `json:"code"`
	Items   []string `json:"items"`
	Omitted int      `json:"omitted,omitempty"`
}

type Check struct {
	Check        config.Check `json:"check"`
	Selected     bool         `json:"selected"`
	Reason       string       `json:"reason"`
	Source       string       `json:"definition_source"`
	BaseRequired bool         `json:"base_required,omitempty"`
}

type Plan struct {
	Changes    []Ownership
	Impact     compmap.Impact
	Checks     []Check
	Invariants []config.Rule
	TrustHits  []string
	Review     []ReviewReason
	Full       bool
}

func Create(old, next Side, changes []gitdiff.Change, all, complete, obligations bool) Plan {
	var plan Plan
	var before, after []string
	trust, pins := make([]string, 0), make([]string, 0)
	oldTrust, newTrust := trustGlobs(old), trustGlobs(next)
	for _, change := range changes {
		item := Ownership{Change: change}
		prior, current := change.Path, change.Path
		switch change.Status {
		case "A":
			prior = ""
		case "D":
			current = ""
		case "R", "C":
			prior = change.OldPath
		}
		if prior != "" {
			before = append(before, prior)
			if old.Map != nil {
				item.OldOwners = old.Map.OwnersOf(prior)
			}
		}
		if current != "" {
			after = append(after, current)
			if next.Map != nil {
				item.NewOwners = next.Map.OwnersOf(current)
			}
		}
		plan.Changes = append(plan.Changes, item)
		if prior != "" && old.Map != nil && len(item.OldOwners) == 0 {
			plan.Impact.UnmappedPaths = append(plan.Impact.UnmappedPaths, prior)
		}
		if current != "" && next.Map != nil && len(item.NewOwners) == 0 {
			plan.Impact.UnmappedPaths = append(plan.Impact.UnmappedPaths, current)
		}
	}
	paths := unique(before, after)
	for _, name := range paths {
		mark(old, oldTrust, name, &trust, &pins)
		mark(next, newTrust, name, &trust, &pins)
	}
	oldImpact, newImpact := impact(old, before), impact(next, after)
	oldObligations, newObligations := impact(old, paths), impact(next, paths)
	plan.Impact.DirectComponents = unique(oldImpact.DirectComponents, newImpact.DirectComponents)
	plan.Impact.TransitiveDependents = slices.DeleteFunc(unique(oldImpact.TransitiveDependents, newImpact.TransitiveDependents), func(id string) bool { return slices.Contains(plan.Impact.DirectComponents, id) })
	plan.Impact.TriggeredPins = unique(oldObligations.TriggeredPins, newObligations.TriggeredPins)
	plan.Impact.UnmappedPaths = unique(plan.Impact.UnmappedPaths)
	plan.TrustHits = unique(trust)
	plan.Full = all || !complete || len(trust) > 0 || (len(plan.Impact.UnmappedPaths) > 0 && (failClosed(old) || failClosed(next)))
	plan.Review = appendReason(plan.Review, "trust_path", trust)
	plan.Review = appendReason(plan.Review, "policy_floor", SemanticChanges(old.Config, next.Config))
	plan.Review = appendReason(plan.Review, "contract_pin", unique(pins, PinChanges(old.Config, next.Config)))
	if next.Config != nil {
		for _, r := range next.Config.Rules {
			if r.Kind == "invariant" {
				plan.Invariants = append(plan.Invariants, r)
			}
		}
	}
	plan.Checks = selectChecks(next, newObligations, paths, plan.Full, "head")
	if obligations {
		baseChecks := selectChecks(old, oldObligations, paths, plan.Full, "base")
		plan.Checks = unionChecks(plan.Checks, baseChecks, paths)
	}
	return plan
}

func impact(side Side, paths []string) compmap.Impact {
	if side.Map == nil {
		return compmap.Impact{}
	}
	return side.Map.ImpactedByPaths(paths)
}

func mark(side Side, globs []compmap.Glob, path string, trust, pins *[]string) {
	if (side.Config != nil && side.Config.Boundaries.EffectiveMode() == "ratchet" && side.Config.Boundaries.BaselinePath() == path) || compmap.MatchCompiled(globs, path) {
		*trust = append(*trust, path)
	}
	if side.Config == nil {
		return
	}

	for _, check := range side.Config.Checks {
		if check.IsRequired() && wrapperInput(check, path) {
			*trust = append(*trust, path)
			break
		}
	}
	for _, pin := range side.Config.Pins {
		if (side.Map != nil && side.Map.PinTouched(pin, path)) || compmap.PinTouches(pin, path) {
			*pins = append(*pins, pin.ID, path)
		}
	}
}

func trustGlobs(side Side) []compmap.Glob {
	paths := []string{config.ConfigFileName, ".waypost.lock", ".github/workflows/**", ".bounds/**"}
	if side.Config != nil {
		paths = append(paths, side.Config.Policy.TrustPaths...)

	}
	if side.Map != nil {
		for _, component := range side.Map.Components {
			paths = append(paths, component.TrustPaths...)
		}
	}
	return compmap.CompileGlobs(paths)
}

func failClosed(side Side) bool {
	return side.Config != nil && config.BoolVal(side.Config.Policy.FailClosedOnUnmapped, true)
}

func selectChecks(side Side, impact compmap.Impact, paths []string, full bool, source string) []Check {
	if side.Config == nil {
		return nil
	}
	impacted := unique(impact.DirectComponents, impact.TransitiveDependents)
	componentChecks := make(map[string]bool)
	if side.Map != nil {
		for _, c := range side.Map.Components {
			if slices.Contains(impacted, c.ID) {
				for _, id := range c.Checks {
					componentChecks[id] = true
				}
			}
		}
	}
	pinChecks := make(map[string]bool)
	for _, p := range side.Config.Pins {
		if slices.Contains(impact.TriggeredPins, p.ID) {
			pinChecks[p.CompatibilityCheck] = true
		}
	}
	var out []Check
	for _, c := range side.Config.Checks {
		item := Check{Check: c, Source: source, Selected: true}
		switch {
		case full:
			item.Reason = "full repository verification"
		case pinChecks[c.ID]:
			item.Reason = "cross-repository compatibility"
		case componentChecks[c.ID] || slices.ContainsFunc(c.Components, func(id string) bool { return slices.Contains(impacted, id) }):
			item.Reason = "impacted component"
		case len(c.Paths) == 0 && len(paths) > 0:
			item.Reason = "global repository check"
		default:
			globs := compmap.CompileGlobs(c.Paths)
			item.Selected = slices.ContainsFunc(paths, func(path string) bool { return compmap.MatchCompiled(globs, path) })
			item.Reason = "changed path matched check scope"
			if !item.Selected {
				item.Reason = "no changed paths or impacted components matched"
			}
		}
		out = append(out, item)
	}
	return out
}

// wrapperInput recognizes package-runner definitions and in-repo executable paths.
func wrapperInput(check config.Check, changed string) bool {
	command := check.Command + " " + check.LocalCommand
	tokens := strings.FieldsFunc(command, func(r rune) bool {
		return strings.ContainsRune(" \n\t\r'\";|&()=<>", r)
	})
	npmLike := slices.ContainsFunc(tokens, func(token string) bool {
		switch path.Base(token) {
		case "npm", "npx", "yarn", "pnpm", "bun":
			return true
		}
		return false
	})
	if npmLike && (path.Base(changed) == "package.json" || strings.HasPrefix(changed, "scripts/") || strings.Contains(changed, "/scripts/")) {
		return true
	}
	for _, token := range tokens {
		if token == changed || path.Join(check.Workdir, token) == changed {
			return true
		}
	}
	return false
}

func unionChecks(head, base []Check, paths []string) []Check {
	var result []Check
	handled := make(map[string]bool)
	byID := make(map[string]Check)
	for _, c := range base {
		byID[c.Check.ID] = c
	}
	for _, h := range head {
		b, ok := byID[h.Check.ID]
		if ok {
			handled[h.Check.ID] = true
			if sameExecution(b.Check, h.Check) {
				h.Source = "both"
				if h.Check.IsRequired() && slices.ContainsFunc(paths, func(rel string) bool { return wrapperInput(h.Check, rel) }) {
					h.Source = "head"
					h.BaseRequired = b.Selected && b.Check.IsRequired()
					h.Reason += " (executable inputs changed in candidate)"
				}
				if b.Selected && !h.Selected {
					h.Selected, h.Reason = true, b.Reason
				}
				if b.Check.IsRequired() {
					h.Check.Required = config.BoolPtr(true)
				}
				if config.BoolVal(b.Check.Serial, true) {
					h.Check.Serial = config.BoolPtr(true)
				}
			} else if b.Selected {
				result = append(result, b)
			}
		}
		result = append(result, h)
	}
	for _, b := range base {
		if !handled[b.Check.ID] {
			result = append(result, b)
		}
	}
	return result
}

func sameExecution(a, b config.Check) bool {
	return a.Command == b.Command && a.Workdir == b.Workdir && a.RequiresBin == b.RequiresBin &&
		a.TimeoutSeconds == b.TimeoutSeconds
}

func appendReason(out []ReviewReason, code string, items []string) []ReviewReason {
	items = unique(items)
	if len(items) == 0 {
		return out
	}
	n := min(12, len(items))
	return append(out, ReviewReason{Code: code, Items: items[:n], Omitted: len(items) - n})
}

func unique(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func PinChanges(a, b *config.Config) []string {
	if a == nil || b == nil {
		return nil
	}
	return ChangedIDs(a.Pins, b.Pins, func(p config.CrossRepoPin) string { return p.ID })
}

func SemanticChanges(a, b *config.Config) []string {
	if a == nil || b == nil {
		return nil
	}
	out := ChangedIDs(a.Checks, b.Checks, func(c config.Check) string { return c.ID })
	if !reflect.DeepEqual(a.Policy.TrustPaths, b.Policy.TrustPaths) ||
		!reflect.DeepEqual(a.Policy.FailClosedOnUnmapped, b.Policy.FailClosedOnUnmapped) ||
		!reflect.DeepEqual(a.Policy.RequireFrozenLockInCI, b.Policy.RequireFrozenLockInCI) ||
		!reflect.DeepEqual(a.Policy.EnforceBaseFloorInCI, b.Policy.EnforceBaseFloorInCI) {
		out = append(out, "policy")
	}
	if !reflect.DeepEqual(a.Boundaries, b.Boundaries) {
		out = append(out, "boundaries")
	}
	out = append(out, ChangedIDs(a.Components, b.Components, func(c config.ComponentConfig) string { return c.ID })...)
	out = append(out, ChangedIDs(a.Rules, b.Rules, func(r config.Rule) string { return r.ID })...)
	out = append(out, ChangedIDs(a.Providers, b.Providers, func(p config.ProviderConfig) string { return p.ID })...)
	return unique(out)
}

func ChangedIDs[T any](a, b []T, id func(T) string) []string {
	m := make(map[string]T)
	for _, x := range a {
		m[id(x)] = x
	}
	var changes []string
	for _, x := range b {
		key := id(x)
		if previous, ok := m[key]; !ok || !reflect.DeepEqual(previous, x) {
			changes = append(changes, key)
		}
		delete(m, key)
	}
	for key := range m {
		changes = append(changes, key)
	}
	return unique(changes)
}

// Untested identifies affected production owners without a touched test.
func Untested(changes []Ownership, production, test func(string) bool) []string {
	prod, tests := make(map[string]bool), make(map[string]bool)
	mark := func(path string, owners []string) {
		if path == "" {
			return
		}
		var set map[string]bool
		switch {
		case test(path):
			set = tests
		case production(path):
			set = prod
		default:
			return
		}
		for _, owner := range owners {
			set[owner] = true
		}
	}
	for _, ch := range changes {
		old := ch.Path
		if ch.OldPath != "" {
			old = ch.OldPath
		}
		if !test(old) {
			mark(old, ch.OldOwners)
		}
		mark(ch.Path, ch.NewOwners)
	}
	var out []string
	for id := range prod {
		if !tests[id] && strings.TrimSpace(id) != "" {
			out = append(out, id)
		}
	}
	return unique(out)
}

// ComponentChecks projects check scope for inventory owned by one component.
func ComponentChecks(side Side, id string, changes []gitdiff.Change) []Check {
	paths := make([]string, 0, len(changes))
	for _, ch := range changes {
		paths = append(paths, ch.Path)
	}
	return selectChecks(side, compmap.Impact{DirectComponents: []string{id}}, paths, false, "head")
}

// Digest identifies the selected definitions and their planning lane.
func (p Plan) Digest() string {
	var selected []Check
	for _, check := range p.Checks {
		if check.Selected {
			selected = append(selected, check)
		}
	}
	raw, _ := json.Marshal(struct {
		Full   bool
		Checks []Check
	}{p.Full, selected})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
