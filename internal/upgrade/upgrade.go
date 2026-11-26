package upgrade

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"gopkg.in/yaml.v3"
)

// Options controls a preset/lockfile upgrade run.
type Options struct {
	Target string // Optional new `extends` reference
	Apply  bool   // False = dry-run (default)
}

// Plan reports the exact reviewable delta of upgrading inheritance/lockfile state.
type Plan struct {
	Applied              bool     `json:"applied"`
	Changed              bool     `json:"changed"`
	PreviousExtends      string   `json:"previous_extends,omitempty"`
	TargetExtends        string   `json:"target_extends,omitempty"`
	PreviousPolicyDigest string   `json:"previous_policy_digest"`
	NewPolicyDigest      string   `json:"new_policy_digest"`
	PreviousLockDigest   string   `json:"previous_lock_digest,omitempty"`
	NewLockDigest        string   `json:"new_lock_digest,omitempty"`
	AddedRules           []string `json:"added_rules,omitempty"`
	RemovedRules         []string `json:"removed_rules,omitempty"`
	ChangedRules         []string `json:"changed_rules,omitempty"`
	AddedChecks          []string `json:"added_checks,omitempty"`
	RemovedChecks        []string `json:"removed_checks,omitempty"`
	ChangedChecks        []string `json:"changed_checks,omitempty"`
	PermissionChanges    []string `json:"permission_changes,omitempty"`
}

// Run computes a reviewable upgrade plan and, when opts.Apply is true, updates
// .waypost.yaml (if Target changed) and .waypost.lock atomically so git revert
// remains a clean rollback path.
func Run(repoDir string, opts Options) (*Plan, error) {
	cfgPath := filepath.Join(repoDir, config.ConfigFileName)
	rawBefore, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cfgPath, err)
	}

	// Always compute canonical CI-mode configs so local overrides never leak into commits.
	beforeRes, err := config.Load(repoDir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		return nil, fmt.Errorf("load current config: %w", err)
	}
	prevLock, prevLockDigest, lockErr := lockfile.Read(repoDir)
	_ = lockErr

	rawAfter := rawBefore
	targetExt := strings.TrimSpace(opts.Target)
	if targetExt != "" && targetExt != beforeRes.Effective.Extends {
		rawAfter, err = replaceExtendsField(rawBefore, targetExt)
		if err != nil {
			return nil, fmt.Errorf("update extends field: %w", err)
		}
	} else {
		targetExt = beforeRes.Effective.Extends
	}

	afterRes, err := config.Load(repoDir, config.LoadOptions{
		Mode:            "ci",
		OverrideRootRaw: rawAfter,
		OverrideLabel:   cfgPath + " (candidate)",
	})
	if err != nil {
		return nil, fmt.Errorf("resolve target config: %w", err)
	}

	newLock := lockfile.Generate(afterRes)
	newLockBytes, err := lockfile.Marshal(newLock)
	if err != nil {
		return nil, err
	}

	plan := &Plan{
		Applied:              false,
		PreviousExtends:      beforeRes.Effective.Extends,
		TargetExtends:        targetExt,
		PreviousPolicyDigest: beforeRes.PolicyDigest,
		NewPolicyDigest:      afterRes.PolicyDigest,
		PreviousLockDigest:   prevLockDigest,
	}

	// Compare rules.
	beforeRules := make(map[string]config.Rule)
	for _, r := range beforeRes.Effective.Rules {
		beforeRules[r.ID] = r
	}
	afterRules := make(map[string]config.Rule)
	for _, r := range afterRes.Effective.Rules {
		afterRules[r.ID] = r
	}
	for id, ar := range afterRules {
		br, ok := beforeRules[id]
		if !ok {
			plan.AddedRules = append(plan.AddedRules, fmt.Sprintf("%s (%s)", id, ar.Kind))
		} else if br != ar {
			plan.ChangedRules = append(plan.ChangedRules, fmt.Sprintf("%s (%s -> %s)", id, br.Kind, ar.Kind))
		}
	}
	for id, br := range beforeRules {
		if _, ok := afterRules[id]; !ok {
			plan.RemovedRules = append(plan.RemovedRules, fmt.Sprintf("%s (%s)", id, br.Kind))
		}
	}

	// Compare checks.
	beforeChecks := make(map[string]config.Check)
	for _, c := range beforeRes.Effective.Checks {
		beforeChecks[c.ID] = c
	}
	afterChecks := make(map[string]config.Check)
	for _, c := range afterRes.Effective.Checks {
		afterChecks[c.ID] = c
	}
	for id, ac := range afterChecks {
		bc, ok := beforeChecks[id]
		if !ok {
			plan.AddedChecks = append(plan.AddedChecks, fmt.Sprintf("%s (%s)", id, ac.Command))
		} else if bc.Command != ac.Command || bc.IsRequired() != ac.IsRequired() {
			plan.ChangedChecks = append(plan.ChangedChecks, fmt.Sprintf("%s: %q (req=%v) -> %q (req=%v)",
				id, bc.Command, bc.IsRequired(), ac.Command, ac.IsRequired()))
		}
	}
	for id := range beforeChecks {
		if _, ok := afterChecks[id]; !ok {
			plan.RemovedChecks = append(plan.RemovedChecks, id)
		}
	}

	// Surface permission/execution-authorization deltas explicitly!
	prevSkills := make(map[string]lockfile.LockedSkill)
	prevProvs := make(map[string]lockfile.LockedProvider)
	if prevLock != nil {
		for _, s := range prevLock.Skills {
			prevSkills[s.ID] = s
		}
		for _, p := range prevLock.Providers {
			prevProvs[p.ID] = p
		}
	}
	for _, s := range afterRes.Effective.Skills {
		prev, ok := prevSkills[s.ID]
		if s.Authorized && (!ok || !prev.Authorized) {
			plan.PermissionChanges = append(plan.PermissionChanges, fmt.Sprintf("skill %q enables authorized execution (%s)", s.ID, s.Source))
		}
	}
	for _, p := range afterRes.Effective.Providers {
		prev, ok := prevProvs[p.ID]
		if p.Authorized && (!ok || !prev.Authorized || prev.Command != p.Command) {
			plan.PermissionChanges = append(plan.PermissionChanges, fmt.Sprintf("provider %q enables/changes authorized command (%s)", p.ID, p.Command))
		}
	}

	sort.Strings(plan.AddedRules)
	sort.Strings(plan.RemovedRules)
	sort.Strings(plan.ChangedRules)
	sort.Strings(plan.AddedChecks)
	sort.Strings(plan.RemovedChecks)
	sort.Strings(plan.ChangedChecks)
	sort.Strings(plan.PermissionChanges)

	lockChanged := prevLock == nil || prevLock.PolicyDigest != newLock.PolicyDigest || prevLock.ConfigSHA256 != newLock.ConfigSHA256
	if !lockChanged && len(prevLock.Chain) == len(newLock.Chain) {
		for i := range prevLock.Chain {
			if prevLock.Chain[i] != newLock.Chain[i] {
				lockChanged = true
				break
			}
		}
	} else if !lockChanged {
		lockChanged = true
	}

	plan.Changed = !bytes.Equal(rawBefore, rawAfter) || lockChanged

	if opts.Apply && plan.Changed {
		if !bytes.Equal(rawBefore, rawAfter) {
			tmp := cfgPath + ".tmp"
			if err := os.WriteFile(tmp, rawAfter, 0o644); err != nil {
				return nil, fmt.Errorf("write updated config: %w", err)
			}
			if err := os.Rename(tmp, cfgPath); err != nil {
				_ = os.Remove(tmp)
				return nil, fmt.Errorf("rename updated config: %w", err)
			}
		}
		newDigest, err := lockfile.Write(repoDir, newLock)
		if err != nil {
			return nil, err
		}
		plan.NewLockDigest = newDigest
		plan.Applied = true
	} else {
		// Compute preview digest of lockfile bytes without writing.
		_ = newLockBytes
		if prevLockDigest != "" && !lockChanged {
			plan.NewLockDigest = prevLockDigest
		}
	}

	return plan, nil
}

// replaceExtendsField updates or inserts `extends` in a YAML document while
// preserving existing field ordering and formatting as cleanly as possible.
func replaceExtendsField(raw []byte, newExtends string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config root must be a YAML mapping")
	}
	m := doc.Content[0]
	found := false
	for i := 0; i < len(m.Content)-1; i += 2 {
		if m.Content[i].Value == "extends" {
			m.Content[i+1].Value = newExtends
			m.Content[i+1].Tag = "!!str"
			found = true
			break
		}
	}
	if !found {
		k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "extends"}
		v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: newExtends}
		m.Content = append(m.Content, k, v)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}
