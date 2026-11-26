package upgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"gopkg.in/yaml.v3"
)

// Options controls a preset/lockfile upgrade run.
type Options struct {
	Target  string // Optional new `extends` reference
	Apply   bool   // False = dry-run (default)
	Offline bool   // Restrict remote preset resolution to verified local cache
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
	Warnings             []string `json:"warnings,omitempty"`
}

// Run computes a reviewable upgrade plan and, when opts.Apply is true, updates
// .waypost.yaml (if Target changed) and .waypost.lock using exclusively created
// temporary files with rollback on error so git revert remains clean.
func Run(repoDir string, opts Options) (*Plan, error) {
	cfgPath := filepath.Join(repoDir, config.ConfigFileName)
	rawBefore, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cfgPath, err)
	}

	prevLock, prevLockDigest, _ := lockfile.Read(repoDir)
	prevLockRaw, _ := os.ReadFile(filepath.Join(repoDir, lockfile.LockFileName))
	pinnedPrev := lockfile.PinnedRemoteSHAs(prevLock)

	// Prefer loading the previously locked remote snapshot from local cache for accurate
	// before/after diffs; if the old remote blob is absent locally, warn clearly and preserve
	// the previous locked policy digest so remote mutations are never hidden.
	var beforeRes *config.ResolvedConfig
	var upgradeWarnings []string
	if len(pinnedPrev) > 0 {
		beforeRes, err = config.Load(repoDir, config.LoadOptions{
			Mode:                "ci",
			PinnedRemoteSHAs:    pinnedPrev,
			RequirePinnedRemote: true,
			Offline:             true,
		})
		if beforeRes == nil {
			upgradeWarnings = append(upgradeWarnings,
				"previous locked remote preset snapshot not found in local cache; rule/check delta against previous remote content may be incomplete (policy/lock digest delta reflects exact change)")
		}
	}
	if beforeRes == nil {
		beforeRes, err = config.Load(repoDir, config.LoadOptions{
			Mode:    "ci",
			Offline: opts.Offline,
		})
		if err != nil {
			return nil, fmt.Errorf("load current config: %w", err)
		}
	}

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

	afterLoadOpts := config.LoadOptions{
		Mode:            "ci",
		OverrideRootRaw: rawAfter,
		OverrideLabel:   cfgPath + " (candidate)",
		Offline:         opts.Offline,
	}
	if opts.Offline {
		afterLoadOpts.PinnedRemoteSHAs = pinnedPrev
		afterLoadOpts.RequirePinnedRemote = true
	}
	afterRes, err := config.Load(repoDir, afterLoadOpts)
	if err != nil {
		return nil, fmt.Errorf("resolve target config: %w", err)
	}

	newLock := lockfile.Generate(afterRes)
	newLockBytes, err := lockfile.Marshal(newLock)
	if err != nil {
		return nil, err
	}
	newLockSum := sha256.Sum256(newLockBytes)
	newLockDigestPreview := hex.EncodeToString(newLockSum[:])

	prevPolicyDigest := beforeRes.PolicyDigest
	if prevLock != nil && prevLock.PolicyDigest != "" {
		prevPolicyDigest = prevLock.PolicyDigest
	}
	plan := &Plan{
		Applied:              false,
		PreviousExtends:      beforeRes.Effective.Extends,
		TargetExtends:        targetExt,
		PreviousPolicyDigest: prevPolicyDigest,
		NewPolicyDigest:      afterRes.PolicyDigest,
		PreviousLockDigest:   prevLockDigest,
		NewLockDigest:        newLockDigestPreview,
		Warnings:             upgradeWarnings,
	}

	// Compare complete rules.
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

	// Compare complete checks (command, workdir, required, timeout, requires_bin, paths, components).
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
		} else if !checksEqual(bc, ac) {
			plan.ChangedChecks = append(plan.ChangedChecks,
				fmt.Sprintf("%s: cmd=%q->%q req=%v->%v timeout=%ds->%ds bin=%q->%q workdir=%q->%q",
					id, bc.Command, ac.Command, bc.IsRequired(), ac.IsRequired(),
					bc.TimeoutSeconds, ac.TimeoutSeconds, bc.RequiresBin, ac.RequiresBin, bc.Workdir, ac.Workdir))
		}
	}
	for id := range beforeChecks {
		if _, ok := afterChecks[id]; !ok {
			plan.RemovedChecks = append(plan.RemovedChecks, id)
		}
	}

	// Compare complete authorized skills and providers so source/version/tool/command changes surface.
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
		if s.Authorized && (!ok || !prev.Authorized || prev.Source != s.Source || prev.Version != s.Version) {
			plan.PermissionChanges = append(plan.PermissionChanges,
				fmt.Sprintf("skill %q authorized execution added/changed (%s@%s)", s.ID, s.Source, s.Version))
		}
	}
	for _, p := range afterRes.Effective.Providers {
		prev, ok := prevProvs[p.ID]
		if p.Authorized && (!ok || !prev.Authorized || prev.Tool != p.Tool || prev.Command != p.Command) {
			plan.PermissionChanges = append(plan.PermissionChanges,
				fmt.Sprintf("provider %q authorized command added/changed (%s: %s)", p.ID, p.Tool, p.Command))
		}
	}

	sort.Strings(plan.AddedRules)
	sort.Strings(plan.RemovedRules)
	sort.Strings(plan.ChangedRules)
	sort.Strings(plan.AddedChecks)
	sort.Strings(plan.RemovedChecks)
	sort.Strings(plan.ChangedChecks)
	sort.Strings(plan.PermissionChanges)

	// Canonical lock comparison ensures version-only or formatting mismatches are always repaired.
	lockChanged := prevLock == nil || !bytes.Equal(prevLockRaw, newLockBytes)
	cfgChanged := !bytes.Equal(rawBefore, rawAfter)
	plan.Changed = cfgChanged || lockChanged

	if opts.Apply && plan.Changed {
		// Stage both files in exclusively created temp files before renaming.
		var cfgTmp string
		if cfgChanged {
			var err error
			cfgTmp, err = stageTempFile(repoDir, ".waypost-cfg-*.tmp", rawAfter)
			if err != nil {
				return nil, err
			}
		}
		lockTmp, err := stageTempFile(repoDir, ".waypost-lock-*.tmp", newLockBytes)
		if err != nil {
			if cfgTmp != "" {
				_ = os.Remove(cfgTmp)
			}
			return nil, err
		}

		if cfgTmp != "" {
			if err := os.Rename(cfgTmp, cfgPath); err != nil {
				_ = os.Remove(cfgTmp)
				_ = os.Remove(lockTmp)
				return nil, fmt.Errorf("publish updated config: %w", err)
			}
		}
		lockPath := filepath.Join(repoDir, lockfile.LockFileName)
		if err := os.Rename(lockTmp, lockPath); err != nil {
			_ = os.Remove(lockTmp)
			// Roll back config file if lock publish failed.
			if cfgChanged {
				_ = os.WriteFile(cfgPath, rawBefore, 0o644)
			}
			return nil, fmt.Errorf("publish updated lockfile: %w", err)
		}
		plan.Applied = true
	}

	return plan, nil
}

func checksEqual(a, b config.Check) bool {
	return a.Command == b.Command &&
		a.Workdir == b.Workdir &&
		a.IsRequired() == b.IsRequired() &&
		a.TimeoutSeconds == b.TimeoutSeconds &&
		a.RequiresBin == b.RequiresBin &&
		a.Description == b.Description &&
		reflect.DeepEqual(a.Paths, b.Paths) &&
		reflect.DeepEqual(a.Components, b.Components)
}

func stageTempFile(dir, pattern string, content []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	name := f.Name()
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("chmod temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return name, nil
}

// replaceExtendsField updates or inserts `extends` in a YAML document, safely replacing
// scalar or alias nodes with a clean scalar string node.
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
			m.Content[i+1] = &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: newExtends,
			}
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
