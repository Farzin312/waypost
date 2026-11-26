package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the declarative v1 repository contract (.waypost.yaml).
type Config struct {
	SchemaVersion string            `yaml:"schema_version" json:"schema_version"`
	Name          string            `yaml:"name,omitempty" json:"name,omitempty"`
	PresetVersion string            `yaml:"preset_version,omitempty" json:"preset_version,omitempty"`
	Description   string            `yaml:"description,omitempty" json:"description,omitempty"`
	Extends       string            `yaml:"extends,omitempty" json:"extends,omitempty"`
	Policy        PolicyConfig      `yaml:"policy,omitempty" json:"policy"`
	Boundaries    *BoundariesConfig `yaml:"boundaries,omitempty" json:"boundaries,omitempty"`
	Rules         []Rule            `yaml:"rules,omitempty" json:"rules,omitempty"`
	Components    []ComponentConfig `yaml:"components,omitempty" json:"components,omitempty"`
	Pins          []CrossRepoPin    `yaml:"pins,omitempty" json:"pins,omitempty"`
	Checks        []Check           `yaml:"checks,omitempty" json:"checks,omitempty"`
	Skills        []SkillRef        `yaml:"skills,omitempty" json:"skills,omitempty"`
	Providers     []ProviderConfig  `yaml:"providers,omitempty" json:"providers,omitempty"`
	CoverageGaps  []string          `yaml:"coverage_gaps,omitempty" json:"coverage_gaps,omitempty"`
	// Explicit opt-out lists for disabling inherited entries by stable ID.
	// In CI mode, disabling a base-branch required check is caught by the base policy floor.
	DisableChecks []string `yaml:"disable_checks,omitempty" json:"disable_checks,omitempty"`
	DisableRules  []string `yaml:"disable_rules,omitempty" json:"disable_rules,omitempty"`
}

// PolicyConfig controls fail-closed verification and trust-boundary escalation.
type PolicyConfig struct {
	FailClosedOnUnmapped  *bool    `yaml:"fail_closed_on_unmapped,omitempty" json:"fail_closed_on_unmapped,omitempty"`
	RequireFrozenLockInCI *bool    `yaml:"require_frozen_lock_in_ci,omitempty" json:"require_frozen_lock_in_ci,omitempty"`
	EnforceBaseFloorInCI  *bool    `yaml:"enforce_base_floor_in_ci,omitempty" json:"enforce_base_floor_in_ci,omitempty"`
	TrustPaths            []string `yaml:"trust_paths,omitempty" json:"trust_paths,omitempty"`
	MaxContextItems       int      `yaml:"max_context_items,omitempty" json:"max_context_items,omitempty"`
}

// BoolVal returns the bool value or the fallback default when unset.
func BoolVal(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// BoolPtr returns a pointer to v.
func BoolPtr(v bool) *bool { return &v }

// Rule is a repository or preset engineering norm classified as either a
// permanent invariant or a model-era crutch subject to periodic pruning.
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Kind        string `yaml:"kind" json:"kind"` // "invariant" | "crutch"
	Summary     string `yaml:"summary" json:"summary"`
	ReviewAfter string `yaml:"review_after,omitempty" json:"review_after,omitempty"`
}

// ComponentConfig declares a repository component, its dependencies, entrypoints,
// trust paths, and bound checks.
type ComponentConfig struct {
	ID          string   `yaml:"id" json:"id"`
	Root        string   `yaml:"root" json:"root"`
	Kind        string   `yaml:"kind,omitempty" json:"kind,omitempty"`
	Language    string   `yaml:"language,omitempty" json:"language,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	DependsOn   []string `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Entrypoints []string `yaml:"entrypoints,omitempty" json:"entrypoints,omitempty"`
	TrustPaths  []string `yaml:"trust_paths,omitempty" json:"trust_paths,omitempty"`
	Checks      []string `yaml:"checks,omitempty" json:"checks,omitempty"`
	Paths       []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

// CrossRepoPin documents an explicit dependency on an external repository contract.
type CrossRepoPin struct {
	ID                 string   `yaml:"id" json:"id"`
	Producer           string   `yaml:"producer" json:"producer"`
	Artifact           string   `yaml:"artifact" json:"artifact"`
	Consumer           string   `yaml:"consumer" json:"consumer"`
	Version            string   `yaml:"version,omitempty" json:"version,omitempty"`
	CompatibilityCheck string   `yaml:"compatibility_check,omitempty" json:"compatibility_check,omitempty"`
	Paths              []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

// Check defines a deterministic verification command bound to file globs or components.
type Check struct {
	ID             string   `yaml:"id" json:"id"`
	Command        string   `yaml:"command" json:"command"`
	Workdir        string   `yaml:"workdir,omitempty" json:"workdir,omitempty"`
	Paths          []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Components     []string `yaml:"components,omitempty" json:"components,omitempty"`
	Required       *bool    `yaml:"required,omitempty" json:"required,omitempty"`
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	Description    string   `yaml:"description,omitempty" json:"description,omitempty"`
	// RequiresBin optionally specifies an executable name that must exist in PATH.
	// If missing on a required check, verify fails closed (FAIL, never PASS/SKIP).
	RequiresBin string `yaml:"requires_bin,omitempty" json:"requires_bin,omitempty"`
}

// IsRequired reports whether the check is required (defaults to true).
func (c Check) IsRequired() bool {
	return BoolVal(c.Required, true)
}

// SkillRef declares an external or standard agent skill/tool reference.
// Fetching/locking a skill never auto-authorizes script execution; `authorized: true`
// must be explicitly set and reviewed.
type SkillRef struct {
	ID          string `yaml:"id" json:"id"`
	Source      string `yaml:"source" json:"source"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
	Kind        string `yaml:"kind,omitempty" json:"kind,omitempty"` // "invariant" | "crutch"
	Authorized  bool   `yaml:"authorized,omitempty" json:"authorized,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// ProviderConfig configures an external read-only architecture/graph provider
// (for example, `bounds report --json`). Execution requires `authorized: true`.
type ProviderConfig struct {
	ID          string `yaml:"id" json:"id"`
	Tool        string `yaml:"tool" json:"tool"`
	Command     string `yaml:"command" json:"command"`
	Authorized  bool   `yaml:"authorized,omitempty" json:"authorized,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// InheritanceStep records one resolved ancestor in the single-parent chain.
type InheritanceStep struct {
	Ref     string `yaml:"ref" json:"ref"`
	Source  string `yaml:"source" json:"source"` // "builtin" | "file" | "remote"
	URL     string `yaml:"url,omitempty" json:"url,omitempty"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	SHA256  string `yaml:"sha256" json:"sha256"`
}

// ResolvedConfig holds the merged effective configuration alongside its provenance.
type ResolvedConfig struct {
	Effective            Config            `json:"effective"`
	RootPath             string            `json:"root_path"`
	Chain                []InheritanceStep `json:"chain"`
	PolicyDigest         string            `json:"policy_digest"`
	LocalOverrideApplied bool              `json:"local_override_applied"`
	LocalOverrideIgnored bool              `json:"local_override_ignored"`
	RawRootSHA256        string            `json:"raw_root_sha256"`
}

// BoundariesConfig configures Waypost's built-in polyglot architecture boundary engine,
// replacing external boundary tools with live zero-cache static import analysis.
type BoundariesConfig struct {
	Enabled             *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Mode                string         `yaml:"mode,omitempty" json:"mode,omitempty"` // "enforce" (default) | "warn"
	NoCycles            *bool          `yaml:"no_cycles,omitempty" json:"no_cycles,omitempty"`
	EnforceDeclaredDeps *bool          `yaml:"enforce_declared_deps,omitempty" json:"enforce_declared_deps,omitempty"`
	IgnorePaths         []string       `yaml:"ignore_paths,omitempty" json:"ignore_paths,omitempty"`
	Rules               []BoundaryRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// IsEnabled reports whether built-in boundary enforcement is active during verification.
func (b *BoundariesConfig) IsEnabled() bool {
	return b != nil && BoolVal(b.Enabled, false)
}

// EffectiveMode returns "enforce" or "warn" (defaults to "enforce").
func (b *BoundariesConfig) EffectiveMode() string {
	if b != nil && b.Mode == "warn" {
		return "warn"
	}
	return "enforce"
}

// BoundaryRule defines a declarative architectural import constraint between components.
type BoundaryRule struct {
	ID                string    `yaml:"id" json:"id"`
	From              string    `yaml:"from,omitempty" json:"from,omitempty"`                             // component ID or glob pattern
	Target            string    `yaml:"target,omitempty" json:"target,omitempty"`                         // target component ID or glob for public_entrypoints
	AllowDependsOn    *[]string `yaml:"allow_depends_on,omitempty" json:"allow_depends_on,omitempty"`     // optional allowlist; non-nil empty slice [] means pure leaf (no imports allowed)
	DenyDependsOn     []string  `yaml:"deny_depends_on,omitempty" json:"deny_depends_on,omitempty"`       // denylist of component IDs/globs
	PublicEntrypoints []string  `yaml:"public_entrypoints,omitempty" json:"public_entrypoints,omitempty"` // allowed target file globs for external importers
	Reason            string    `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// UnmarshalYAML preserves the schema's field presence and types. The default YAML
// decoder would coerce scalars to strings and conflate null with absent lists.
func (r *BoundaryRule) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: boundary rule must be a mapping", node.Line)
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]
		if value.Kind == yaml.AliasNode {
			value = value.Alias
		}
		switch key {
		case "id", "from", "target", "reason":
			if value.Tag != "!!str" || (key != "reason" && strings.TrimSpace(value.Value) == "") {
				return fmt.Errorf("line %d: boundary rule %s must be a valid string", value.Line, key)
			}
		case "allow_depends_on", "deny_depends_on", "public_entrypoints":
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("line %d: boundary rule %s must be a list of strings", value.Line, key)
			}
			for _, item := range value.Content {
				if item.Kind == yaml.AliasNode {
					item = item.Alias
				}
				if item.Tag != "!!str" {
					return fmt.Errorf("line %d: boundary rule %s must contain only strings", item.Line, key)
				}
			}
		default:
			return fmt.Errorf("line %d: unknown boundary rule field %q", node.Content[i].Line, key)
		}
	}
	type plainRule BoundaryRule
	return node.Decode((*plainRule)(r))
}
