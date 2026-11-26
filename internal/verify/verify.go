package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/policy"
	"github.com/Farzin312/waypost/internal/version"
)

// Strict 4-state verification statuses. SKIP and WARN are never reported as PASS.
const (
	StatusPass = "PASS"
	StatusFail = "FAIL"
	StatusWarn = "WARN"
	StatusSkip = "SKIP"
)

// Options configures a verification run.
type Options struct {
	Mode   string // "local" | "ci"
	Base   string
	Frozen bool
	All    bool
}

// Receipt is the versioned machine-readable verification artifact (receipt.v1.json).
type Receipt struct {
	ReceiptVersion  string         `json:"receipt_version"`
	SchemaVersion   string         `json:"schema_version"`
	ResolverVersion string         `json:"resolver_version"`
	CLIVersion      string         `json:"cli_version"`
	Platform        string         `json:"platform"`
	GeneratedAt     string         `json:"generated_at"`
	Authority       string         `json:"authority"` // "local" | "ci"
	Git             ReceiptGit     `json:"git"`
	Digests         ReceiptDigests `json:"digests"`
	Policy          ReceiptPolicy  `json:"policy"`
	Impact          ReceiptImpact  `json:"impact"`
	Checks          []CheckResult  `json:"checks"`
	Summary         ReceiptSummary `json:"summary"`
}

type ReceiptGit struct {
	IsGitRepo      bool   `json:"is_git_repo"`
	HeadSHA        string `json:"head_sha,omitempty"`
	TreeHash       string `json:"tree_hash,omitempty"`
	BaseRef        string `json:"base_ref,omitempty"`
	TargetSHA      string `json:"target_sha,omitempty"`
	BaseSHA        string `json:"base_sha,omitempty"`
	Dirty          bool   `json:"dirty"`
	MergeBaseError string `json:"merge_base_error,omitempty"`
}

type ReceiptDigests struct {
	EffectivePolicyDigest string `json:"effective_policy_digest"`
	ConfigSHA256          string `json:"config_sha256"`
	LockDigest            string `json:"lock_digest,omitempty"`
}

type ReceiptPolicy struct {
	TrustBoundaryTriggered   bool     `json:"trust_boundary_triggered"`
	PolicyFloorEnforced      bool     `json:"policy_floor_enforced"`
	FullRepoEscalated        bool     `json:"full_repo_escalated"`
	LocalOverrideApplied     bool     `json:"local_override_applied"`
	LocalOverrideIgnored     bool     `json:"local_override_ignored"`
	EscalationReasons        []string `json:"escalation_reasons,omitempty"`
	TamperingFindings        []string `json:"tampering_findings,omitempty"`
	LockRequired             bool     `json:"lock_required"`
	LockValid                bool     `json:"lock_valid"`
	LockMismatches           []string `json:"lock_mismatches,omitempty"`
	AuthorizationEscalations []string `json:"authorization_escalations,omitempty"`
	PreflightFailures        []string `json:"preflight_failures,omitempty"`
}

type ReceiptImpact struct {
	ChangedPaths         []string `json:"changed_paths,omitempty"`
	DirectComponents     []string `json:"direct_components,omitempty"`
	TransitiveDependents []string `json:"transitive_dependents,omitempty"`
	TriggeredPins        []string `json:"triggered_pins,omitempty"`
	UnmappedPaths        []string `json:"unmapped_paths,omitempty"`
}

type CheckResult struct {
	ID            string `json:"id"`
	Command       string `json:"command"`
	Workdir       string `json:"workdir,omitempty"`
	Required      bool   `json:"required"`
	FromBaseFloor bool   `json:"from_base_floor,omitempty"`
	Status        string `json:"status"` // PASS | FAIL | WARN | SKIP
	ExitCode      int    `json:"exit_code"`
	DurationMS    int64  `json:"duration_ms"`
	Reason        string `json:"reason,omitempty"`
	OutputExcerpt string `json:"output_excerpt,omitempty"`
}

type ReceiptSummary struct {
	Outcome string `json:"outcome"` // PASS | FAIL | WARN
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Warned  int    `json:"warned"`
	Skipped int    `json:"skipped"`
}

// Run executes waypost verification end-to-end and returns a deterministic Receipt.
// Security ordering:
// 1. Inspect git snapshot and resolve trusted base policy floor from git (never PR worktree).
// 2. Verify frozen lockfile and CI preflight guards BEFORE executing any providers or checks.
// 3. Build component map (enabling providers ONLY if lock & base policy allow them).
// 4. Plan and execute checks with strict 4-state outcomes and redacted excerpts.
func Run(repoDir string, opts Options) (*Receipt, error) {
	mode := opts.Mode
	if mode == "" {
		mode = "local"
	}

	resolved, err := config.Load(repoDir, config.LoadOptions{Mode: mode})
	if err != nil {
		return nil, err
	}
	canonicalRes := resolved
	if mode != "ci" && resolved.LocalOverrideApplied {
		canonicalRes, err = config.Load(repoDir, config.LoadOptions{Mode: "ci"})
		if err != nil {
			return nil, err
		}
	}

	snap, err := gitdiff.Inspect(repoDir, opts.Base, mode)
	if err != nil {
		return nil, err
	}

	// Load trusted base policy floor FIRST so PR cannot disable CI controls.
	baseFloor := policy.LoadBaseFloor(repoDir, mode, resolved, snap)
	lockReq := opts.Frozen || (mode == "ci" && baseFloor.RequireFrozenLockInCI)
	lockRes := lockfile.Verify(repoDir, canonicalRes)

	// Evaluate fail-closed preflight conditions BEFORE running any external providers or checks.
	var preflightFailures []string
	if lockReq && !lockRes.Valid {
		preflightFailures = append(preflightFailures, "frozen lockfile validation failed; aborting before executing commands")
	}
	if mode == "ci" {
		if snap.MergeBaseError != "" {
			preflightFailures = append(preflightFailures, "CI diff range invalid: "+snap.MergeBaseError)
		}
		if snap.IsGitRepo && snap.Dirty {
			preflightFailures = append(preflightFailures, "CI worktree is dirty (uncommitted changes would mix live inputs with committed HEAD identity)")
		}
		if snap.IsGitRepo && snap.BaseSHA == "" && !opts.All {
			preflightFailures = append(preflightFailures, "CI mode requires a valid git base ref (pass --base <ref>) or explicit --all")
		}
		if baseFloor.LoadError != "" {
			preflightFailures = append(preflightFailures, baseFloor.LoadError)
		}
	}

	// Only allow providers if preflight passed, lock is valid, and (in CI) base policy approved them.
	allowProviders := len(preflightFailures) == 0 && lockRes.Valid
	var allowedProvCmds map[string]string
	if mode == "ci" && baseFloor.Loaded && baseFloor.Enforced {
		allowedProvCmds = baseFloor.AllowedProviderCommands
	} else if mode == "ci" {
		// Without an established base policy floor, CI never executes newly introduced providers.
		allowProviders = false
	}

	var tracked []string
	if snap.IsGitRepo {
		tracked, _ = gitdiff.ListTrackedFiles(repoDir)
	}
	cm, err := compmap.BuildWithOptions(repoDir, &resolved.Effective, tracked, compmap.BuildOptions{
		AllowProviders:          allowProviders,
		AllowedProviderCommands: allowedProvCmds,
	})
	if err != nil {
		return nil, err
	}

	plan, err := policy.Plan(repoDir, mode, resolved, baseFloor, cm, snap, opts.All)
	if err != nil {
		return nil, err
	}

	vInfo := version.Current()
	rec := &Receipt{
		ReceiptVersion:  "1",
		SchemaVersion:   vInfo.SchemaVersion,
		ResolverVersion: vInfo.ResolverVersion,
		CLIVersion:      vInfo.CLIVersion,
		Platform:        vInfo.Platform,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Authority:       mode,
		Git: ReceiptGit{
			IsGitRepo:      snap.IsGitRepo,
			HeadSHA:        snap.HeadSHA,
			TreeHash:       snap.TreeHash,
			BaseRef:        snap.BaseRef,
			TargetSHA:      snap.TargetSHA,
			BaseSHA:        snap.BaseSHA,
			Dirty:          snap.Dirty,
			MergeBaseError: snap.MergeBaseError,
		},
		Digests: ReceiptDigests{
			EffectivePolicyDigest: plan.EffectivePolicyDigest,
			ConfigSHA256:          resolved.RawRootSHA256,
			LockDigest:            lockRes.LockDigest,
		},
		Policy: ReceiptPolicy{
			TrustBoundaryTriggered:   plan.TrustBoundaryTriggered,
			PolicyFloorEnforced:      plan.PolicyFloorEnforced,
			FullRepoEscalated:        plan.FullRepoEscalated,
			LocalOverrideApplied:     resolved.LocalOverrideApplied,
			LocalOverrideIgnored:     resolved.LocalOverrideIgnored,
			EscalationReasons:        plan.EscalationReasons,
			TamperingFindings:        plan.TamperingFindings,
			LockRequired:             lockReq,
			LockValid:                lockRes.Valid,
			LockMismatches:           lockRes.Mismatches,
			AuthorizationEscalations: lockRes.AuthorizationEscalation,
			PreflightFailures:        preflightFailures,
		},
		Impact: ReceiptImpact{
			ChangedPaths:         snap.AffectedPaths,
			DirectComponents:     plan.Impact.DirectComponents,
			TransitiveDependents: plan.Impact.TransitiveDependents,
			TriggeredPins:        plan.Impact.TriggeredPins,
			UnmappedPaths:        plan.Impact.UnmappedPaths,
		},
		Checks: make([]CheckResult, 0, len(plan.Checks)),
	}

	// Refuse to execute any check commands if preflight failed (e.g. invalid frozen lock or dirty CI).
	if len(preflightFailures) > 0 {
		for _, sc := range plan.Checks {
			cr := CheckResult{
				ID:            sc.Check.ID,
				Command:       sc.Check.Command,
				Workdir:       sc.Check.Workdir,
				Required:      sc.Check.IsRequired(),
				FromBaseFloor: sc.FromBase,
				Status:        StatusSkip,
				Reason:        "aborted before execution due to preflight failure",
			}
			rec.Checks = append(rec.Checks, cr)
			rec.Summary.Skipped++
		}
		rec.Summary.Outcome = StatusFail
		return rec, nil
	}

	for _, sc := range plan.Checks {
		cr := executeCheck(repoDir, sc)
		rec.Checks = append(rec.Checks, cr)
		switch cr.Status {
		case StatusPass:
			rec.Summary.Passed++
		case StatusFail:
			rec.Summary.Failed++
		case StatusWarn:
			rec.Summary.Warned++
		case StatusSkip:
			rec.Summary.Skipped++
		}
	}

	switch {
	case rec.Summary.Failed > 0:
		rec.Summary.Outcome = StatusFail
	case rec.Summary.Warned > 0:
		rec.Summary.Outcome = StatusWarn
	default:
		rec.Summary.Outcome = StatusPass
	}

	return rec, nil
}

func executeCheck(repoDir string, sc policy.SelectedCheck) CheckResult {
	chk := sc.Check
	req := chk.IsRequired()
	cr := CheckResult{
		ID:            chk.ID,
		Command:       chk.Command,
		Workdir:       chk.Workdir,
		Required:      req,
		FromBaseFloor: sc.FromBase,
		Reason:        sc.Reason,
	}

	if !sc.Selected {
		cr.Status = StatusSkip
		return cr
	}

	if chk.RequiresBin != "" {
		if _, err := exec.LookPath(chk.RequiresBin); err != nil {
			cr.ExitCode = 127
			cr.Reason = fmt.Sprintf("required executable %q not found in PATH", chk.RequiresBin)
			if req {
				cr.Status = StatusFail
			} else {
				cr.Status = StatusWarn
			}
			return cr
		}
	}

	timeout := time.Duration(chk.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", chk.Command)
	workDir := repoDir
	if chk.Workdir != "" {
		workDir = filepath.Join(repoDir, chk.Workdir)
	}
	cmd.Dir = workDir

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	start := time.Now()
	err := cmd.Run()
	cr.DurationMS = time.Since(start).Milliseconds()
	cr.OutputExcerpt = RedactAndTrim(buf.String(), 600)

	if err == nil {
		cr.Status = StatusPass
		cr.ExitCode = 0
		return cr
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		cr.ExitCode = 124
		cr.Reason = fmt.Sprintf("timed out after %s", timeout)
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		cr.ExitCode = exitErr.ExitCode()
	} else {
		cr.ExitCode = 1
		cr.Reason = err.Error()
	}

	if req {
		cr.Status = StatusFail
	} else {
		cr.Status = StatusWarn
	}
	return cr
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
	regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9\-_]{16,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[=:]\s*)([^\s'"]+)`),
}

// RedactAndTrim strips likely credentials from command excerpts and bounds length.
func RedactAndTrim(raw string, maxBytes int) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, re := range secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			if idx := strings.IndexAny(match, "=:"); idx > 0 {
				return match[:idx+1] + "[REDACTED]"
			}
			if strings.HasPrefix(strings.ToLower(match), "bearer ") {
				return match[:7] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	if maxBytes > 0 && len(s) > maxBytes {
		s = s[:maxBytes] + "... [truncated]"
	}
	return s
}

// WriteJSON writes receipt.v1.json cleanly to path.
func WriteJSON(path string, r *Receipt) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// RenderMarkdown formats a concise PR-friendly verification summary.
func RenderMarkdown(r *Receipt) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## Waypost Verification Receipt — `%s`\n\n", r.Summary.Outcome))
	b.WriteString(fmt.Sprintf("- **Authority:** `%s` | **CLI:** `waypost %s` (schema `%s`, resolver `%s`)\n",
		r.Authority, r.CLIVersion, r.SchemaVersion, r.ResolverVersion))
	if r.Git.IsGitRepo {
		b.WriteString(fmt.Sprintf("- **Git:** head `%s` | base `%s` | target `%s` | dirty `%v`\n",
			short(r.Git.HeadSHA), short(r.Git.BaseSHA), short(r.Git.TargetSHA), r.Git.Dirty))
	}
	b.WriteString(fmt.Sprintf("- **Digests:** policy `%s` | lock `%s` (valid: `%v`)\n",
		short(r.Digests.EffectivePolicyDigest), short(r.Digests.LockDigest), r.Policy.LockValid))
	if r.Policy.TrustBoundaryTriggered || r.Policy.FullRepoEscalated {
		b.WriteString(fmt.Sprintf("- **Escalation:** trust_boundary=`%v`, policy_floor=`%v`, full_repo=`%v`\n",
			r.Policy.TrustBoundaryTriggered, r.Policy.PolicyFloorEnforced, r.Policy.FullRepoEscalated))
	}
	b.WriteString(fmt.Sprintf("- **Totals:** %d PASS · %d FAIL · %d WARN · %d SKIP\n\n",
		r.Summary.Passed, r.Summary.Failed, r.Summary.Warned, r.Summary.Skipped))

	if len(r.Policy.PreflightFailures) > 0 {
		b.WriteString("### Preflight Failures (Execution Aborted)\n")
		for _, f := range r.Policy.PreflightFailures {
			b.WriteString("- " + f + "\n")
		}
		b.WriteString("\n")
	}
	if len(r.Policy.TamperingFindings) > 0 {
		b.WriteString("### Policy Floor Findings\n")
		for _, f := range r.Policy.TamperingFindings {
			b.WriteString("- " + f + "\n")
		}
		b.WriteString("\n")
	}
	if len(r.Policy.LockMismatches) > 0 {
		b.WriteString("### Lockfile Mismatches\n")
		for _, m := range r.Policy.LockMismatches {
			b.WriteString("- " + m + "\n")
		}
		b.WriteString("\n")
	}

	if len(r.Checks) > 0 {
		b.WriteString("| Check | Status | Required | Exit | Duration | Reason |\n")
		b.WriteString("| --- | --- | --- | ---: | ---: | --- |\n")
		for _, c := range r.Checks {
			b.WriteString(fmt.Sprintf("| `%s` | **%s** | %v | %d | %dms | %s |\n",
				c.ID, c.Status, c.Required, c.ExitCode, c.DurationMS, strings.ReplaceAll(c.Reason, "|", "\\|")))
		}
	} else {
		b.WriteString("_No checks declared._\n")
	}
	return b.String()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "-"
	}
	return s
}
