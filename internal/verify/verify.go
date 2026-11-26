package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/policy"
	"github.com/Farzin312/waypost/internal/shellcmd"
	"github.com/Farzin312/waypost/internal/version"
)

// Strict 4-state verification statuses. SKIP and WARN are never reported as PASS.
const (
	StatusPass = "PASS"
	StatusFail = "FAIL"
	StatusWarn = "WARN"
	StatusSkip = "SKIP"
)

const (
	// maxCapturedOutputBytes bounds per-check captured stdout/stderr in memory (64 KiB)
	// so noisy builds cannot exhaust RAM while still retaining both head and tail context.
	maxCapturedOutputBytes = 64 * 1024
	maxExcerptBytes        = 1200
)

// Options configures a verification run.
type Options struct {
	Mode    string // "local" | "ci"
	Base    string
	Frozen  bool
	All     bool
	Offline bool
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
// 1. Read any committed .waypost.lock remote SHA pins before resolving inheritance.
// 2. Inspect git snapshot and resolve trusted base policy floor from git (never PR worktree).
// 3. Verify frozen lockfile and CI preflight guards BEFORE executing any providers or checks.
// 4. Build component map (enabling providers ONLY if lock & base policy allow them).
// 5. Plan and execute checks with strict 4-state outcomes, bounded output, and redacted excerpts.
func Run(repoDir string, opts Options) (*Receipt, error) {
	mode := opts.Mode
	if mode == "" {
		mode = "local"
	}

	snap, err := gitdiff.Inspect(repoDir, opts.Base, mode)
	if err != nil {
		return nil, err
	}

	// Evaluate early git preflight failures BEFORE resolving remote presets so a
	// dirty or invalid CI checkout never makes outbound network requests.
	gitPreflightFailed := mode == "ci" && (snap.MergeBaseError != "" ||
		(snap.IsGitRepo && snap.Dirty) ||
		(snap.IsGitRepo && snap.BaseSHA == "" && !opts.All))

	existingLock, _, _ := lockfile.Read(repoDir)
	pinnedRemote := lockfile.PinnedRemoteSHAs(existingLock)
	requirePinnedRemote := opts.Frozen || opts.Offline || mode == "ci"

	loadOpts := config.LoadOptions{
		Mode:                mode,
		PinnedRemoteSHAs:    pinnedRemote,
		RequirePinnedRemote: requirePinnedRemote,
		Offline:             opts.Offline || gitPreflightFailed,
	}
	resolved, err := config.Load(repoDir, loadOpts)
	if err != nil {
		return nil, err
	}
	canonicalRes := resolved
	if mode != "ci" && resolved.LocalOverrideApplied {
		ciLoadOpts := loadOpts
		ciLoadOpts.Mode = "ci"
		canonicalRes, err = config.Load(repoDir, ciLoadOpts)
		if err != nil {
			return nil, err
		}
	}

	// Load trusted base policy floor FIRST so PR cannot disable CI controls.
	baseFloor := policy.LoadBaseFloor(repoDir, mode, resolved, snap, opts.Offline)
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
	var scanOptions archgraph.AnalyzeOptions
	var inventoryErr error
	if snap.IsGitRepo {
		tracked, inventoryErr = gitdiff.ListTrackedFiles(repoDir)
		if mode == "ci" {
			scanOptions.AllowedFiles = fileInventory(tracked)
		} else {
			working, err := gitdiff.ListWorkingFiles(repoDir)
			if err == nil {
				scanOptions.AllowedFiles = fileInventory(working)
				scanOptions.AllowMissingFiles = true
			} else {
				inventoryErr = err
			}
		}
	}
	mapOptions := compmap.BuildOptions{AllowedFiles: scanOptions.AllowedFiles}
	cm, err := compmap.BuildWithOptions(repoDir, &resolved.Effective, tracked, mapOptions)
	if err != nil {
		return nil, err
	}
	plan, err := policy.Plan(repoDir, mode, resolved, baseFloor, cm, snap, opts.All)
	if err != nil {
		return nil, err
	}

	// Boundary checks run on static maps before any provider or shell command can mutate the tree.
	var boundaryCheck *CheckResult
	if len(preflightFailures) == 0 && plan.EffectiveBoundaries.IsEnabled() {
		check := checkBoundaries(repoDir, cm, plan.EffectiveBoundaries, baseFloor, snap, scanOptions, inventoryErr)
		boundaryCheck = &check
	}
	if allowProviders && len(resolved.Effective.Providers) > 0 {
		mapOptions.AllowProviders = true
		mapOptions.AllowedProviderCommands = allowedProvCmds
		cm, err = compmap.BuildWithOptions(repoDir, &resolved.Effective, tracked, mapOptions)
		if err != nil {
			return nil, err
		}
		plan, err = policy.Plan(repoDir, mode, resolved, baseFloor, cm, snap, opts.All)
		if err != nil {
			return nil, err
		}
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

	if boundaryCheck != nil {
		rec.addCheck(*boundaryCheck)
	}
	for _, sc := range plan.Checks {
		rec.addCheck(executeCheck(repoDir, sc))
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

func (r *Receipt) addCheck(check CheckResult) {
	r.Checks = append(r.Checks, check)
	switch check.Status {
	case StatusPass:
		r.Summary.Passed++
	case StatusFail:
		r.Summary.Failed++
	case StatusWarn:
		r.Summary.Warned++
	case StatusSkip:
		r.Summary.Skipped++
	}
}

func fileInventory(files []string) map[string]bool {
	inventory := make(map[string]bool, len(files))
	for _, f := range files {
		inventory[f] = true
	}
	return inventory
}

func checkBoundaries(repoDir string, cm *compmap.Map, boundaries *config.BoundariesConfig, floor policy.BaseFloor, snap *gitdiff.Snapshot, opts archgraph.AnalyzeOptions, inventoryErr error) CheckResult {
	start := time.Now()
	required := boundaries.EffectiveMode() == "enforce"
	check := CheckResult{ID: "waypost-boundaries", Command: "waypost graph --check-boundaries (built-in)", Required: required}
	baseEnforced := floor.Loaded && floor.Enforced && floor.BaseConfig != nil && floor.BaseConfig.Effective.Boundaries.IsEnabled()
	check.FromBaseFloor = baseEnforced
	if required {
		check.Status = StatusFail
	} else {
		check.Status = StatusWarn
	}
	check.ExitCode = 1

	report, violations, err := collectBoundaryViolations(repoDir, cm, boundaries, floor, snap, baseEnforced, opts, inventoryErr)
	check.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		check.Reason = "boundary analysis error: " + err.Error()
		return check
	}
	if len(violations) == 0 {
		check.Status = StatusPass
		check.ExitCode = 0
		check.Reason = fmt.Sprintf("0 violations (%d files, %d imports, %d edges)", report.FilesScanned, report.ImportsScanned, len(report.Edges))
		return check
	}
	check.Reason = fmt.Sprintf("%d boundary violation(s)", len(violations))
	var lines []string
	for i, violation := range violations {
		if i >= 12 {
			lines = append(lines, fmt.Sprintf("... +%d more violations", len(violations)-12))
			break
		}
		lines = append(lines, fmt.Sprintf("[%s] %s", violation.RuleID, violation.Message))
	}
	check.OutputExcerpt = RedactAndTrim(strings.Join(lines, "\n"), maxExcerptBytes)
	return check
}

// Stage only static discovery inputs from the trusted Git tree. New or modified
// worktree manifests cannot change how the base policy assigns component ownership.
func buildBaseBoundaryMap(repoDir string, snap *gitdiff.Snapshot, base *config.Config) (*compmap.Map, error) {
	ref := snap.TargetSHA
	if ref == "" {
		ref = snap.BaseSHA
	}
	files, err := gitdiff.RegularFilesAtRef(repoDir, ref)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "waypost-base-components-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	paths := make([]string, 0, len(files))
	for rel := range files {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		if !compmap.StaticComponentInput(rel) {
			continue
		}
		dest := filepath.Join(dir, rel)
		if !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("invalid base discovery path %q", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return nil, err
		}
		var raw []byte
		if filepath.Ext(rel) != ".py" {
			if files[rel] > compmap.MaxStaticDiscoveryBytes {
				return nil, fmt.Errorf("base discovery input %q exceeds %d bytes", rel, compmap.MaxStaticDiscoveryBytes)
			}
			var found bool
			raw, found, err = gitdiff.ReadFileAtRef(repoDir, ref, rel)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, fmt.Errorf("base discovery input %q is missing at %s", rel, ref)
			}
		}
		if err := os.WriteFile(dest, raw, 0o600); err != nil {
			return nil, err
		}
	}
	return compmap.BuildWithOptions(dir, base, nil, compmap.BuildOptions{AllowedFiles: fileInventory(paths)})
}

func collectBoundaryViolations(repoDir string, cm *compmap.Map, boundaries *config.BoundariesConfig, floor policy.BaseFloor, snap *gitdiff.Snapshot, baseEnforced bool, opts archgraph.AnalyzeOptions, inventoryErr error) (*archgraph.Report, []archgraph.Violation, error) {
	if inventoryErr != nil {
		return nil, nil, fmt.Errorf("list Git scan inputs: %w", inventoryErr)
	}
	var violations []archgraph.Violation
	if baseEnforced {
		base := &floor.BaseConfig.Effective
		baseMap, err := buildBaseBoundaryMap(repoDir, snap, base)
		if err != nil {
			return nil, nil, fmt.Errorf("build trusted base component map: %w", err)
		}
		baseReport, err := archgraph.AnalyzeWithOptions(repoDir, baseMap, base.Boundaries, opts)
		if err != nil {
			return nil, nil, fmt.Errorf("scan trusted base boundary policy: %w", err)
		}
		violations = append(violations, baseReport.Violations...)
	}
	report, err := archgraph.AnalyzeWithOptions(repoDir, cm, boundaries, opts)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[archgraph.Violation]bool)
	merged := make([]archgraph.Violation, 0, len(violations)+len(report.Violations))
	for _, v := range slices.Concat(violations, report.Violations) {
		key := v
		key.Severity = ""
		if v.Kind != "scan-error" && v.Kind != "cycle" {
			key.Message = ""
		}
		if !seen[key] {
			seen[key] = true
			merged = append(merged, v)
		}
	}
	return report, merged, nil
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

	cmd := shellcmd.CommandContext(ctx, chk.Command)
	workDir := repoDir
	if chk.Workdir != "" {
		workDir = filepath.Join(repoDir, chk.Workdir)
	}
	cmd.Dir = workDir

	buf := newCappedBuffer(maxCapturedOutputBytes)
	cmd.Stdout = buf
	cmd.Stderr = buf

	start := time.Now()
	err := cmd.Run()
	cr.DurationMS = time.Since(start).Milliseconds()
	cr.OutputExcerpt = RedactAndTrim(buf.String(), maxExcerptBytes)

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

// cappedBuffer bounds captured command output in memory while preserving both
// the initial head and rolling tail so error summaries at the end are retained.
type cappedBuffer struct {
	mu        sync.Mutex
	headLimit int
	tailLimit int
	head      []byte
	tail      []byte
	dropped   int64
}

func newCappedBuffer(totalLimit int) *cappedBuffer {
	if totalLimit < 256 {
		totalLimit = 256
	}
	headLimit := totalLimit / 4
	tailLimit := totalLimit - headLimit
	return &cappedBuffer{
		headLimit: headLimit,
		tailLimit: tailLimit,
	}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	origLen := len(p)
	if len(b.head) < b.headLimit {
		need := b.headLimit - len(b.head)
		if len(p) <= need {
			b.head = append(b.head, p...)
			return origLen, nil
		}
		b.head = append(b.head, p[:need]...)
		p = p[need:]
	}

	// Append remaining bytes into rolling tail window of size tailLimit.
	if len(p) >= b.tailLimit {
		b.dropped += int64(len(b.tail) + len(p) - b.tailLimit)
		b.tail = append(b.tail[:0], p[len(p)-b.tailLimit:]...)
		return origLen, nil
	}
	overflow := len(b.tail) + len(p) - b.tailLimit
	if overflow > 0 {
		b.dropped += int64(overflow)
		copy(b.tail, b.tail[overflow:])
		b.tail = b.tail[:len(b.tail)-overflow]
	}
	b.tail = append(b.tail, p...)
	return origLen, nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dropped == 0 {
		out := make([]byte, 0, len(b.head)+len(b.tail))
		out = append(out, b.head...)
		out = append(out, b.tail...)
		return string(out)
	}
	marker := fmt.Sprintf("\n... [%d bytes omitted] ...\n", b.dropped)
	out := make([]byte, 0, len(b.head)+len(marker)+len(b.tail))
	out = append(out, b.head...)
	out = append(out, marker...)
	out = append(out, b.tail...)
	return string(out)
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
	regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9\-_]{16,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s'"]+)`),
}

// RedactAndTrim strips likely credentials from command excerpts and bounds length,
// keeping both head and tail when truncated so trailing failure traces stay visible.
func RedactAndTrim(raw string, maxBytes int) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, re := range secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			if strings.HasPrefix(strings.ToLower(match), "bearer ") {
				return match[:7] + "[REDACTED]"
			}
			if idx := strings.IndexAny(match, "=:"); idx > 0 {
				return match[:idx+1] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	if maxBytes > 0 && len(s) > maxBytes {
		const sep = "\n... [truncated] ...\n"
		if maxBytes <= len(sep)+16 {
			return s[:maxBytes] + "... [truncated]"
		}
		avail := maxBytes - len(sep)
		headLen := avail / 3
		tailLen := avail - headLen
		s = strings.TrimRight(s[:headLen], "\r\n ") + sep + strings.TrimLeft(s[len(s)-tailLen:], "\r\n ")
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
