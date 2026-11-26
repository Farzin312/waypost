package verify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/policy"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/shellcmd"
	"github.com/Farzin312/waypost/internal/version"
	"github.com/Farzin312/waypost/internal/workstate"
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
	Mode           string // "local" | "ci"
	Base           string
	Frozen         bool
	All            bool
	Offline        bool
	Jobs           int
	AllowBootstrap bool
	Providers      bool
}

// Receipt is the versioned machine-readable verification artifact (receipt.v1.json).
type Receipt struct {
	Verifier        version.Info   `json:"verifier"`
	PlanComplete    bool           `json:"plan_complete"`
	NoWorkReason    string         `json:"no_work_reason,omitempty"`
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
	TargetPolicyDigest    string `json:"target_policy_digest,omitempty"`
	HeadPolicyDigest      string `json:"head_policy_digest,omitempty"`
	EffectivePolicyDigest string `json:"effective_policy_digest"`
	ConfigSHA256          string `json:"config_sha256"`
	LockDigest            string `json:"lock_digest,omitempty"`
}

type ReceiptPolicy struct {
	ApplicableRules          []string                  `json:"applicable_rules,omitempty"`
	Providers                []compmap.ProviderStatus  `json:"providers,omitempty"`
	ReviewRecommended        bool                      `json:"review_recommended,omitempty"`
	ReviewReasons            []changeplan.ReviewReason `json:"review_reasons,omitempty"`
	TrustBoundaryTriggered   bool                      `json:"trust_boundary_triggered"`
	PolicyFloorEnforced      bool                      `json:"policy_floor_enforced"`
	FullRepoEscalated        bool                      `json:"full_repo_escalated"`
	LocalOverrideApplied     bool                      `json:"local_override_applied"`
	LocalOverrideIgnored     bool                      `json:"local_override_ignored"`
	EscalationReasons        []string                  `json:"escalation_reasons,omitempty"`
	TamperingFindings        []string                  `json:"tampering_findings,omitempty"`
	LockRequired             bool                      `json:"lock_required"`
	LockValid                bool                      `json:"lock_valid"`
	LockMismatches           []string                  `json:"lock_mismatches,omitempty"`
	AuthorizationEscalations []string                  `json:"authorization_escalations,omitempty"`
	PreflightFailures        []string                  `json:"preflight_failures,omitempty"`
}

type ReceiptImpact struct {
	ChangedPaths         []string `json:"changed_paths,omitempty"`
	DirectComponents     []string `json:"direct_components,omitempty"`
	TransitiveDependents []string `json:"transitive_dependents,omitempty"`
	TriggeredPins        []string `json:"triggered_pins,omitempty"`
	UnmappedPaths        []string `json:"unmapped_paths,omitempty"`
}

type CheckResult struct {
	Lane             string `json:"lane"`
	DefinitionSource string `json:"definition_source"`
	SelectionReason  string `json:"selection_reason,omitempty"`
	ID               string `json:"id"`
	Command          string `json:"command"`
	Workdir          string `json:"workdir,omitempty"`
	Required         bool   `json:"required"`
	FromBaseFloor    bool   `json:"from_base_floor,omitempty"`
	Status           string `json:"status"` // PASS | FAIL | WARN | SKIP
	ExitCode         int    `json:"exit_code"`
	DurationMS       int64  `json:"duration_ms"`
	Reason           string `json:"reason,omitempty"`
	OutputExcerpt    string `json:"output_excerpt,omitempty"`
}

type ReceiptSummary struct {
	Outcome string `json:"outcome"` // PASS | FAIL | WARN
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Warned  int    `json:"warned"`
	Skipped int    `json:"skipped"`
}

// Run builds and validates the full verification plan before starting external work.
func Run(repoDir string, opts Options) (*Receipt, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, repoDir, opts)
}

func run(ctx context.Context, repoDir string, opts Options) (*Receipt, error) {
	mode := opts.Mode
	if mode == "" {
		mode = "local"
	}
	if mode != "local" && mode != "ci" {
		return nil, fmt.Errorf("unknown verification mode %q", mode)
	}
	jobs := opts.Jobs
	if jobs == 0 {
		jobs = min(2, runtime.NumCPU())
	}
	if jobs < 1 {
		return nil, fmt.Errorf("jobs must be positive")
	}

	v := version.Verifier()
	rec := &Receipt{
		ReceiptVersion: "1", SchemaVersion: v.SchemaVersion, ResolverVersion: v.ResolverVersion,
		CLIVersion: v.CLIVersion, Platform: v.Platform, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Authority: mode, Verifier: v, Checks: []CheckResult{},
	}
	fail := func(err error) {
		if err != nil {
			rec.Policy.PreflightFailures = append(rec.Policy.PreflightFailures, err.Error())
		}
	}
	if mode == "ci" && opts.Base == "" {
		opts.Base = os.Getenv("WAYPOST_CI_BASE")
	}
	bootstrap := false
	if mode == "ci" && (opts.Base == "" || allZero(opts.Base)) && opts.AllowBootstrap {
		bootstrap = true
		opts.Base = ""
	}
	snap, err := gitdiff.Inspect(repoDir, opts.Base, mode)
	if mode == "local" && err != nil {
		return nil, err
	}
	fail(err)
	rec.Git = ReceiptGit{
		IsGitRepo: snap.IsGitRepo, HeadSHA: snap.HeadSHA, TreeHash: snap.TreeHash,
		BaseRef: snap.BaseRef, TargetSHA: snap.TargetSHA, BaseSHA: snap.BaseSHA,
		Dirty: snap.Dirty, MergeBaseError: snap.MergeBaseError,
	}
	rec.Impact.ChangedPaths = snap.AffectedPaths
	selfBase := snap.TargetSHA != "" && (snap.TargetSHA == snap.HeadSHA || snap.BaseSHA == snap.HeadSHA)
	if mode == "ci" {
		if selfBase {
			fail(errors.New("CI comparison target or merge-base points to the worktree HEAD"))
		}
		if !snap.IsGitRepo {
			fail(errors.New("CI requires a Git worktree"))
		}
		if snap.Dirty {
			fail(errors.New("CI worktree is dirty (uncommitted changes would mix live inputs with committed HEAD identity)"))
		}
		if snap.MergeBaseError != "" {
			fail(fmt.Errorf("CI diff range invalid: %s", snap.MergeBaseError))
		}
		if (!gitdiff.ValidSHA(snap.BaseSHA) || !gitdiff.ValidSHA(snap.TargetSHA)) && !bootstrap {
			fail(errors.New("CI requires a verified target base (pass --base <ref> or set WAYPOST_CI_BASE)"))
		}
	}

	store := repoview.NewStore(repoDir)
	defer store.Close()
	var head, target, prior *project.Snapshot
	var headView *repoview.View
	var fingerprint, stateError string
	var selection workstate.Selection
	if mode == "ci" {
		if gitdiff.ValidSHA(snap.HeadSHA) {
			headView, err = store.Tree(snap.HeadSHA)
		}
	} else {
		headView, err = repoview.Working(repoDir)
		if headView != nil && headView.SHA != "" {
			defer func() {
				if err := saveWorkState(headView, selection, fingerprint, stateError, rec); err != nil {
					rec.Policy.EscalationReasons = append(rec.Policy.EscalationReasons, "cannot save work state: "+err.Error())
				}
			}()
			var fingerprintErr error
			fingerprint, fingerprintErr = workstate.Fingerprint(headView)
			if fingerprintErr != nil {
				stateError = fingerprintErr.Error()
				rec.Policy.EscalationReasons = append(rec.Policy.EscalationReasons, "work state unavailable: "+stateError)
			}
		}
	}
	fail(err)
	load := config.LoadOptions{Mode: mode, RequirePinnedRemote: opts.Frozen || opts.Offline || mode == "ci", Offline: opts.Offline || len(rec.Policy.PreflightFailures) > 0}
	if headView != nil {
		head, err = project.Load(headView, load, compmap.BuildOptions{})

		fail(err)
	}
	if head == nil || head.Policy == nil {
		fail(errors.New("repository has no readable .waypost.yaml policy"))
	}
	readCommit := func(sha string) (*project.Snapshot, error) {
		if sha == "" {
			return nil, nil
		}
		view, err := store.Tree(sha)
		if err != nil {
			return nil, err
		}
		return project.Load(view, config.LoadOptions{Offline: load.Offline}, compmap.BuildOptions{})
	}
	if snap.TargetSHA != "" && (mode == "ci" || snap.TargetSHA != snap.BaseSHA) {
		target, err = readCommit(snap.TargetSHA)
		if mode == "ci" && err != nil {
			fail(fmt.Errorf("unable to load base policy floor: %w", err))
		}
	}
	if snap.BaseSHA == snap.TargetSHA && target != nil {
		prior = target
	} else if snap.BaseSHA != "" {
		prior, err = readCommit(snap.BaseSHA)
		if mode == "ci" && err != nil {
			fail(fmt.Errorf("unable to load merge-base inventory: %w", err))
		}
	}
	if mode == "ci" && target != nil && target.Policy == nil {
		if !opts.AllowBootstrap {
			fail(errors.New("CI target lacks .waypost.yaml; first adoption requires --allow-bootstrap"))
		} else {
			bootstrap = true
		}
	}
	if bootstrap {
		if err := verifyBootstrap(repoDir, snap.HeadSHA, snap.TargetSHA); err != nil {
			fail(err)
		}
	}

	lockRequired := opts.Frozen || (mode == "ci" && (head == nil || head.Config() == nil || config.BoolVal(head.Config().Policy.RequireFrozenLockInCI, true)))
	if target != nil && target.Config() != nil && config.BoolVal(target.Config().Policy.RequireFrozenLockInCI, true) && mode == "ci" {
		lockRequired = true
	}
	rec.Policy.LockRequired = lockRequired
	if head != nil && head.Policy != nil {
		canonical := head.Policy
		if head.Policy.LocalOverrideApplied {
			canonicalLoad := load
			canonicalLoad.Mode = "ci"
			canonicalLoad.PinnedBuiltins = lockfile.PinnedBuiltins(head.Lock)
			canonicalLoad.PinnedRemoteSHAs = lockfile.PinnedRemoteSHAs(head.Lock)
			canonical, err = config.Load(repoDir, canonicalLoad)
			fail(err)
		}
		if head.Lock != nil && canonical != nil {
			lv := lockfile.VerifyParsed(head.Lock, head.LockDigest, canonical)
			rec.Policy.LockValid = lv.Valid
			rec.Policy.LockMismatches = lv.Mismatches
			rec.Policy.AuthorizationEscalations = lv.AuthorizationEscalation
		}
		rec.Policy.LocalOverrideApplied = head.Policy.LocalOverrideApplied
		rec.Policy.LocalOverrideIgnored = head.Policy.LocalOverrideIgnored
		if mode == "ci" {
			_, err := os.Lstat(filepath.Join(repoDir, config.LocalConfigFileName))
			rec.Policy.LocalOverrideIgnored = err == nil
		}
		rec.Digests.ConfigSHA256 = head.Policy.RawRootSHA256
		rec.Digests.EffectivePolicyDigest = head.Policy.PolicyDigest
		rec.Digests.HeadPolicyDigest = head.Policy.PolicyDigest
		rec.Digests.LockDigest = head.LockDigest
		fail(project.ValidateProofs(headView, head.Config()))
		fail(project.ValidateReferences(head.Config(), head.Map))
	}
	if lockRequired && !rec.Policy.LockValid {
		fail(errors.New("frozen lockfile validation failed; aborting before executing commands"))
	}

	enforce := mode == "ci" && !selfBase && target != nil && target.Config() != nil && config.BoolVal(target.Config().Policy.EnforceBaseFloorInCI, true)
	var baseBaseline *archgraph.BaselineFile
	var blockingFloor []string
	boundaryPreflightOK := len(rec.Policy.PreflightFailures) == 0
	if mode == "ci" && target != nil && target.Policy != nil {
		rec.Digests.TargetPolicyDigest = target.Policy.PolicyDigest
		if (target.Lock == nil && config.BoolVal(target.Config().Policy.RequireFrozenLockInCI, true)) || (target.Lock != nil && !lockfile.VerifyParsed(target.Lock, target.LockDigest, target.Policy).Valid) {
			fail(errors.New("trusted target lock is missing or does not match resolved policy"))
		}
	}
	if enforce && head != nil && head.Config() != nil {
		fail(project.ValidateProofs(headView, target.Config()))
		var findings []string
		findings, blockingFloor, baseBaseline = policy.CompareFloor(target, head, prior)
		rec.Policy.TamperingFindings = findings
		for _, item := range blockingFloor {
			fail(errors.New(item))
		}
	}
	rec.Policy.PolicyFloorEnforced = enforce
	if enforce && rec.Digests.HeadPolicyDigest != "" && rec.Digests.TargetPolicyDigest != rec.Digests.HeadPolicyDigest {
		digest := sha256.Sum256([]byte("waypost-v1-base:" + rec.Digests.TargetPolicyDigest + "\x00head:" + rec.Digests.HeadPolicyDigest))
		rec.Digests.EffectivePolicyDigest = fmt.Sprintf("%x", digest)
	}

	complete := snap.IsGitRepo && snap.BaseSHA != "" && snap.MergeBaseError == "" && prior != nil
	if bootstrap {
		complete = len(rec.Policy.PreflightFailures) == 0
	}
	if mode == "local" && !snap.IsGitRepo {
		complete = false
	}
	side := func(p *project.Snapshot) changeplan.Side {
		if p == nil {
			return changeplan.Side{}
		}
		return changeplan.Side{Config: p.Config(), Map: p.Map}
	}
	buildPlan := func() changeplan.Plan {
		plan := changeplan.Create(side(prior), side(head), snap.Changes, opts.All || bootstrap, complete, false)
		if enforce {
			obligations := changeplan.Create(side(target), side(head), snap.Changes, plan.Full, complete, true)
			plan.Checks = obligations.Checks
			plan.Review = mergeReviews(plan.Review, obligations.Review)
			plan.Full = obligations.Full
			plan.TrustHits = merged(plan.TrustHits, obligations.TrustHits)
			plan.Impact.TriggeredPins = merged(plan.Impact.TriggeredPins, obligations.Impact.TriggeredPins)
		}
		return plan
	}
	plan := buildPlan()

	if opts.Providers && head != nil && head.Config() != nil && len(rec.Policy.PreflightFailures) == 0 {
		// Discovery can select a previously unselected check.
		for _, check := range head.Config().Checks {
			if err := validateWorkdir(repoDir, check.Workdir); err != nil {
				fail(fmt.Errorf("check %q: %w", check.ID, err))
			}
		}
	}

	var input handoff
	if len(rec.Policy.PreflightFailures) == 0 {
		var cleanup func()
		input, cleanup, err = handoffFile(snap)
		defer cleanup()
		if mode == "ci" {
			fail(err)
		}
	}
	for _, check := range plan.Checks {
		if check.Selected {
			if err := validateWorkdir(repoDir, check.Check.Workdir); err != nil {
				fail(fmt.Errorf("check %q: %w", check.Check.ID, err))
			}
		}
	}

	// Static boundary diagnostics remain available when policy-floor preflight
	// blocks execution. Git and lock failures still prevent every evaluation.
	if boundaryPreflightOK && head != nil && (head.Boundaries().IsEnabled() || enforce && target.Boundaries().IsEnabled()) {
		check, scanned := checkArchitecture(target, head, enforce, baseBaseline, blockingFloor)
		rec.addCheck(check)
		if mode == "ci" && !scanned {
			fail(errors.New("CI boundary inventory could not be scanned completely"))
		}
	}

	// A provider is opt-in. CI also requires the same tool and command on the target.
	if opts.Providers && ctx.Err() == nil && len(rec.Policy.PreflightFailures) == 0 && head != nil &&
		rec.Policy.LockValid && !rec.Policy.LocalOverrideApplied && len(head.Config().Providers) > 0 {
		options := compmap.BuildOptions{View: headView, Context: ctx, AllowProviders: mode != "ci" || enforce}
		if mode == "ci" && enforce {
			options.AllowedProviderCommands = make(map[string]string)
			for _, old := range target.Config().Providers {
				for _, current := range head.Config().Providers {
					if old.Authorized && old.ID == current.ID && old.Tool == current.Tool {
						options.AllowedProviderCommands[old.ID] = old.Command
					}
				}
			}
		}
		discovery, err := compmap.BuildWithOptions(repoDir, head.Config(), nil, options)
		if err != nil {
			fail(err)
		} else {
			rec.Policy.Providers = discovery.ProviderStatuses
			discovery.PinInputs = head.Map.PinInputs
			head.Map = discovery
			plan = buildPlan()
		}
	}
	selection = workstate.Selection{BaseSHA: snap.BaseSHA, TargetSHA: snap.TargetSHA, PlanDigest: plan.Digest()}
	for _, r := range plan.Invariants {
		rec.Policy.ApplicableRules = append(rec.Policy.ApplicableRules, r.ID)
	}
	if enforce {
		for _, r := range target.Config().Rules {
			if r.Kind == "invariant" {
				rec.Policy.ApplicableRules = append(rec.Policy.ApplicableRules, r.ID)
			}
		}
	}
	rec.Policy.ApplicableRules = merged(rec.Policy.ApplicableRules, nil)
	rec.Policy.ReviewReasons = plan.Review
	rec.Policy.ReviewRecommended = len(plan.Review) > 0
	rec.Policy.TrustBoundaryTriggered = len(plan.TrustHits) > 0
	rec.Policy.FullRepoEscalated = plan.Full
	if len(plan.TrustHits) > 0 {
		rec.Policy.EscalationReasons = append(rec.Policy.EscalationReasons, fmt.Sprintf("trust-boundary paths modified: %q", plan.TrustHits))
	}
	if !complete {
		rec.Policy.EscalationReasons = append(rec.Policy.EscalationReasons, "change attribution incomplete")
	}
	if len(plan.Impact.UnmappedPaths) > 0 && plan.Full {
		rec.Policy.EscalationReasons = append(rec.Policy.EscalationReasons, "unmapped changed paths escalated verification")
	}
	if opts.All {
		rec.Policy.EscalationReasons = append(rec.Policy.EscalationReasons, "--all requested full verification")
	}
	rec.Impact.DirectComponents = plan.Impact.DirectComponents
	rec.Impact.TransitiveDependents = plan.Impact.TransitiveDependents
	rec.Impact.TriggeredPins = plan.Impact.TriggeredPins
	rec.Impact.UnmappedPaths = plan.Impact.UnmappedPaths

	rec.PlanComplete = complete && len(rec.Policy.PreflightFailures) == 0
	if len(rec.Policy.PreflightFailures) > 0 {
		for _, c := range plan.Checks {
			result := checkResult(c, "full")
			result.Status = StatusSkip
			result.Reason = "aborted before execution due to preflight failure"
			rec.addCheck(result)
		}
		rec.Summary.Outcome = StatusFail
		return rec, nil
	}
	safe := mode == "local" && !plan.Full && input.file != "" && safeChanges(plan, headView, head.Map)
	production := slices.ContainsFunc(plan.Changes, func(ch changeplan.Ownership) bool {
		return project.ProductionFile(ch.Path)
	})
	for _, result := range schedule(plan.Checks, jobs, func(check changeplan.Check) CheckResult {
		if safe && check.Selected && check.Check.LocalCommand != "" &&
			(!production || explicitTestCommand(check.Check.LocalCommand, check.Check.Workdir, headView)) {
			local := check
			local.Check.Command = check.Check.LocalCommand
			result := executeCheckContext(ctx, repoDir, local, "local_changed", input)
			if result.ExitCode != noTestsExitCode || ctx.Err() != nil {
				return result
			}
			full := executeCheckContext(ctx, repoDir, check, "full", input)
			full.DurationMS += result.DurationMS
			full.Reason = "local selector found no tests; ran full command: " + full.Reason
			return full
		}
		return executeCheckContext(ctx, repoDir, check, "full", input)
	}) {
		rec.addCheck(result)
	}
	if rec.Summary.Passed+rec.Summary.Failed+rec.Summary.Warned == 0 {
		rec.NoWorkReason = "no checks matched the changes"
	}
	switch {
	case ctx.Err() != nil:
		rec.PlanComplete = false
		fail(ctx.Err())
		rec.Summary.Outcome = StatusFail
	case rec.Summary.Failed > 0:
		rec.Summary.Outcome = StatusFail
	case rec.Summary.Warned > 0:
		rec.Summary.Outcome = StatusWarn
	default:
		rec.Summary.Outcome = StatusPass
	}
	return rec, nil
}

func allZero(ref string) bool {
	return (len(ref) == 40 || len(ref) == 64) && strings.Trim(ref, "0") == ""
}

func verifyBootstrap(repo, head, target string) error {
	if !gitdiff.ValidSHA(head) {
		return errors.New("bootstrap requires a committed HEAD")
	}
	shallow, err := gitdiff.Git(repo, "rev-parse", "--is-shallow-repository")
	if err != nil || strings.TrimSpace(string(shallow)) != "false" {
		return errors.New("bootstrap requires complete Git history to establish prior policy")
	}
	if gitdiff.ValidSHA(target) {
		history, err := gitdiff.Git(repo, "log", "--full-history", "--format=%H", target, "--", config.ConfigFileName)
		if err != nil {
			return fmt.Errorf("bootstrap cannot establish the prior policy: %w", err)
		}
		if len(strings.Fields(string(history))) > 0 {
			return errors.New("bootstrap requires previous trees with no Waypost policy")
		}
		return nil
	}
	history, err := gitdiff.Git(repo, "log", "--full-history", "--format=%H", head, "--", config.ConfigFileName)
	if err != nil {
		return fmt.Errorf("bootstrap cannot establish the prior policy: %w", err)
	}
	for _, sha := range strings.Fields(string(history)) {
		if sha != head {
			return errors.New("bootstrap requires previous trees with no Waypost policy")
		}
	}
	return nil
}

func merged(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

func mergeReviews(a, b []changeplan.ReviewReason) []changeplan.ReviewReason {
	for _, incoming := range b {
		i := slices.IndexFunc(a, func(r changeplan.ReviewReason) bool { return r.Code == incoming.Code })
		if i < 0 {
			a = append(a, incoming)
			continue
		}
		items := merged(a[i].Items, incoming.Items)
		n := min(12, len(items))
		a[i].Omitted = max(a[i].Omitted, incoming.Omitted) + len(items) - n
		a[i].Items = items[:n]
	}
	return a
}

func validateWorkdir(repo, rel string) error {
	if rel == "" || rel == "." {
		return nil
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		return err
	}
	defer root.Close()
	for name := filepath.FromSlash(rel); name != "."; name = filepath.Dir(name) {
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("workdir %q must be a repository directory", rel)
		}
	}
	return nil
}

func saveWorkState(view *repoview.View, selection workstate.Selection, fingerprint, diagnostic string, receipt *Receipt) error {
	summary := workstate.Summary{Overall: receipt.Summary.Outcome}
	for _, c := range receipt.Checks {
		if c.Status == StatusFail {
			summary.Failing = append(summary.Failing, c.ID)
		}
		if c.Required && c.Status == StatusSkip {
			summary.Unrun = append(summary.Unrun, c.ID)
		}
	}
	for _, values := range []*[]string{&summary.Failing, &summary.Unrun} {
		*values = merged(*values, nil)
		if len(*values) > 12 {
			summary.Omitted += len(*values) - 12
			*values = (*values)[:12]
		}
	}
	return workstate.Save(view, selection, fingerprint, diagnostic, summary)
}

func safeChanges(plan changeplan.Plan, view *repoview.View, cm *compmap.Map) bool {
	if len(plan.Changes) == 0 || len(plan.Impact.UnmappedPaths) > 0 {
		return false
	}
	tested := make(map[string]bool)
	for name, file := range view.Files {
		if file.Regular() && project.TestFile(name) {
			for _, owner := range cm.OwnersOf(name) {
				tested[owner] = true
			}
		}
	}
	for _, change := range plan.Changes {
		if (change.Status != "M" && change.Status != "A") || !view.Files[change.Path].Regular() {
			return false
		}
		if project.ProductionFile(change.Path) && slices.ContainsFunc(change.NewOwners, func(id string) bool { return !tested[id] }) {
			return false
		}
	}
	return true
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

func checkResult(sc changeplan.Check, lane string) CheckResult {
	return CheckResult{ID: sc.Check.ID, Command: sc.Check.Command, Workdir: sc.Check.Workdir,
		Required: sc.Check.IsRequired(), FromBaseFloor: sc.Source == "base" || sc.BaseRequired, Lane: lane,
		DefinitionSource: sc.Source, SelectionReason: sc.Reason, Reason: sc.Reason}
}

func executeCheckContext(parent context.Context, repoDir string, sc changeplan.Check, lane string, input handoff) CheckResult {
	chk := sc.Check
	req := chk.IsRequired()
	cr := checkResult(sc, lane)
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
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := shellcmd.CommandContext(ctx, chk.Command)
	workDir := repoDir
	if chk.Workdir != "" {
		workDir = filepath.Join(repoDir, chk.Workdir)
	}
	cmd.Dir = workDir
	cmd.Env = input.env()

	buf := newCappedBuffer(maxCapturedOutputBytes)
	cmd.Stdout = buf
	cmd.Stderr = buf

	start := time.Now()
	err := shellcmd.Run(cmd)
	cr.DurationMS = time.Since(start).Milliseconds()
	cr.OutputExcerpt = RedactAndTrim(buf.String(), maxExcerptBytes)

	if ctx.Err() == nil && (err == nil || errors.Is(err, exec.ErrWaitDelay)) {
		if errors.Is(err, exec.ErrWaitDelay) {
			cr.Reason += "; closed leaked child stdio"
		}
		cr.Status = StatusPass
		cr.ExitCode = 0
		return cr
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		cr.ExitCode = 124
		cr.Reason = fmt.Sprintf("timed out after %s", timeout)
	} else if ctx.Err() != nil {
		cr.ExitCode = 130
		cr.Reason = ctx.Err().Error()
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
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return WriteArtifact(path, b)
}

// WriteArtifact publishes an output with an atomic rename, including when the
// previous destination was a symlink.
func WriteArtifact(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".waypost-output-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
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
			b.WriteString("- " + markdownField(f) + "\n")
		}
		b.WriteString("\n")
	}
	if len(r.Policy.TamperingFindings) > 0 {
		b.WriteString("### Policy Floor Findings\n")
		for _, f := range r.Policy.TamperingFindings {
			b.WriteString("- " + markdownField(f) + "\n")
		}
		b.WriteString("\n")
	}
	if len(r.Policy.LockMismatches) > 0 {
		b.WriteString("### Lockfile Mismatches\n")
		for _, m := range r.Policy.LockMismatches {
			b.WriteString("- " + markdownField(m) + "\n")
		}
		b.WriteString("\n")
	}

	if len(r.Checks) > 0 {
		b.WriteString("| Check | Status | Required | Exit | Duration | Reason |\n")
		b.WriteString("| --- | --- | --- | ---: | ---: | --- |\n")
		for _, c := range r.Checks {
			b.WriteString(fmt.Sprintf("| %s | **%s** | %v | %d | %dms | %s |\n",
				markdownField(c.ID), markdownField(c.Status), c.Required, c.ExitCode, c.DurationMS, markdownField(c.Reason)))
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

// markdownField encodes Markdown punctuation without emitting controls or HTML.
func markdownField(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029':
			fmt.Fprintf(&b, "\\u%04x", r)
		case strings.ContainsRune(`\`+"`|<>[](){}!_#*&~:", r):
			fmt.Fprintf(&b, "&#%d;", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
