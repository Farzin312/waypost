// Package history compares resolved Waypost snapshots along Git history.
package history

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repoview"
)

type Options struct {
	Ref, Component, Since, Cursor string
	Limit                         int
	TrustOnly, AllParents         bool
	MaxCommits                    int // optional bound used by interactive orientation
}

type Result struct {
	Version     string   `json:"history_version"`
	RefSHA      string   `json:"ref_sha"`
	Traversal   string   `json:"traversal"`
	Complete    bool     `json:"complete"`
	Truncated   bool     `json:"truncated"`
	NextCursor  string   `json:"next_cursor,omitempty"`
	Events      []Event  `json:"events"`
	Diagnostics []string `json:"diagnostics"`
}

type Event struct {
	SHA         string       `json:"sha"`
	Date        string       `json:"date"`
	Subject     string       `json:"subject"`
	Type        string       `json:"type,omitempty"`
	Scope       string       `json:"scope,omitempty"`
	Parents     []string     `json:"parents"`
	Comparisons []Comparison `json:"comparisons"`
}

type Comparison struct {
	Parent            string                    `json:"parent,omitempty"`
	Complete          bool                      `json:"complete"`
	Ownership         string                    `json:"ownership"`
	Changes           []changeplan.Ownership    `json:"changes,omitempty"`
	OmittedChanges    int                       `json:"omitted_changes,omitempty"`
	ComponentCounts   map[string]int            `json:"component_counts,omitempty"`
	OmittedUnmapped   int                       `json:"omitted_unmapped_paths,omitempty"`
	Impact            compmap.Impact            `json:"impact"`
	Checks            []string                  `json:"checks,omitempty"`
	Review            []changeplan.ReviewReason `json:"review_reasons,omitempty"`
	Policy            []Delta                   `json:"policy_changes,omitempty"`
	OmittedPolicy     int                       `json:"omitted_policy_changes,omitempty"`
	Baseline          []Occurrence              `json:"baseline_occurrences,omitempty"`
	BaselineCount     int                       `json:"baseline_count,omitempty"`
	OmittedBaseline   int                       `json:"omitted_baseline_occurrences,omitempty"`
	CycleEdges        []EdgeDelta               `json:"cycle_edges,omitempty"`
	CycleEdgeCount    int                       `json:"cycle_edge_count,omitempty"`
	OmittedCycleEdges int                       `json:"omitted_cycle_edges,omitempty"`
	Diagnostics       []string                  `json:"diagnostics,omitempty"`
}

type Delta struct {
	Kind   string   `json:"kind"`
	ID     string   `json:"id"`
	Change string   `json:"change"`
	Fields []string `json:"fields,omitempty"`
	Before any      `json:"-"`
	After  any      `json:"-"`
}

type Occurrence struct {
	Entry  archgraph.BaselineEntry `json:"entry"`
	Before int                     `json:"before"`
	After  int                     `json:"after"`
}

type EdgeDelta struct {
	Rule   string              `json:"rule"`
	Edge   archgraph.CycleEdge `json:"edge"`
	Change string              `json:"change"`
}

type cursor struct {
	SHA, Component, Since, After string
	TrustOnly, AllParents        bool
}

var conventional = regexp.MustCompile(`^([a-z][a-z0-9-]*)(?:\(([^()]+)\))?!?:[ \t]`)

func Read(repo string, opts Options) (Result, error) {
	return Scan(repo, opts, nil)
}

// Scan visits matching history incrementally. With emit, events are streamed
// without retaining the full traversal in memory.
func Scan(repo string, opts Options, emit func(Event) error) (Result, error) {
	out := Result{Version: "1", Traversal: "first-parent", Complete: true, Events: []Event{}, Diagnostics: []string{}}
	if opts.AllParents {
		out.Traversal = "all-parents"
	}
	if opts.Limit < 0 {
		return out, errors.New("history limit must be non-negative")
	}
	if opts.Since != "" {
		if _, err := time.Parse(time.DateOnly, opts.Since); err != nil {
			return out, fmt.Errorf("invalid --since date %q (expected YYYY-MM-DD)", opts.Since)
		}
	}
	c := cursor{Component: opts.Component, Since: opts.Since, TrustOnly: opts.TrustOnly, AllParents: opts.AllParents}
	if opts.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		var prior cursor
		if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &prior) != nil || !gitdiff.ValidSHA(prior.SHA) || !gitdiff.ValidSHA(prior.After) {
			return out, errors.New("invalid history cursor")
		}
		c.SHA, c.After = prior.SHA, prior.After
		if c != prior {
			return out, errors.New("history cursor filters changed")
		}
	}
	ref := opts.Ref
	if ref == "" {
		ref = c.SHA
	}
	if ref == "" {
		ref = "HEAD"
	}
	sha, err := gitdiff.ResolveCommit(repo, ref)
	if err != nil {
		return out, fmt.Errorf("resolve history ref: %w", err)
	}
	if c.SHA != "" && c.SHA != sha {
		return out, errors.New("history cursor ref changed")
	}
	c.SHA = sha
	out.RefSHA = sha

	log, err := openLog(repo, sha, opts)
	if err != nil {
		return out, err
	}
	defer log.close()
	prefix, err := repoview.GitPrefix(repo)
	if err != nil {
		return out, err
	}

	store := repoview.NewStore(repo)
	defer store.Close()
	type loaded struct {
		snapshot *project.Snapshot
		error    error
	}
	snapshots := make(map[string]loaded)
	var order []string
	get := func(sha string) (*project.Snapshot, error) {
		if sha == "" {
			return nil, nil
		}
		if item, ok := snapshots[sha]; ok {
			return item.snapshot, item.error
		}
		view, err := store.HistoricalTree(sha, prefix)
		var snapshot *project.Snapshot
		if err == nil {
			snapshot, err = project.Load(view, config.LoadOptions{Offline: true}, compmap.BuildOptions{SkipInventoryOwnership: true})
		}
		if len(order) == 12 {
			delete(snapshots, order[0])
			order = order[1:]
		}
		snapshots[sha] = loaded{snapshot, err}
		order = append(order, sha)
		return snapshot, err
	}
	n, scanned := 0, 0
	last := ""
	seeking := c.After != ""
	for {
		event, firstParentChanges, err := log.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
		if seeking {
			if event.SHA == c.After {
				seeking = false
			}
			continue
		}
		if (opts.MaxCommits > 0 && scanned == opts.MaxCommits) ||
			(opts.Limit > 0 && n == opts.Limit && opts.Component == "" && !opts.TrustOnly) {
			out.Truncated = true
			break
		}
		scanned++

		parents := event.Parents
		missingParents := false
		if len(parents) == 0 {
			raw, readErr := gitdiff.Git(repo, "cat-file", "commit", event.SHA)
			header, _, _ := strings.Cut(string(raw), "\n\n")
			for line := range strings.SplitSeq(header, "\n") {
				if parent, ok := strings.CutPrefix(line, "parent "); ok {
					event.Parents = append(event.Parents, parent)
				}
			}
			missingParents = readErr != nil || len(event.Parents) > 0
			parents = []string{""}
		}
		if !opts.AllParents {
			parents = parents[:1]
		}
		child, childErr := get(event.SHA)
		matches := false
		for _, parent := range parents {
			old, oldErr := get(parent)
			comparison := Comparison{Parent: parent, Complete: true, Ownership: "resolved"}
			if childErr != nil {
				comparison.incomplete("child policy unavailable: " + childErr.Error())
			}
			if oldErr != nil {
				comparison.incomplete("parent policy unavailable: " + oldErr.Error())
			}
			changes, diffErr := firstParentChanges, error(nil)
			if opts.AllParents {
				changes, diffErr = gitdiff.Diff(repo, parent, event.SHA)
			}
			if missingParents {
				comparison.incomplete("shallow or missing parent; change attribution unavailable")
				changes = nil
			}
			if diffErr != nil {
				comparison.incomplete("Git diff unavailable: " + diffErr.Error())
			}
			if child == nil || child.Policy == nil || (old == nil && parent != "") || (old != nil && old.Policy == nil) {
				comparison.Ownership = "unknown"
				if child != nil && child.Policy == nil || old != nil && old.Policy == nil {
					comparison.Diagnostics = append(comparison.Diagnostics, "pre-adoption history has no resolved Waypost policy")
				}
			}
			plan := changeplan.Create(side(old), side(child), changes, false, comparison.Complete, false)
			comparison.Changes, comparison.Impact, comparison.Review = plan.Changes, plan.Impact, plan.Review
			for _, check := range plan.Checks {
				if check.Selected {
					comparison.Checks = append(comparison.Checks, check.Check.ID)
				}
			}
			if childErr == nil && oldErr == nil && !missingParents {
				comparePolicy(&comparison, old, child)
			}
			if !comparison.Complete {
				out.Complete = false
			}
			for _, diagnostic := range comparison.Diagnostics {
				if len(out.Diagnostics) < 20 {
					out.Diagnostics = append(out.Diagnostics, event.SHA[:12]+": "+diagnostic)
				}
			}
			if opts.Component != "" {
				comparison.project(opts.Component, old, child)
			}
			componentMatch := opts.Component == "" || len(comparison.Changes)+len(comparison.Policy)+len(comparison.Baseline)+len(comparison.CycleEdges) > 0
			trustMatch := !opts.TrustOnly || len(comparison.Review) > 0 || len(comparison.Baseline) > 0 || len(comparison.CycleEdges) > 0
			if componentMatch && trustMatch || !comparison.Complete {
				matches = true
				comparison.bound()
				event.Comparisons = append(event.Comparisons, comparison)
			}
		}
		if !matches {
			continue
		}
		if opts.Limit > 0 && n == opts.Limit {
			out.Truncated = true
			break
		}
		if emit != nil {
			if err := emit(event); err != nil {
				return out, err
			}
		} else {
			out.Events = append(out.Events, event)
		}
		n++
		last = event.SHA
	}
	if seeking {
		return out, errors.New("history cursor is not reachable with these filters")
	}
	if out.Truncated {
		if last != "" {
			c.After = last
			raw, _ := json.Marshal(c)
			out.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
		}
	} else {
		if err := log.finish(); err != nil {
			out.Complete = false
			out.Diagnostics = append(out.Diagnostics, "Git traversal incomplete: "+err.Error())
		}
	}
	return out, nil
}

type logReader struct {
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	scanner     *bufio.Scanner
	pending     string
	withChanges bool
	finished    bool
}

// Git emits first-parent changes with the log, using NUL-delimited names.
func openLog(repo, sha string, opts Options) (*logReader, error) {
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{"--no-replace-objects", "--no-lazy-fetch", "-C", repo, "log", "--no-show-signature", "--no-notes", "--encoding=UTF-8", "--format=%x1e%H%x00%P%x00%cI%x00%s", "-z"}
	if !opts.AllParents {
		args = append(args, "--first-parent", "--diff-merges=first-parent", "--root", "--relative", "--name-status", "-r", "-M", "--no-ext-diff", "--no-textconv")
	}
	if opts.Since != "" {
		args = append(args, "--since-as-filter="+opts.Since+"T00:00:00Z")
	}
	if opts.MaxCommits > 0 {
		args = append(args, fmt.Sprintf("--max-count=%d", opts.MaxCommits+1))
	}
	cmd := exec.CommandContext(ctx, "git", append(args, sha, "--")...)
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		cancel()
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	scanner.Split(splitNUL)
	return &logReader{cmd: cmd, cancel: cancel, scanner: scanner, withChanges: !opts.AllParents}, nil
}

func (r *logReader) close() {
	r.cancel()
	if !r.finished {
		_ = r.finish()
	}
}
func (r *logReader) finish() error {
	r.finished = true
	return r.cmd.Wait()
}

func (r *logReader) scan() (string, error) {
	if r.scanner.Scan() {
		return r.scanner.Text(), nil
	}
	if err := r.scanner.Err(); err != nil {
		return "", err
	}
	return "", io.EOF
}

func (r *logReader) next() (Event, []gitdiff.Change, error) {
	var event Event
	token := r.pending
	r.pending = ""
	if token == "" {
		var err error
		token, err = r.scan()
		if err != nil {
			return event, nil, err
		}
	}
	sha, ok := strings.CutPrefix(token, "\x1e")
	if !ok || !gitdiff.ValidSHA(sha) {
		return event, nil, errors.New("invalid commit in Git log")
	}
	fields := make([]string, 3)
	for i := range fields {
		value, err := r.scan()
		if err != nil {
			return event, nil, fmt.Errorf("incomplete Git log record: %w", err)
		}
		fields[i] = value
	}
	event = Event{SHA: sha, Parents: strings.Fields(fields[0]), Date: fields[1], Subject: EscapeControls(fields[2])}
	if event.Parents == nil {
		event.Parents = []string{}
	}
	if match := conventional.FindStringSubmatch(event.Subject); match != nil {
		event.Type, event.Scope = match[1], match[2]
	}
	if !r.withChanges {
		return event, nil, nil
	}
	var changes []gitdiff.Change
	for {
		code, err := r.scan()
		if errors.Is(err, io.EOF) {
			return event, changes, nil
		}
		if err != nil {
			return event, nil, err
		}
		code = strings.TrimPrefix(code, "\n")
		if code == "" {
			continue
		}
		if strings.HasPrefix(code, "\x1e") {
			r.pending = code
			return event, changes, nil
		}
		name, err := r.scan()
		if err != nil {
			return event, nil, fmt.Errorf("incomplete Git path change: %w", err)
		}
		ch := gitdiff.Change{Status: code[:1], Path: name}
		if ch.Status == "R" || ch.Status == "C" {
			ch.OldPath = name
			ch.Path, err = r.scan()
			if err != nil {
				return event, nil, fmt.Errorf("incomplete Git rename: %w", err)
			}
		}
		changes = append(changes, ch)
	}
}

func splitNUL(data []byte, eof bool) (int, []byte, error) {
	for i, b := range data {
		if b == 0 {
			return i + 1, data[:i], nil
		}
	}
	if eof && len(data) > 0 {
		return 0, nil, errors.New("unterminated Git log field")
	}
	return 0, nil, nil
}

func (c *Comparison) incomplete(message string) {
	c.Complete = false
	c.Diagnostics = append(c.Diagnostics, message)
}

func side(p *project.Snapshot) changeplan.Side {
	if p == nil || p.Policy == nil {
		return changeplan.Side{}
	}
	return changeplan.Side{Map: p.Map, Config: p.Config()}
}

func EscapeControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func comparePolicy(c *Comparison, old, next *project.Snapshot) {
	a, b := old.Config(), next.Config()
	if a == nil {
		a = &config.Config{}
	}
	if b == nil {
		b = &config.Config{}
	}
	c.Policy = append(c.Policy, deltas("rule", a.Rules, b.Rules, func(r config.Rule) string { return r.ID })...)
	c.Policy = append(c.Policy, deltas("component", a.Components, b.Components, func(c config.ComponentConfig) string { return c.ID })...)
	c.Policy = append(c.Policy, deltas("check", a.Checks, b.Checks, func(r config.Check) string { return r.ID })...)
	c.Policy = append(c.Policy, deltas("pin", a.Pins, b.Pins, func(r config.CrossRepoPin) string { return r.ID })...)
	var left, right []config.BoundaryRule
	var leftPolicy, rightPolicy *config.BoundariesConfig
	if a.Boundaries != nil {
		copy := *a.Boundaries
		left = copy.Rules
		copy.Rules = nil
		leftPolicy = &copy
	}
	if b.Boundaries != nil {
		copy := *b.Boundaries
		right = copy.Rules
		copy.Rules = nil
		rightPolicy = &copy
	}
	if !reflect.DeepEqual(leftPolicy, rightPolicy) {
		d := Delta{Kind: "boundary_policy", ID: "boundaries"}
		if leftPolicy != nil {
			d.Before = leftPolicy
		}
		if rightPolicy != nil {
			d.After = rightPolicy
		}
		c.Policy = append(c.Policy, d)
	}
	c.Policy = append(c.Policy, deltas("boundary_rule", left, right, func(r config.BoundaryRule) string { return r.ID })...)
	var before, after *archgraph.BaselineFile
	var err error
	if old != nil {
		before, err = old.RecordedBaseline()
		if err != nil {
			c.incomplete("parent baseline unavailable: " + err.Error())
		}
	}
	if next != nil && !sameBaseline(old, next) {
		after, err = next.RecordedBaseline()
		if err != nil {
			c.incomplete("child baseline unavailable: " + err.Error())
		}
	}
	if c.Complete && !sameBaseline(old, next) {
		compareBaselines(c, before, after)
	}
}

func sameBaseline(a, b *project.Snapshot) bool {
	if a == nil || b == nil || a.Boundaries() == nil || b.Boundaries() == nil {
		return false
	}
	rel := a.Boundaries().BaselinePath()
	if rel != b.Boundaries().BaselinePath() || a.Boundaries().EffectiveMode() != b.Boundaries().EffectiveMode() {
		return false
	}
	file := a.View.Files[rel]
	return file.Blob != "" && file.Blob == b.View.Files[rel].Blob && file.Mode == b.View.Files[rel].Mode
}

func (c *Comparison) project(id string, old, next *project.Snapshot) {
	c.Changes = slices.DeleteFunc(c.Changes, func(ch changeplan.Ownership) bool {
		return !slices.Contains(ch.OldOwners, id) && !slices.Contains(ch.NewOwners, id)
	})
	var scoped []gitdiff.Change
	for i := range c.Changes {
		ch := &c.Changes[i]
		ch.OldOwners = slices.DeleteFunc(slices.Clone(ch.OldOwners), func(owner string) bool { return owner != id })
		ch.NewOwners = slices.DeleteFunc(slices.Clone(ch.NewOwners), func(owner string) bool { return owner != id })
		scoped = append(scoped, ch.Change)
	}
	c.Policy = slices.DeleteFunc(c.Policy, func(d Delta) bool { return !policyTouchesComponent([]Delta{d}, old, next, id) })
	c.Baseline = slices.DeleteFunc(c.Baseline, func(d Occurrence) bool {
		return d.Entry.From != id && d.Entry.To != id && !slices.Contains(d.Entry.CycleMembers, id)
	})
	c.CycleEdges = slices.DeleteFunc(c.CycleEdges, func(d EdgeDelta) bool { return d.Edge.From != id && d.Edge.To != id })
	projected := changeplan.Create(side(old), side(next), scoped, false, c.Complete, false)
	c.Impact = compmap.Impact{}
	if len(c.Changes) > 0 {
		c.Impact.DirectComponents = []string{id}
	}
	c.Checks = nil
	c.Review = slices.DeleteFunc(projected.Review, func(r changeplan.ReviewReason) bool { return r.Code != "trust_path" })
	if len(projected.Impact.TriggeredPins) > 0 {
		var pinIDs []string
		for _, d := range c.Policy {
			if d.Kind == "pin" {
				pinIDs = append(pinIDs, d.ID)
			}
		}
		for _, snapshot := range []*project.Snapshot{old, next} {
			if snapshot.Config() == nil {
				continue
			}
			for _, pin := range snapshot.Config().Pins {
				if pin.ConsumerComponent == id || pin.ConsumerComponent == "" && pin.Consumer == id {
					pinIDs = append(pinIDs, pin.ID)
				}
			}
		}
		for _, pin := range projected.Impact.TriggeredPins {
			if slices.Contains(pinIDs, pin) {
				c.Impact.TriggeredPins = append(c.Impact.TriggeredPins, pin)
			}
		}
		if len(c.Impact.TriggeredPins) > 0 {
			n := min(12, len(c.Impact.TriggeredPins))
			c.Review = append(c.Review, changeplan.ReviewReason{Code: "contract_pin", Items: c.Impact.TriggeredPins[:n], Omitted: len(c.Impact.TriggeredPins) - n})
		}
	}
	if len(c.Policy) > 0 {
		ids := make([]string, 0, len(c.Policy))
		for _, d := range c.Policy {
			ids = append(ids, d.ID)
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		n := min(12, len(ids))
		c.Review = append(c.Review, changeplan.ReviewReason{Code: "policy_floor", Items: ids[:n], Omitted: len(ids) - n})
	}
	for _, check := range changeplan.ComponentChecks(side(next), id, scoped) {
		if check.Selected {
			c.Checks = append(c.Checks, check.Check.ID)
		}
	}
}

func (c *Comparison) bound() {
	for _, ch := range c.Changes {
		owners := append(slices.Clone(ch.OldOwners), ch.NewOwners...)
		slices.Sort(owners)
		for _, owner := range slices.Compact(owners) {
			if c.ComponentCounts == nil {
				c.ComponentCounts = make(map[string]int)
			}
			c.ComponentCounts[owner]++
		}
	}
	c.Changes, c.OmittedChanges = sample(c.Changes, 50)
	c.Impact.UnmappedPaths, c.OmittedUnmapped = sample(c.Impact.UnmappedPaths, 20)
	c.Policy, c.OmittedPolicy = sample(c.Policy, 20)
	for i := range c.Policy {
		c.Policy[i].summarize()
	}
	c.BaselineCount, c.CycleEdgeCount = len(c.Baseline), len(c.CycleEdges)
	c.Baseline, c.OmittedBaseline = sample(c.Baseline, 12)
	for i := range c.Baseline {
		e := &c.Baseline[i].Entry
		e.CyclePath, e.CycleMembers, e.CycleEdges = nil, nil, nil
	}
	c.CycleEdges, c.OmittedCycleEdges = sample(c.CycleEdges, 20)
}

func sample[T any](values []T, limit int) ([]T, int) {
	n := min(len(values), limit)
	return slices.Clone(values[:n]), len(values) - n
}

func (d *Delta) summarize() {
	switch {
	case d.Before == nil:
		d.Change = "added"
	case d.After == nil:
		d.Change = "removed"
	default:
		d.Change = "modified"
		fields := func(value any) map[string]json.RawMessage {
			raw, _ := json.Marshal(value)
			var out map[string]json.RawMessage
			_ = json.Unmarshal(raw, &out)
			return out
		}
		a, b := fields(d.Before), fields(d.After)
		for k := range maps.Keys(a) {
			if string(a[k]) != string(b[k]) {
				d.Fields = append(d.Fields, k)
			}
		}
		for k := range maps.Keys(b) {
			if _, ok := a[k]; !ok {
				d.Fields = append(d.Fields, k)
			}
		}
		slices.Sort(d.Fields)
	}
	d.Before, d.After = nil, nil
}
func deltas[T any](kind string, a, b []T, id func(T) string) []Delta {
	before, after := make(map[string]T), make(map[string]T)
	for _, x := range a {
		before[id(x)] = x
	}
	for _, x := range b {
		after[id(x)] = x
	}
	var out []Delta
	for _, key := range changeplan.ChangedIDs(a, b, id) {
		d := Delta{Kind: kind, ID: key}
		if v, ok := before[key]; ok {
			d.Before = v
		}
		if v, ok := after[key]; ok {
			d.After = v
		}
		out = append(out, d)
	}
	return out
}

func compareBaselines(c *Comparison, old, next *archgraph.BaselineFile) {
	if old == nil {
		old = &archgraph.BaselineFile{}
	}
	if next == nil {
		next = &archgraph.BaselineFile{}
	}
	counts := make(map[string]Occurrence)
	type edge struct {
		rule string
		edge archgraph.CycleEdge
	}
	before, after := make(map[edge]bool), make(map[edge]bool)
	for _, e := range old.Entries {
		counts[e.Fingerprint] = Occurrence{Entry: e, Before: e.Occurrences()}
		for _, x := range e.CycleEdges {
			before[edge{e.RuleID, x}] = true
		}
	}
	for _, e := range next.Entries {
		d := counts[e.Fingerprint]
		d.Entry, d.After = e, e.Occurrences()
		counts[e.Fingerprint] = d
		for _, x := range e.CycleEdges {
			after[edge{e.RuleID, x}] = true
		}
	}
	for _, d := range counts {
		if d.Before != d.After {
			c.Baseline = append(c.Baseline, d)
		}
	}
	slices.SortFunc(c.Baseline, func(a, b Occurrence) int { return strings.Compare(a.Entry.Fingerprint, b.Entry.Fingerprint) })
	for x := range before {
		if !after[x] {
			c.CycleEdges = append(c.CycleEdges, EdgeDelta{x.rule, x.edge, "removed"})
		}
	}
	for x := range after {
		if !before[x] {
			c.CycleEdges = append(c.CycleEdges, EdgeDelta{x.rule, x.edge, "added"})
		}
	}
	slices.SortFunc(c.CycleEdges, func(a, b EdgeDelta) int {
		return slices.Compare([]string{a.Rule, a.Edge.From, a.Edge.To}, []string{b.Rule, b.Edge.From, b.Edge.To})
	})
}

// Recent returns at most limit distinct subjects across directly touched components.
func Recent(repo, ref string, cm *compmap.Map, components []string, limit int) ([]RecentCommit, error) {
	if len(components) == 0 || limit <= 0 || !gitdiff.ValidSHA(ref) {
		return nil, nil
	}
	log, err := openLog(repo, ref, Options{MaxCommits: 39})
	if err != nil {
		return nil, err
	}
	defer log.close()
	var out []RecentCommit
	seen := make(map[string]bool)
	for len(out) < limit {
		event, changes, err := log.next()
		if errors.Is(err, io.EOF) {
			return out, log.finish()
		}
		if err != nil {
			return out, err
		}
		if seen[event.Subject] {
			continue
		}
		var owner string
		for _, ch := range changes {
			for _, rel := range []string{ch.Path, ch.OldPath} {
				if rel == "" {
					continue
				}
				for _, id := range cm.OwnersOf(rel) {
					if slices.Contains(components, id) && (owner == "" || id < owner) {
						owner = id
					}
				}
			}
		}
		if owner == "" {
			continue
		}
		seen[event.Subject] = true
		subject := event.Subject
		if r := []rune(subject); len(r) > 120 {
			subject = string(r[:117]) + "..."
		}
		out = append(out, RecentCommit{event.SHA, owner, subject})
	}
	return out, nil
}

type RecentCommit struct {
	SHA       string `json:"sha"`
	Component string `json:"component"`
	Subject   string `json:"subject"`
}

func policyTouchesComponent(deltas []Delta, old, next *project.Snapshot, id string) bool {
	hasComponent := func(p *project.Snapshot) bool {
		return p != nil && slices.ContainsFunc(p.Map.Components, func(c compmap.Component) bool { return c.ID == id })
	}
	for _, delta := range deltas {
		for _, direction := range []struct {
			value    any
			snapshot *project.Snapshot
		}{{delta.Before, old}, {delta.After, next}} {
			switch value := direction.value.(type) {
			case config.ComponentConfig:
				if value.ID == id {
					return true
				}
			case config.Rule, *config.BoundariesConfig:
				if hasComponent(direction.snapshot) {
					return true
				}
			case config.CrossRepoPin:
				if value.ConsumerComponent == id || value.ConsumerComponent == "" && value.Consumer == id {
					return true
				}
			case config.Check:
				if slices.Contains(value.Components, id) {
					return true
				}
				p := direction.snapshot
				if p == nil {
					continue
				}
				for _, c := range p.Map.Components {
					if c.ID == id && (slices.Contains(c.Checks, value.ID) || len(value.Paths) == 0 && len(value.Components) == 0) {
						return true
					}
				}
				globs := compmap.CompileGlobs(value.Paths)
				for path := range p.View.Files {
					if compmap.MatchCompiled(globs, path) && slices.Contains(p.Map.OwnersOf(path), id) {
						return true
					}
				}
			case config.BoundaryRule:
				if value.From != "" && archgraph.MatchesComponentPattern(value.From, id) || value.Target != "" && archgraph.MatchesComponentPattern(value.Target, id) {
					return true
				}
			}
		}
	}
	return false
}
