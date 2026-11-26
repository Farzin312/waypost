package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/history"
	"github.com/Farzin312/waypost/internal/pins"
	"github.com/Farzin312/waypost/internal/project"
	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/spec"
	"github.com/Farzin312/waypost/internal/verify"
)

func readSnapshot(dir, ref string) (*project.Snapshot, func(), error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, func() {}, err
	}
	store := repoview.NewStore(abs)
	cleanup := func() { _ = store.Close() }
	var view *repoview.View
	if ref == "" {
		view, err = repoview.Working(abs)
	} else {
		view, err = store.Commit(ref)
	}
	if err != nil {
		return nil, cleanup, err
	}
	p, err := project.Load(view, config.LoadOptions{Mode: "ci", Offline: true}, compmap.BuildOptions{})
	return p, cleanup, err
}

func readFormat(value string) error {
	if value != "text" && value != "markdown" && value != "json" {
		return fmt.Errorf("unknown format %q", value)
	}
	return nil
}

func runSpec(args []string, w io.Writer) error {
	f := flag.NewFlagSet("spec", flag.ContinueOnError)
	dir := f.String("dir", ".", "repository root directory")
	ref := f.String("ref", "", "Git commit snapshot")
	component := f.String("component", "", "component ID")
	include := f.Bool("history", false, "include recent matching history")
	since := f.String("since", "", "include history since YYYY-MM-DD")
	limit := f.Int("limit", 5, "positive history limit")
	format := f.String("format", "text", "text, markdown, or json")
	receiptPath := f.String("receipt", "", "optional verification receipt for the selected commit")
	if err := parseCommandFlags(f, args, w); err != nil {
		return err
	}
	if err := readFormat(*format); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected spec argument %q", f.Arg(0))
	}
	var historyFlag bool
	f.Visit(func(flag *flag.Flag) { historyFlag = historyFlag || flag.Name == "since" || flag.Name == "limit" })
	if !*include && historyFlag {
		return fmt.Errorf("--since and --limit require --history")
	}
	if *include && *limit <= 0 {
		return fmt.Errorf("spec --history requires a positive --limit")
	}

	p, cleanup, err := readSnapshot(*dir, *ref)
	defer cleanup()
	if err != nil {
		return err
	}
	report, err := spec.Build(p, *component)
	if err != nil {
		return err
	}
	if *include {
		h, err := history.Read(p.View.Repo, history.Options{Ref: p.View.SHA, Component: *component, Since: *since, Limit: *limit})
		if err != nil {
			return err
		}
		report.History = &h
	}
	if *receiptPath != "" {
		abs, err := filepath.Abs(*receiptPath)
		if err != nil {
			return err
		}
		raw, err := repopath.Read(filepath.Dir(abs), filepath.Base(abs), repopath.MaxPolicyBytes)
		if err != nil {
			return err
		}
		var rec verify.Receipt
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if err := report.AttachReceipt(rec); err != nil {
			return err
		}
	}
	if *format == "json" {
		return writeJSON(w, report)
	}
	renderSpec(w, report, *format == "markdown")
	return nil
}

func runHistory(args []string, w io.Writer) error {
	f := flag.NewFlagSet("history", flag.ContinueOnError)
	dir := f.String("dir", ".", "repository root directory")
	var options history.Options
	f.StringVar(&options.Ref, "ref", "", "Git commit to traverse")
	f.StringVar(&options.Component, "component", "", "directly touched component ID")
	f.StringVar(&options.Since, "since", "", "earliest date (YYYY-MM-DD)")
	f.IntVar(&options.Limit, "limit", 20, "matching events (0 for all)")
	f.BoolVar(&options.TrustOnly, "trust-only", false, "trust or policy changes only")
	f.BoolVar(&options.AllParents, "all-parents", false, "traverse all parents")
	f.StringVar(&options.Cursor, "cursor", "", "pagination token")
	format := f.String("format", "text", "text, markdown, or json")
	if err := parseCommandFlags(f, args, w); err != nil {
		return err
	}
	if err := readFormat(*format); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected history argument %q", f.Arg(0))
	}
	if options.Limit == 0 && *format == "json" {
		started := false
		h, err := history.Scan(*dir, options, func(e history.Event) error {
			raw, err := json.Marshal(e)
			if err != nil {
				return err
			}
			prefix := ","
			if !started {
				prefix = "{\"events\":["
				started = true
			}
			_, err = fmt.Fprintf(w, "%s%s", prefix, raw)
			return err
		})
		if err != nil {
			return err
		}
		if !started {
			return json.NewEncoder(w).Encode(h)
		}
		type metadata struct {
			Version     string   `json:"history_version"`
			SHA         string   `json:"ref_sha"`
			Traversal   string   `json:"traversal"`
			Complete    bool     `json:"complete"`
			Truncated   bool     `json:"truncated"`
			Cursor      string   `json:"next_cursor,omitempty"`
			Diagnostics []string `json:"diagnostics"`
		}
		raw, err := json.Marshal(metadata{h.Version, h.RefSHA, h.Traversal, h.Complete, h.Truncated, h.NextCursor, h.Diagnostics})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "],%s\n", raw[1:])
		return err
	}
	if options.Limit == 0 {
		heading(w, "Waypost history", *format == "markdown")
		h, err := history.Scan(*dir, options, func(e history.Event) error { renderEvent(w, e, *format == "markdown"); return nil })
		if err != nil {
			return err
		}
		for _, msg := range h.Diagnostics {
			fmt.Fprintln(w, safeText(msg, *format == "markdown"))
		}
		return nil
	}
	h, err := history.Read(*dir, options)
	if err != nil {
		return err
	}
	if *format == "json" {
		return json.NewEncoder(w).Encode(h)
	}
	renderHistory(w, h, *format == "markdown")
	return nil
}

func runPins(args []string, w io.Writer) error {
	f := flag.NewFlagSet("pins", flag.ContinueOnError)
	dir := f.String("dir", ".", "repository root directory")
	format := f.String("format", "text", "text, markdown, or json")
	var repos []string
	f.Func("repo", "DIR@REF snapshot (repeatable)", func(s string) error { repos = append(repos, s); return nil })
	if err := parseCommandFlags(f, args, w); err != nil {
		return err
	}
	if err := readFormat(*format); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected pins argument %q", f.Arg(0))
	}
	var snapshots []pins.Input
	add := func(p *project.Snapshot) {
		input := pins.Input{View: p.View, Configured: p.Config() != nil}
		if p.Config() != nil {
			input.Pins = p.Config().Pins
		}
		snapshots = append(snapshots, input)
	}
	if len(repos) == 0 {
		p, cleanup, err := readSnapshot(*dir, "")
		defer cleanup()
		if err != nil {
			return err
		}
		add(p)
	}
	for _, s := range repos {
		i := strings.LastIndexByte(s, '@')
		if i < 1 || i == len(s)-1 {
			return fmt.Errorf("expected --repo DIR@REF, got %q", s)
		}
		p, cleanup, err := readSnapshot(s[:i], s[i+1:])
		defer cleanup()
		if err != nil {
			return err
		}
		add(p)
	}
	report := pins.Reconcile(snapshots)
	if *format == "json" {
		return writeJSON(w, report)
	}
	markdown := *format == "markdown"
	heading(w, "Waypost pins", markdown)
	for _, p := range report.Pins {
		fmt.Fprintf(w, "- %s %s → %s, %s [%s] declared %s, observed %s", safeText(p.ID, markdown),
			safeText(p.Producer, markdown), safeText(p.Consumer, markdown), safeText(p.Artifact, markdown), p.Status,
			safeText(nonEmpty(p.Declared, "unknown"), markdown), safeText(nonEmpty(p.Observed, "unknown"), markdown))
		for _, value := range []string{p.ReleaseLine, p.ArtifactIdentity, p.Integrity, p.CompatibilityCheck, p.ProducerVersion, p.Detail} {
			if value != "" {
				fmt.Fprintf(w, "; %s", safeText(value, markdown))
			}
		}
		fmt.Fprintln(w)
	}
	for _, d := range report.Diagnostics {
		fmt.Fprintln(w, safeText(d, markdown))
	}
	return nil
}

func safeText(value string, markdown bool) string {
	value = history.EscapeControls(value)
	if markdown {
		value = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "`", "\\`", "|", "\\|", "~", "\\~", "#", "\\#", "!", "\\!").Replace(value)
	}
	return value
}

func heading(w io.Writer, title string, markdown bool) {
	if markdown {
		fmt.Fprint(w, "## ")
	}
	fmt.Fprintln(w, title)
	fmt.Fprintln(w)
}

func renderSpec(w io.Writer, r spec.Report, markdown bool) {
	heading(w, "Waypost spec", markdown)
	fmt.Fprintf(w, "%s %s · policy %s\n\n", r.Snapshot.Kind, shortHash(r.Snapshot.SHA), shortHash(r.PolicyDigest))
	for _, c := range r.Components {
		fmt.Fprintf(w, "- %s (%s) %s\n", safeText(c.ID, markdown), safeText(c.Root, markdown), c.Source)
		if len(c.Paths) > 0 {
			fmt.Fprintf(w, "  - paths %s\n", safeText(strings.Join(c.Paths, ", "), markdown))
		}
		for _, section := range []struct {
			label string
			facts []spec.Fact
		}{
			{"entrypoints", c.Entrypoints}, {"public entrypoints", c.PublicEntrypoints},
			{"depends on", c.DependsOn}, {"depended by", c.DependedBy}, {"tests", c.Tests},
		} {
			if len(section.facts) == 0 {
				continue
			}
			var values []string
			for _, fact := range section.facts {
				values = append(values, safeText(fact.Value, markdown)+" ("+fact.Source+")")
			}
			fmt.Fprintf(w, "  - %s %s\n", section.label, strings.Join(values, ", "))
		}
		if len(c.Checks) > 0 {
			fmt.Fprintf(w, "  - checks %s\n", safeText(strings.Join(c.Checks, ", "), markdown))
		}
	}
	if len(r.Rules) > 0 {
		fmt.Fprintln(w, "\nRules")
	}
	for _, rule := range r.Rules {
		fmt.Fprintf(w, "- %s (%s, %s) %s\n", safeText(rule.ID, markdown), rule.Kind, safeText(rule.Source, markdown), safeText(rule.Summary, markdown))
		if rule.Overrides != "" {
			fmt.Fprintf(w, "  - overrides %s\n", safeText(rule.Overrides, markdown))
		}
		if rule.Reason != "" {
			fmt.Fprintf(w, "  - %s\n", safeText(rule.Reason, markdown))
		}
		if rule.VerifiedBy != nil {
			if len(rule.VerifiedBy.Checks) > 0 {
				fmt.Fprintf(w, "  - verified by checks %s\n", safeText(strings.Join(rule.VerifiedBy.Checks, ", "), markdown))
			}
			if len(rule.VerifiedBy.Tests) > 0 {
				fmt.Fprintf(w, "  - linked tests %s\n", safeText(strings.Join(rule.VerifiedBy.Tests, ", "), markdown))
			}
		}
	}
	if len(r.Checks) > 0 {
		fmt.Fprintln(w, "\nChecks")
	}
	for _, c := range r.Checks {
		fmt.Fprintf(w, "- %s · %s\n", safeText(c.ID, markdown), safeText(c.Command, markdown))
	}
	if len(r.Pins) > 0 {
		fmt.Fprintln(w, "\nPins")
	}
	for _, p := range r.Pins {
		fmt.Fprintf(w, "- %s %s [%s]\n", safeText(p.ID, markdown), safeText(p.Version, markdown), p.Status)
	}
	fmt.Fprintf(w, "\nBoundaries %s · %d violations · %d baseline entries / %d occurrences · scan complete %t\n",
		r.Boundaries.Mode, r.Boundaries.Violations, r.Boundaries.BaselineEntries, r.Boundaries.BaselineOccurrences, r.Boundaries.ScanComplete)
	if r.Boundaries.Policy != nil {
		for _, rule := range r.Boundaries.Policy.Rules {
			fmt.Fprintf(w, "- %s %s\n", safeText(rule.ID, markdown), safeText(rule.Reason, markdown))
		}
	}
	for _, entry := range r.Boundaries.Baseline {
		fmt.Fprintf(w, "- %s %s (%d occurrences)\n", safeText(entry.RuleID, markdown), shortHash(entry.Fingerprint), entry.Occurrences())
	}
	if r.Receipt != nil {
		fmt.Fprintf(w, "\nVerification %s at %s\n", safeText(r.Receipt.Outcome, markdown), shortHash(r.Receipt.HeadSHA))
	}
	for _, gap := range r.CoverageGaps {
		fmt.Fprintf(w, "\nCoverage gap %s\n", safeText(gap, markdown))
	}
	for _, d := range r.Diagnostics {
		fmt.Fprintf(w, "\n%s\n", safeText(d, markdown))
	}
	if r.History != nil {
		fmt.Fprintln(w)
		renderHistory(w, *r.History, markdown)
	}
}

func renderHistory(w io.Writer, r history.Result, markdown bool) {
	heading(w, "Waypost history "+shortHash(r.RefSHA), markdown)
	for _, event := range r.Events {
		renderEvent(w, event, markdown)
	}
	for _, d := range r.Diagnostics {
		fmt.Fprintf(w, "  %s\n", safeText(d, markdown))
	}
	if r.NextCursor != "" {
		fmt.Fprintf(w, "\nNext cursor %s\n", r.NextCursor)
	}
}

func renderEvent(w io.Writer, e history.Event, markdown bool) {
	fmt.Fprintf(w, "- %s %s %s\n", shortHash(e.SHA), safeText(e.Date, markdown), safeText(e.Subject, markdown))
	for _, c := range e.Comparisons {
		if len(e.Comparisons) > 1 {
			fmt.Fprintf(w, "  - parent %s\n", shortHash(c.Parent))
		}
		if len(c.Impact.DirectComponents) > 0 {
			fmt.Fprintf(w, "  - touched %s\n", safeText(strings.Join(c.Impact.DirectComponents, ", "), markdown))
		}
		if len(c.Policy) > 0 {
			var items []string
			for _, d := range c.Policy {
				items = append(items, d.Kind+" "+d.ID)
			}
			slices.Sort(items)
			fmt.Fprintf(w, "  - policy %s\n", safeText(strings.Join(items, ", "), markdown))
		}
		if len(c.Baseline) > 0 || len(c.CycleEdges) > 0 {
			fmt.Fprintf(w, "  - recorded baseline %d occurrence changes and %d cycle edge changes\n", len(c.Baseline), len(c.CycleEdges))
		}
	}
}
