package archgraph

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

func TestBaselineCanonicalFingerprintsAndCounts(t *testing.T) {
	a := Violation{Kind: "denied-dependency", RuleID: "deny", From: "web", To: "backend", File: "web/app.ts", TargetFile: "backend/lib.ts", Line: 1}
	moved := a
	moved.Line, moved.Message, moved.Severity = 99, "changed diagnostic", "warn"
	b := a
	b.File = "web/other.ts"
	if ViolationFingerprint(a) != ViolationFingerprint(moved) || ViolationFingerprint(a) == ViolationFingerprint(b) {
		t.Fatal("fingerprint lost site identity or depends on line number")
	}

	cycle := Violation{Kind: "cycle", RuleID: "no-cycles", From: "b", CyclePath: []string{"b", "c", "a", "b"}}
	rotated := cycle
	rotated.From, rotated.CyclePath = "a", []string{"a", "b", "c", "a"}
	opposite := rotated
	opposite.CyclePath = []string{"a", "c", "b", "a"}
	if ViolationFingerprint(cycle) != ViolationFingerprint(rotated) || ViolationFingerprint(cycle) == ViolationFingerprint(opposite) {
		t.Fatal("fingerprint failed to normalize rotation or lost direction")
	}

	dir := t.TempDir()
	rel := "config/architecture.json"
	if err := SaveBaseline(dir, rel, []Violation{b, moved, a}); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveBaseline(dir, rel, []Violation{a, b, moved}); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("baseline was not canonical: %v,\n%s\n%s", err, first, second)
	}
	baseline, err := LoadBaseline(dir, rel)
	if err != nil || len(baseline.Entries) != 2 || baseline.Entries[0].Source != a.File ||
		baseline.Entries[0].Count != 2 || baseline.Entries[1].Count != 0 {
		t.Fatalf("load baseline: %+v, %v", baseline, err)
	}
	fresh := a
	fresh.TargetFile = "backend/secret.ts"
	report := Report{Violations: []Violation{moved, fresh, {Kind: "scan-error"}}}
	EvaluateBoundariesWithBaseline(&report, baseline)
	if report.GrandfatheredCount != 1 || report.ResolvedBaselineCount != 2 || len(report.Violations) != 2 ||
		report.Violations[0].TargetFile != fresh.TargetFile || report.Violations[1].Kind != "scan-error" {
		t.Fatalf("incorrect partition: %+v", report)
	}
	if _, err := ParseBaseline(bytes.Replace(first, []byte(a.File), []byte("web/forged.ts"), 1)); err == nil {
		t.Fatal("accepted an entry with forged fingerprint metadata")
	}
}

func TestBaselineReadsLegacyCycleAndImplicitCounts(t *testing.T) {
	entry := BaselineEntry{
		Kind: "cycle", RuleID: "no-cycles", From: "a",
		Source: "a/old.ts", Target: "b/old.ts", CyclePath: []string{"a", "b", "a"},
	}
	entry.Fingerprint = entry.legacyDigest()
	for _, count := range []int{0, -2, 1} {
		entry.Count = count
		raw, err := json.Marshal(BaselineFile{SchemaVersion: "1", Entries: []BaselineEntry{entry}})
		if err != nil {
			t.Fatal(err)
		}
		baseline, err := ParseBaseline(raw)
		if count < 0 {
			if err == nil || !strings.Contains(err.Error(), "negative count") {
				t.Fatalf("expected rejection of negative count: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		cycle := Violation{
			Kind: "cycle", RuleID: "no-cycles", File: "a/new.ts", TargetFile: "b/new.ts",
			CycleMembers: []string{"b", "a"}, CycleEdges: []CycleEdge{{From: "b", To: "a"}, {From: "a", To: "b"}},
		}
		report := Report{Violations: []Violation{cycle, cycle}}
		EvaluateBoundariesWithBaseline(&report, baseline)
		if report.GrandfatheredCount != 1 || len(report.Violations) != 1 {
			t.Fatalf("legacy count %d did not grandfather one unchanged cycle: %+v", count, report)
		}
	}
}

func TestRatchetFailsClosedForMissingInvalidAndOversizedBaselines(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.BoundariesConfig{Enabled: config.BoolPtr(true), Mode: "ratchet"}
	rel := cfg.BaselinePath()
	for _, tc := range []struct{ name, data string }{
		{"missing", ""},
		{"malformed", "{"},
		{"schema", `{"schema_version":"2","entries":[]}`},
		{"null-entries", `{"schema_version":"1","entries":null}`},
		{"trailing-object", `{"schema_version":"1","entries":[]}{}`},
		{"oversized", strings.Repeat(" ", MaxBaselineBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.data != "" {
				mustWrite(t, filepath.Join(dir, rel), tc.data)
			}
			r, err := Analyze(dir, &compmap.Map{}, cfg)
			if err != nil || len(r.ScanErrors) != 1 || len(r.Violations) != 1 || r.Violations[0].Severity != "error" ||
				r.Violations[0].RuleID != "boundary-baseline" {
				t.Fatalf("invalid file was not blocking: %+v, %v", r, err)
			}
		})
	}
}

func TestBaselineRejectsTraversalAndEscapingSymlinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	sentinel := filepath.Join(outside, "baseline.json")
	mustWrite(t, sentinel, "untouched")
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(sentinel, filepath.Join(dir, "alias.json")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{sentinel, "../baseline.json", "a/../baseline.json", "escape/baseline.json", "escape/missing.json", "alias.json", ".git/config", config.ConfigFileName} {
		if _, err := LoadBaseline(dir, rel); err == nil {
			t.Errorf("read accepted %q", rel)
		}
		if err := SaveBaseline(dir, rel, nil); err == nil {
			t.Errorf("write accepted %q", rel)
		}
		if err := RemoveBaseline(dir, rel); err == nil {
			t.Errorf("remove accepted %q", rel)
		}
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "untouched" {
		t.Fatalf("outside file was touched: %q, %v", got, err)
	}
}

func TestBaselineEditRejectsSubstitutionThroughInRepoSymlink(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".git/config"), "keep untouched")
	if err := os.Symlink(".git", filepath.Join(dir, "alias")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := SaveBaseline(dir, "alias/config", nil); err == nil {
		t.Fatal("baseline write reached Git metadata through an alias")
	}
	if err := RemoveBaseline(dir, "alias/config"); err == nil {
		t.Fatal("baseline deletion reached Git metadata through an alias")
	}
	if raw, err := os.ReadFile(filepath.Join(dir, ".git/config")); err != nil || string(raw) != "keep untouched" {
		t.Fatalf("Git metadata changed: %q, %v", raw, err)
	}
}

func TestCycleRatchetAllowsDisjointStructuralSplits(t *testing.T) {
	v := func(members []string, edges ...CycleEdge) Violation {
		return Violation{Kind: "cycle", RuleID: "no-cycles", From: members[0], CycleMembers: members, CycleEdges: edges}
	}
	left := v([]string{"a", "b"}, CycleEdge{"a", "b"}, CycleEdge{"b", "a"})
	right := v([]string{"c", "d"}, CycleEdge{"c", "d"}, CycleEdge{"d", "c"})
	var edges []CycleEdge
	edges = append(edges, left.CycleEdges...)
	edges = append(edges, right.CycleEdges...)
	edges = append(edges, CycleEdge{"b", "c"}, CycleEdge{"d", "a"})
	old := v([]string{"a", "b", "c", "d"}, edges...)
	encode := func(violations ...Violation) *BaselineFile {
		t.Helper()
		raw, err := EncodeBaseline(violations)
		if err != nil {
			t.Fatal(err)
		}
		baseline, err := ParseBaseline(raw)
		if err != nil {
			t.Fatal(err)
		}
		return baseline
	}
	recorded := encode(old)
	split := encode(left, right)
	if n := BaselineExpansion(recorded, split); n != 0 {
		t.Fatalf("split added %d occurrences", n)
	}
	report := &Report{Violations: []Violation{left, right}}
	EvaluateBoundariesWithBaseline(report, recorded)
	if len(report.Violations) != 0 || report.GrandfatheredCount != 2 {
		t.Fatalf("split not grandfathered: %+v", report)
	}
	if n := BaselineExpansion(split, recorded); n != 1 {
		t.Fatalf("joined distinct allowances: %d", n)
	}
	if n := BaselineExpansion(recorded, encode(left, left)); n == 0 {
		t.Fatal("duplicate allowance grew")
	}
	newEdge := v([]string{"a", "b"}, CycleEdge{"a", "b"}, CycleEdge{"b", "a"}, CycleEdge{"a", "a"})
	if n := BaselineExpansion(recorded, encode(newEdge)); n != 1 {
		t.Fatalf("new internal edge accepted: %d", n)
	}
}

func TestGoPackageAllowanceSurvivesWitnessChange(t *testing.T) {
	v := Violation{Kind: "denied-dependency", RuleID: "no-lib", From: "app", To: "lib", File: "app/main.go", TargetFile: "lib/zzz.go"}
	legacy, err := EncodeBaseline([]Violation{v})
	if err != nil {
		t.Fatal(err)
	}
	old, err := ParseBaseline(legacy)
	if err != nil {
		t.Fatal(err)
	}
	v.TargetPackageDir = "lib"
	before := ViolationFingerprint(v)
	v.TargetFile = "lib/aaa.go"
	if before != ViolationFingerprint(v) {
		t.Fatal("Go witness changed package fingerprint")
	}
	report := Report{Violations: []Violation{v, v}}
	EvaluateBoundariesWithBaseline(&report, old)
	if report.GrandfatheredCount != 1 || len(report.Violations) != 1 {
		t.Fatalf("allowance reused or lost: %+v", report)
	}
	raw, err := EncodeBaseline([]Violation{v})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := ParseBaseline(raw)
	if err != nil || canonical.Entries[0].Target != "lib" || BaselineExpansion(old, canonical) != 0 {
		t.Fatalf("package baseline not compatible with legacy allowance: %s %v", raw, err)
	}
}
