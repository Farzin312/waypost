package archgraph

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

const MaxBaselineBytes = 4 * 1024 * 1024

type BaselineFile struct {
	SchemaVersion string          `json:"schema_version"`
	Entries       []BaselineEntry `json:"entries"`
}

type BaselineEntry struct {
	Kind         string      `json:"kind"`
	RuleID       string      `json:"rule_id"`
	From         string      `json:"from"`
	To           string      `json:"to,omitempty"`
	Source       string      `json:"source,omitempty"`
	Target       string      `json:"target,omitempty"`
	CyclePath    []string    `json:"cycle_path,omitempty"` // Legacy baseline field.
	CycleMembers []string    `json:"cycle_members,omitempty"`
	CycleEdges   []CycleEdge `json:"cycle_edges,omitempty"`
	Fingerprint  string      `json:"fingerprint"`
	Count        int         `json:"count,omitempty"`
}

// Occurrences returns the baseline allowance, including the implicit count in older files.
func (e BaselineEntry) Occurrences() int { return max(e.Count, 1) }

// ViolationFingerprint identifies a boundary violation independently of its line,
// diagnostic message, and severity.
func ViolationFingerprint(v Violation) string {
	return baselineEntry(v).Fingerprint
}

func baselineEntry(v Violation) BaselineEntry {
	e := BaselineEntry{
		Kind: v.Kind, RuleID: v.RuleID, From: v.From, To: v.To,
		Source: normalizeFile(v.File), Target: normalizeFile(v.TargetFile),
	}
	if v.Kind == "cycle" {
		e.To, e.Source, e.Target = "", "", ""
		e.CycleMembers, e.CycleEdges = v.CycleMembers, v.CycleEdges
		if len(e.CycleMembers) == 0 {
			e.CycleMembers, e.CycleEdges = cycleFromPath(v.CyclePath)
		}
		e.canonicalizeCycle()
	}
	e.Fingerprint = e.digest()
	return e
}

func (e BaselineEntry) digest() string {
	if e.Kind == "cycle" {
		return baselineDigest(e.Kind, e.RuleID, e.CycleMembers, e.CycleEdges)
	}
	return e.legacyDigest()
}

func (e BaselineEntry) legacyDigest() string {
	return baselineDigest(e.Kind, e.RuleID, e.From, e.To, e.Source, e.Target, e.CyclePath)
}

func baselineDigest(fields ...any) string {
	raw, _ := json.Marshal(fields)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func normalizeFile(file string) string {
	if file == "" {
		return ""
	}
	return path.Clean(filepath.ToSlash(file))
}

func (e *BaselineEntry) canonicalizeCycle() {
	e.CycleMembers = slices.Clone(e.CycleMembers)
	e.CycleEdges = slices.Clone(e.CycleEdges)
	slices.Sort(e.CycleMembers)
	sortCycleEdges(e.CycleEdges)
	if len(e.CycleMembers) > 0 {
		e.From = e.CycleMembers[0]
	}
}

func sortCycleEdges(edges []CycleEdge) {
	slices.SortFunc(edges, func(a, b CycleEdge) int {
		if a.From != b.From {
			return strings.Compare(a.From, b.From)
		}
		return strings.Compare(a.To, b.To)
	})
}

func cycleFromPath(cycle []string) ([]string, []CycleEdge) {
	if len(cycle) > 1 && cycle[0] == cycle[len(cycle)-1] {
		cycle = cycle[:len(cycle)-1]
	}
	edges := make([]CycleEdge, 0, len(cycle))
	for i, from := range cycle {
		edges = append(edges, CycleEdge{From: from, To: cycle[(i+1)%len(cycle)]})
	}
	return cycle, edges
}

// ParseBaseline validates both worktree and trusted Git baselines.
func ParseBaseline(raw []byte) (*BaselineFile, error) {
	if len(raw) > MaxBaselineBytes {
		return nil, fmt.Errorf("baseline exceeds %d bytes", MaxBaselineBytes)
	}
	var baseline BaselineFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&baseline); err != nil {
		return nil, fmt.Errorf("invalid baseline JSON: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("baseline must contain exactly one JSON object")
	}
	if baseline.SchemaVersion != "1" || baseline.Entries == nil {
		return nil, errors.New("baseline requires schema_version \"1\" and an entries array")
	}
	seen := make(map[string]bool, len(baseline.Entries))
	total := 0
	for i := range baseline.Entries {
		entry := &baseline.Entries[i]
		if entry.Kind == "cycle" {
			if len(entry.CyclePath) > 0 && len(entry.CycleMembers) == 0 && len(entry.CycleEdges) == 0 &&
				entry.Fingerprint == entry.legacyDigest() {
				// A legacy path grants only the directed edges it recorded.
				entry.CycleMembers, entry.CycleEdges = cycleFromPath(entry.CyclePath)
				entry.canonicalizeCycle()
				entry.Fingerprint = entry.digest()
			} else {
				entry.canonicalizeCycle()
			}
			if len(entry.CycleMembers) == 0 || len(entry.CycleEdges) == 0 {
				return nil, fmt.Errorf("invalid baseline cycle %q", entry.Fingerprint)
			}
		}
		if entry.Kind == "" || entry.Kind == "scan-error" || entry.RuleID == "" || entry.From == "" || entry.Fingerprint != entry.digest() {
			return nil, fmt.Errorf("invalid baseline entry %q", entry.Fingerprint)
		}
		if seen[entry.Fingerprint] {
			return nil, fmt.Errorf("duplicate baseline fingerprint %q", entry.Fingerprint)
		}
		seen[entry.Fingerprint] = true
		if entry.Occurrences() > math.MaxInt-total {
			return nil, errors.New("baseline occurrence counts exceed the supported total")
		}
		total += entry.Occurrences()
	}
	return &baseline, nil
}

func LoadBaseline(repoRoot, relPath string) (*BaselineFile, error) {
	if err := config.ValidateBaselinePath(repoRoot, relPath); err != nil {
		return nil, err
	}
	raw, err := compmap.ReadBoundedRegularFile(repoRoot, filepath.Join(repoRoot, relPath), MaxBaselineBytes)
	if err != nil {
		return nil, err
	}
	return ParseBaseline(raw)
}

func SaveBaseline(repoRoot, relPath string, violations []Violation) error {
	baseline := BaselineFile{SchemaVersion: "1", Entries: make([]BaselineEntry, 0, len(violations))}
	positions := make(map[string]int, len(violations))
	for _, v := range violations {
		if v.Kind == "scan-error" {
			return errors.New("cannot save an incomplete boundary scan")
		}
		entry := baselineEntry(v)
		if i, ok := positions[entry.Fingerprint]; ok {
			existing := &baseline.Entries[i]
			existing.Count = existing.Occurrences() + 1
		} else {
			positions[entry.Fingerprint] = len(baseline.Entries)
			baseline.Entries = append(baseline.Entries, entry)
		}
	}
	slices.SortFunc(baseline.Entries, func(a, b BaselineEntry) int {
		left := []string{a.Kind, a.From, a.To, a.Source, a.Target, a.Fingerprint}
		right := []string{b.Kind, b.From, b.To, b.Source, b.Target, b.Fingerprint}
		return slices.Compare(left, right)
	})
	raw, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > MaxBaselineBytes {
		return fmt.Errorf("baseline exceeds %d bytes", MaxBaselineBytes)
	}
	root, err := openBaselineForEdit(repoRoot, relPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(relPath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(repoRoot, ".waypost-baseline-*.tmp")
	if err != nil {
		return err
	}
	defer root.Remove(filepath.Base(tmp.Name()))
	_, writeErr := tmp.Write(raw)
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return root.Rename(filepath.Base(tmp.Name()), relPath)
}

// RemoveBaseline removes a baseline after a complete scan finds no violations.
func RemoveBaseline(repoRoot, relPath string) error {
	root, err := openBaselineForEdit(repoRoot, relPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(relPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func openBaselineForEdit(repoRoot, relPath string) (*os.Root, error) {
	if err := config.ValidateBaselinePath(repoRoot, relPath); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		return nil, err
	}
	target := filepath.FromSlash(relPath)
	for prefix := target; prefix != "."; prefix = filepath.Dir(prefix) {
		info, err := root.Lstat(prefix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			switch {
			case prefix == target && !info.Mode().IsRegular():
				err = fmt.Errorf("baseline %q is not a regular file", relPath)
			case prefix != target && !info.IsDir():
				err = fmt.Errorf("baseline parent %q is not a real directory", prefix)
			}
		}
		if err != nil {
			root.Close()
			return nil, err
		}
	}
	return root, nil
}

// EvaluateBoundariesWithBaseline partitions a live ratchet report. A nil baseline
// is a blocking scan error, and incomplete scan diagnostics are never grandfathered.
func EvaluateBoundariesWithBaseline(report *Report, baseline *BaselineFile) {
	if baseline == nil {
		report.addBaselineError("", errors.New("ratchet requires a valid boundary baseline"))
		return
	}
	remaining := make(map[string]int, len(baseline.Entries))
	for _, e := range baseline.Entries {
		remaining[e.Fingerprint] = e.Occurrences()
	}
	live := report.Violations[:0]
	for _, v := range report.Violations {
		key := ViolationFingerprint(v)
		if remaining[key] > 0 && v.Kind != "scan-error" {
			remaining[key]--
			report.grandfathered = append(report.grandfathered, v)
		} else {
			live = append(live, v)
		}
	}
	report.Violations = live
	report.GrandfatheredCount = len(report.grandfathered)
	for _, count := range remaining {
		report.ResolvedBaselineCount += count
	}
}

// Grandfathered returns the still-live violations for shrinking a baseline.
func (r *Report) Grandfathered() []Violation { return r.grandfathered }

func (r *Report) addBaselineError(rel string, err error) {
	message := fmt.Sprintf("boundary baseline %q: %v (run waypost graph --update-baseline to seed)", rel, err)
	r.ScanErrors = append(r.ScanErrors, message)
	r.Violations = append(r.Violations, Violation{
		RuleID: "boundary-baseline", Kind: "scan-error", Severity: "error", Message: message,
	})
}
