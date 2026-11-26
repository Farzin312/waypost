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
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repowrite"
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
	if v.TargetPackageDir != "" {
		e.Target = normalizeFile(v.TargetPackageDir)
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
			if !validCycle(*entry) {
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
		if entry.Count < 0 {
			return nil, fmt.Errorf("baseline entry %q has negative count", entry.Fingerprint)
		}
		if entry.Occurrences() > math.MaxInt-total {
			return nil, errors.New("baseline occurrence counts exceed the supported total")
		}
		total += entry.Occurrences()
	}
	return &baseline, nil
}

func validCycle(entry BaselineEntry) bool {
	if len(entry.CycleMembers) == 0 || len(entry.CycleEdges) == 0 {
		return false
	}
	members := make(map[string]bool)
	for _, member := range entry.CycleMembers {
		if member == "" || members[member] {
			return false
		}
		members[member] = true
	}
	forward, reverse := make(map[string][]string), make(map[string][]string)
	seen := make(map[CycleEdge]bool)
	for _, edge := range entry.CycleEdges {
		if seen[edge] || !members[edge.From] || !members[edge.To] {
			return false
		}
		seen[edge] = true
		forward[edge.From] = append(forward[edge.From], edge.To)
		reverse[edge.To] = append(reverse[edge.To], edge.From)
	}
	for _, adj := range []map[string][]string{forward, reverse} {
		reached := make(map[string]bool)
		queue := []string{entry.CycleMembers[0]}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			if reached[id] {
				continue
			}
			reached[id] = true
			queue = append(queue, adj[id]...)
		}
		if len(reached) != len(members) {
			return false
		}
	}
	return true
}

func LoadBaseline(repoRoot, relPath string) (*BaselineFile, error) {
	if err := config.ValidateBaselinePath(repoRoot, relPath); err != nil {
		return nil, err
	}
	raw, err := repopath.Read(repoRoot, relPath, MaxBaselineBytes)
	if err != nil {
		return nil, err
	}
	return ParseBaseline(raw)
}

func EncodeBaseline(violations []Violation) ([]byte, error) {
	baseline := BaselineFile{SchemaVersion: "1", Entries: make([]BaselineEntry, 0, len(violations))}
	positions := make(map[string]int, len(violations))
	for _, v := range violations {
		if v.Kind == "scan-error" {
			return nil, errors.New("cannot save an incomplete boundary scan")
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
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > MaxBaselineBytes {
		return nil, fmt.Errorf("baseline exceeds %d bytes", MaxBaselineBytes)
	}
	return raw, nil
}

func SaveBaseline(repoRoot, relPath string, violations []Violation) error {
	raw, err := EncodeBaseline(violations)
	if err != nil {
		return err
	}
	return writeBaseline(repoRoot, relPath, raw)
}

// RemoveBaseline removes a recorded baseline under the shared writer lock.
func RemoveBaseline(repoRoot, relPath string) error {
	return writeBaseline(repoRoot, relPath, nil)
}

func writeBaseline(repoRoot, relPath string, raw []byte) error {
	tx, close, err := repowrite.Acquire(repoRoot)
	if err != nil {
		return err
	}
	defer close()
	if err := config.ValidateBaselinePath(repoRoot, relPath); err != nil {
		return err
	}
	old, err := repowrite.Read(repoRoot, relPath)
	if err != nil || repowrite.Same(old, raw) {
		return err
	}
	return tx.Commit(repowrite.Mutation{Path: relPath, Old: old, New: raw})
}

// EvaluateBoundariesWithBaseline partitions a live ratchet report. A nil baseline
// is a blocking scan error, and incomplete scan diagnostics are never grandfathered.
func EvaluateBoundariesWithBaseline(report *Report, baseline *BaselineFile) {
	if baseline == nil {
		report.addBaselineError("", errors.New("ratchet requires a valid boundary baseline"))
		return
	}
	allowances := newAllowances(baseline)
	live := report.Violations[:0]
	for _, v := range report.Violations {
		if v.Kind != "scan-error" && allowances.consumeViolation(&v) {
			report.grandfathered = append(report.grandfathered, v)
		} else {
			live = append(live, v)
		}
	}
	report.Violations = live
	report.GrandfatheredCount = len(report.grandfathered)
	report.ResolvedBaselineCount = allowances.remaining()
}

// BaselineExpansion counts candidate occurrences outside the trusted allowances.
func BaselineExpansion(old, candidate *BaselineFile) int {
	allowances := newAllowances(old)
	added := 0
	entries := slices.Clone(candidate.Entries)
	// Prefer exact/larger SCCs before assigning split cycles.
	slices.SortStableFunc(entries, func(a, b BaselineEntry) int { return len(b.CycleEdges) - len(a.CycleEdges) })
	for _, e := range entries {
		used := allowances.consume(e)
		if used < e.Occurrences() && strings.HasSuffix(e.Source, ".go") {
			legacy, _ := allowances.consumeLegacyGo(e, e.Occurrences()-used)
			used += legacy
		}
		added += e.Occurrences() - used
	}
	return added
}

type cycleAllowance struct {
	entry   BaselineEntry
	members map[string]int
	edges   map[CycleEdge]int
	used    int
}

type allowances struct {
	exact       map[string]int
	goWitnesses map[string][]BaselineEntry
	cycles      []cycleAllowance
}

func newAllowances(b *BaselineFile) *allowances {
	a := &allowances{exact: make(map[string]int), goWitnesses: make(map[string][]BaselineEntry)}
	if b == nil {
		return a
	}
	for _, e := range b.Entries {
		if e.Kind != "cycle" {
			a.exact[e.Fingerprint] = e.Occurrences()
			if strings.HasSuffix(e.Source, ".go") && strings.HasSuffix(e.Target, ".go") {
				packageEntry := e
				packageEntry.Target = path.Dir(e.Target)
				key := packageEntry.digest()
				a.goWitnesses[key] = append(a.goWitnesses[key], e)
			}
			continue
		}
		c := cycleAllowance{entry: e, members: make(map[string]int), edges: make(map[CycleEdge]int)}
		for _, member := range e.CycleMembers {
			c.members[member] = 0
		}
		for _, edge := range e.CycleEdges {
			c.edges[edge] = 0
		}
		a.cycles = append(a.cycles, c)
	}
	return a
}

func (a *allowances) consumeViolation(v *Violation) bool {
	e := baselineEntry(*v)
	if a.consume(e) == 1 {
		return true
	}
	if v.TargetPackageDir == "" {
		return false
	}
	if n, witness := a.consumeLegacyGo(e, 1); n == 1 {
		v.TargetPackageDir, v.TargetFile = "", witness
		return true
	}
	return false
}

func (a *allowances) consumeLegacyGo(e BaselineEntry, n int) (used int, witness string) {
	for _, legacy := range a.goWitnesses[e.Fingerprint] {
		matched := min(a.exact[legacy.Fingerprint], n-used)
		if matched == 0 {
			continue
		}
		a.exact[legacy.Fingerprint] -= matched
		used += matched
		witness = legacy.Target
		if used == n {
			break
		}
	}
	return used, witness
}

func (a *allowances) consume(e BaselineEntry) int {
	n := e.Occurrences()
	if e.Kind != "cycle" {
		used := min(a.exact[e.Fingerprint], n)
		a.exact[e.Fingerprint] -= used
		return used
	}
	if len(e.CycleMembers) == 0 || len(e.CycleEdges) == 0 {
		return 0
	}
	chosen, consumed := -1, 0
	for i, c := range a.cycles {
		if c.entry.RuleID != e.RuleID {
			continue
		}
		capacity := min(c.entry.Occurrences(), n)
		for _, member := range e.CycleMembers {
			used, ok := c.members[member]
			if !ok {
				capacity = 0
				break
			}
			capacity = min(capacity, c.entry.Occurrences()-used)
		}
		for _, edge := range e.CycleEdges {
			used, ok := c.edges[edge]
			if !ok {
				capacity = 0
				break
			}
			capacity = min(capacity, c.entry.Occurrences()-used)
		}
		if capacity > consumed {
			chosen, consumed = i, capacity
			if consumed == n {
				break
			}
		}
	}
	if chosen < 0 {
		return 0
	}
	c := &a.cycles[chosen]
	for _, member := range e.CycleMembers {
		c.members[member] += consumed
		c.used = max(c.used, c.members[member])
	}
	for _, edge := range e.CycleEdges {
		c.edges[edge] += consumed
	}
	return consumed
}

func (a *allowances) remaining() int {
	n := 0
	for _, left := range a.exact {
		n += left
	}
	for _, cycle := range a.cycles {
		n += cycle.entry.Occurrences() - cycle.used
	}
	return n
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
