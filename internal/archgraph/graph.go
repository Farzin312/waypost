package archgraph

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

const maxSampleSitesPerEdge = 5

// ImportSite pinpoints a concrete file:line import in the repository.
type ImportSite struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Specifier  string `json:"specifier"`
	TargetFile string `json:"target_file"`
}

// ComponentEdge summarizes all observed static code imports from component From to To.
type ComponentEdge struct {
	From        string       `json:"from"`
	To          string       `json:"to"`
	FileCount   int          `json:"file_count"`
	ImportCount int          `json:"import_count"`
	Declared    bool         `json:"declared"`
	SampleSites []ImportSite `json:"sample_sites,omitempty"`
}

// NodeMetrics gives an AI agent the architectural role and blast-radius metrics of a component.
type NodeMetrics struct {
	ID                 string   `json:"id"`
	Root               string   `json:"root"`
	Kind               string   `json:"kind,omitempty"`
	Language           string   `json:"language,omitempty"`
	FileCount          int      `json:"file_count"`
	FanIn              int      `json:"fan_in"`
	FanOut             int      `json:"fan_out"`
	Criticality        string   `json:"criticality"` // "hub" | "entrypoint" | "leaf" | "standard" | "isolated"
	ObservedDependsOn  []string `json:"observed_depends_on,omitempty"`
	ObservedDependedBy []string `json:"observed_depended_by,omitempty"`
	DeclaredDependsOn  []string `json:"declared_depends_on,omitempty"`
	UndeclaredImports  []string `json:"undeclared_imports,omitempty"`
}

// CycleEdge is a directed import between two members of a cyclic component group.
type CycleEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// CycleWitness records a cyclic component group and one concrete cycle through it.
type CycleWitness struct {
	Members   []string     `json:"members"`
	Edges     []CycleEdge  `json:"edges"`
	Path      []string     `json:"path"`
	Witnesses []ImportSite `json:"witnesses,omitempty"`
}

// Violation represents one concrete architectural boundary breach with exact file:line location.
type Violation struct {
	RuleID       string      `json:"rule_id"`
	Kind         string      `json:"kind"`     // "cycle" | "undeclared-dependency" | "disallowed-dependency" | "denied-dependency" | "private-import"
	Severity     string      `json:"severity"` // "error" | "warn"
	From         string      `json:"from"`
	To           string      `json:"to,omitempty"`
	File         string      `json:"file,omitempty"`
	Line         int         `json:"line,omitempty"`
	Specifier    string      `json:"specifier,omitempty"`
	TargetFile   string      `json:"target_file,omitempty"`
	Message      string      `json:"message"`
	CyclePath    []string    `json:"cycle_path,omitempty"`
	CycleMembers []string    `json:"cycle_members,omitempty"`
	CycleEdges   []CycleEdge `json:"cycle_edges,omitempty"`
}

// BlastRadius reports file-level and component-level reverse impact for a set of changed files.
type BlastRadius struct {
	ChangedFiles         []string `json:"changed_files,omitempty"`
	DirectImporters      []string `json:"direct_importers,omitempty"`
	TransitiveFiles      []string `json:"transitive_files,omitempty"`
	DirectComponents     []string `json:"direct_components,omitempty"`
	TransitiveDependents []string `json:"transitive_dependents,omitempty"`
}

// Report is the complete live code architecture & boundary analysis result.
type Report struct {
	FilesScanned          int             `json:"files_scanned"`
	ImportsScanned        int             `json:"imports_scanned"`
	BoundariesMode        string          `json:"boundaries_mode,omitempty"` // "enforce" | "ratchet" | "warn" | "off"
	Nodes                 []NodeMetrics   `json:"nodes"`
	Edges                 []ComponentEdge `json:"edges,omitempty"`
	Cycles                []CycleWitness  `json:"cycles,omitempty"`
	Violations            []Violation     `json:"violations,omitempty"`
	GrandfatheredCount    int             `json:"grandfathered_count,omitempty"`
	ResolvedBaselineCount int             `json:"resolved_baseline_count,omitempty"`
	ScanErrors            []string        `json:"scan_errors,omitempty"`
	Hubs                  []string        `json:"hubs,omitempty"`
	Blast                 *BlastRadius    `json:"blast_radius,omitempty"`

	// internal lookup maps for BlastRadius computation
	grandfathered []Violation
	rawImports    []RawImport
	fileOwner     map[string]string
	revCompAdj    map[string][]string
}

// Analyze scans source imports statically across TS/JS, Go, Python, and Rust, maps them
// onto Waypost components, detects cycles with file:line witnesses, and evaluates all
// declarative BoundariesConfig rules.
func Analyze(repoDir string, cm *compmap.Map, boundaries *config.BoundariesConfig) (*Report, error) {
	return AnalyzeWithOptions(repoDir, cm, boundaries, AnalyzeOptions{})
}

func AnalyzeWithOptions(repoDir string, cm *compmap.Map, boundaries *config.BoundariesConfig, opts AnalyzeOptions) (*Report, error) {
	report, err := AnalyzeLive(repoDir, cm, boundaries, opts)
	if err != nil || report.BoundariesMode != "ratchet" {
		return report, err
	}
	read := opts.BaselineReader
	if read == nil {
		read = func(relPath string) (*BaselineFile, error) { return LoadBaseline(repoDir, relPath) }
	}
	baseline, err := read(boundaries.BaselinePath())
	if err != nil {
		report.addBaselineError(boundaries.BaselinePath(), err)
	} else {
		EvaluateBoundariesWithBaseline(report, baseline)
	}
	return report, nil
}

// AnalyzeLive scans raw violations before comparing them to any baseline.
// Explicit baseline updates and trusted Git verification supply their own baseline.
func AnalyzeLive(repoDir string, cm *compmap.Map, boundaries *config.BoundariesConfig, opts AnalyzeOptions) (*Report, error) {
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, err
	}

	var ignore []string
	if boundaries != nil {
		ignore = boundaries.IgnorePaths
	}
	scan, err := scanRepoImports(absRepo, cm, ignore, opts)
	if err != nil {
		return nil, err
	}

	files, rawImports := scan.files, scan.imports
	declaredDeps := make(map[string]map[string]bool, len(cm.Components))
	for _, c := range cm.Components {
		depSet := make(map[string]bool, len(c.DependsOn))
		for _, d := range c.DependsOn {
			depSet[d] = true
		}
		declaredDeps[c.ID] = depSet
	}

	fileOwner := make(map[string]string, len(files))
	fileCount := make(map[string]int, len(cm.Components))
	for f := range files {
		owner := primaryOwnerOf(cm, f)
		if owner != "" {
			fileOwner[f] = owner
			fileCount[owner]++
		}
	}

	type edgeKey struct{ from, to string }
	type edgeAcc struct {
		files   map[string]bool
		count   int
		samples []ImportSite
	}
	edgeMap := make(map[edgeKey]*edgeAcc)
	obsDeps := make(map[string]map[string]bool)
	obsRev := make(map[string]map[string]bool)

	type ownedImport struct {
		RawImport
		from, to string
	}
	// A Go import targets every file in the package. Keep one edge per
	// owning component, with a concrete Go file as the witness.
	goOwners := make(map[string]map[string]string, len(scan.goPackages))
	for dir, members := range scan.goPackages {
		goOwners[dir] = make(map[string]string)
		for _, f := range members {
			owner := fileOwner[f]
			if owner != "" && goOwners[dir][owner] == "" {
				goOwners[dir][owner] = f
			}
		}
	}
	var ownedImports []ownedImport
	for _, imp := range rawImports {
		from := fileOwner[imp.File]
		if from == "" {
			continue
		}
		if imp.TargetPackageDir == "" {
			if to := fileOwner[imp.TargetFile]; to != "" && to != from {
				ownedImports = append(ownedImports, ownedImport{imp, from, to})
			}
		} else {
			for to, file := range goOwners[imp.TargetPackageDir] {
				if to != from {
					witness := imp
					witness.TargetFile = file
					ownedImports = append(ownedImports, ownedImport{witness, from, to})
				}
			}
		}
	}

	for _, imp := range ownedImports {
		fromComp, toComp := imp.from, imp.to
		k := edgeKey{from: fromComp, to: toComp}
		acc := edgeMap[k]
		if acc == nil {
			acc = &edgeAcc{files: make(map[string]bool)}
			edgeMap[k] = acc
		}
		acc.files[imp.File] = true
		acc.count++
		if len(acc.samples) < maxSampleSitesPerEdge {
			acc.samples = append(acc.samples, ImportSite{
				File:       imp.File,
				Line:       imp.Line,
				Specifier:  imp.Specifier,
				TargetFile: imp.TargetFile,
			})
		}
		if obsDeps[fromComp] == nil {
			obsDeps[fromComp] = make(map[string]bool)
		}
		obsDeps[fromComp][toComp] = true
		if obsRev[toComp] == nil {
			obsRev[toComp] = make(map[string]bool)
		}
		obsRev[toComp][fromComp] = true
	}

	edges := make([]ComponentEdge, 0, len(edgeMap))
	edgeWitness := make(map[edgeKey]ImportSite, len(edgeMap))
	for k, acc := range edgeMap {
		decl := declaredDeps[k.from][k.to]
		edges = append(edges, ComponentEdge{
			From:        k.from,
			To:          k.to,
			FileCount:   len(acc.files),
			ImportCount: acc.count,
			Declared:    decl,
			SampleSites: acc.samples,
		})
		if len(acc.samples) > 0 {
			edgeWitness[k] = acc.samples[0]
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})

	// Build nodes and compute criticality/hubs.
	nodes := make([]NodeMetrics, 0, len(cm.Components))
	revCompAdj := make(map[string][]string, len(cm.Components))
	var hubs []string
	for _, c := range cm.Components {
		od := mapKeysSorted(obsDeps[c.ID])
		or := mapKeysSorted(obsRev[c.ID])
		revCompAdj[c.ID] = or
		var undecl []string
		for _, dep := range od {
			if !declaredDeps[c.ID][dep] {
				undecl = append(undecl, dep)
			}
		}
		fanIn := len(or)
		fanOut := len(od)
		crit := classifyCriticality(fanIn, fanOut)
		if crit == "hub" {
			hubs = append(hubs, c.ID)
		}
		nodes = append(nodes, NodeMetrics{
			ID:                 c.ID,
			Root:               c.Root,
			Kind:               c.Kind,
			Language:           c.Language,
			FileCount:          fileCount[c.ID],
			FanIn:              fanIn,
			FanOut:             fanOut,
			Criticality:        crit,
			ObservedDependsOn:  od,
			ObservedDependedBy: or,
			DeclaredDependsOn:  c.DependsOn,
			UndeclaredImports:  undecl,
		})
	}
	sort.Strings(hubs)

	// Detect live code import cycles with concrete file:line witnesses.
	cycles := detectObservedCycles(nodes, func(u, v string) (ImportSite, bool) {
		s, ok := edgeWitness[edgeKey{from: u, to: v}]
		return s, ok
	})

	mode := "off"
	severity := "warn"
	if boundaries.IsEnabled() {
		mode = boundaries.EffectiveMode()
		if mode != "warn" {
			severity = "error"
		}
	}

	var violations []Violation
	if boundaries.IsEnabled() {
		for _, scanError := range scan.errors {
			violations = append(violations, Violation{
				RuleID: "incomplete-scan", Kind: "scan-error", Severity: severity, Message: scanError,
			})
		}

		// 1. Cycle rule
		if config.BoolVal(boundaries.NoCycles, true) {
			for _, cyc := range cycles {
				msg := fmt.Sprintf("circular component import cycle: %s (cyclic components: %s)",
					strings.Join(cyc.Path, " -> "), strings.Join(cyc.Members, ", "))
				v := Violation{
					RuleID:       "no-cycles",
					Kind:         "cycle",
					Severity:     severity,
					From:         cyc.Members[0],
					CyclePath:    cyc.Path,
					CycleMembers: cyc.Members,
					CycleEdges:   cyc.Edges,
					Message:      msg,
				}
				if len(cyc.Witnesses) > 0 {
					w := cyc.Witnesses[0]
					v.File = w.File
					v.Line = w.Line
					v.Specifier = w.Specifier
					v.TargetFile = w.TargetFile
				}
				violations = append(violations, v)
			}
		}

		// 2. Enforce declared component dependencies (strict allowlist mode matching legacy bounds enforce: on)
		if config.BoolVal(boundaries.EnforceDeclaredDeps, false) {
			for _, imp := range ownedImports {
				fromComp, toComp := imp.from, imp.to
				if !declaredDeps[fromComp][toComp] {
					violations = append(violations, Violation{
						RuleID:     "enforce-declared-deps",
						Kind:       "undeclared-dependency",
						Severity:   severity,
						From:       fromComp,
						To:         toComp,
						File:       imp.File,
						Line:       imp.Line,
						Specifier:  imp.Specifier,
						TargetFile: imp.TargetFile,
						Message:    fmt.Sprintf("%s:%d (%s) imports %s (%s), which is not listed in %s.depends_on", imp.File, imp.Line, fromComp, toComp, imp.Specifier, fromComp),
					})
				}
			}
		}

		// 3. Explicit declarative boundary rules (allow_depends_on, deny_depends_on, public_entrypoints)
		for _, imp := range ownedImports {
			fromComp, toComp := imp.from, imp.to
			for _, rule := range boundaries.Rules {
				if rule.From != "" && MatchesComponentPattern(rule.From, fromComp) {
					if rule.AllowDependsOn != nil {
						allowed := false
						for _, pat := range *rule.AllowDependsOn {
							if MatchesComponentPattern(pat, toComp) {
								allowed = true
								break
							}
						}
						if !allowed {
							reason := rule.Reason
							if reason == "" {
								reason = fmt.Sprintf("component %q is only allowed to depend on %v", fromComp, *rule.AllowDependsOn)
							}
							violations = append(violations, Violation{
								RuleID:     rule.ID,
								Kind:       "disallowed-dependency",
								Severity:   severity,
								From:       fromComp,
								To:         toComp,
								File:       imp.File,
								Line:       imp.Line,
								Specifier:  imp.Specifier,
								TargetFile: imp.TargetFile,
								Message:    fmt.Sprintf("%s:%d (%s -> %s via %q): %s", imp.File, imp.Line, fromComp, toComp, imp.Specifier, reason),
							})
						}
					}
					for _, pat := range rule.DenyDependsOn {
						if MatchesComponentPattern(pat, toComp) {
							reason := rule.Reason
							if reason == "" {
								reason = fmt.Sprintf("component %q must not depend on %q", fromComp, toComp)
							}
							violations = append(violations, Violation{
								RuleID:     rule.ID,
								Kind:       "denied-dependency",
								Severity:   severity,
								From:       fromComp,
								To:         toComp,
								File:       imp.File,
								Line:       imp.Line,
								Specifier:  imp.Specifier,
								TargetFile: imp.TargetFile,
								Message:    fmt.Sprintf("%s:%d (%s -> %s via %q): %s", imp.File, imp.Line, fromComp, toComp, imp.Specifier, reason),
							})
							break
						}
					}
				}
				if rule.Target != "" && len(rule.PublicEntrypoints) > 0 && MatchesComponentPattern(rule.Target, toComp) {
					if rule.From != "" && !MatchesComponentPattern(rule.From, fromComp) {
						continue
					}
					if !isPublicImport(rule.PublicEntrypoints, imp.RawImport, toComp, scan.goPackages, fileOwner) {
						reason := rule.Reason
						if reason == "" {
							reason = fmt.Sprintf("external imports into %q must go through public entrypoints %v", toComp, rule.PublicEntrypoints)
						}
						violations = append(violations, Violation{
							RuleID:     rule.ID,
							Kind:       "private-import",
							Severity:   severity,
							From:       fromComp,
							To:         toComp,
							File:       imp.File,
							Line:       imp.Line,
							Specifier:  imp.Specifier,
							TargetFile: imp.TargetFile,
							Message:    fmt.Sprintf("%s:%d (%s deep-imports private file %s in %s): %s", imp.File, imp.Line, fromComp, imp.TargetFile, toComp, reason),
						})
					}
				}
			}
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].RuleID != violations[j].RuleID {
			return violations[i].RuleID < violations[j].RuleID
		}
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		if violations[i].Line != violations[j].Line {
			return violations[i].Line < violations[j].Line
		}
		if violations[i].TargetFile != violations[j].TargetFile {
			return violations[i].TargetFile < violations[j].TargetFile
		}
		return violations[i].Message < violations[j].Message
	})

	return &Report{
		FilesScanned:   len(files),
		ImportsScanned: len(rawImports),
		BoundariesMode: mode,
		Nodes:          nodes,
		Edges:          edges,
		Cycles:         cycles,
		Violations:     violations,
		ScanErrors:     scan.errors,
		Hubs:           hubs,
		rawImports:     rawImports,
		fileOwner:      fileOwner,
		revCompAdj:     revCompAdj,
	}, nil
}

func isPublicImport(globs []string, imp RawImport, owner string, packages map[string][]string, owners map[string]string) bool {
	if imp.TargetPackageDir == "" {
		return compmap.MatchAnyGlob(globs, imp.TargetFile)
	}
	if compmap.MatchAnyGlob(globs, imp.TargetPackageDir) {
		return true
	}
	for _, f := range packages[imp.TargetPackageDir] {
		if owners[f] == owner && compmap.MatchAnyGlob(globs, f) {
			return true
		}
	}
	return false
}

// ComputeBlastRadius walks file-level AND component-level reverse import edges from changedFiles.
func (r *Report) ComputeBlastRadius(changedFiles []string) BlastRadius {
	revFiles := make(map[string][]string)
	revPackages := make(map[string][]string)
	for _, imp := range r.rawImports {
		if imp.TargetPackageDir != "" {
			dir := imp.TargetPackageDir
			revPackages[dir] = append(revPackages[dir], imp.File)
		} else {
			revFiles[imp.TargetFile] = append(revFiles[imp.TargetFile], imp.File)
		}
	}
	importersOf := func(file string) []string {
		if strings.EqualFold(path.Ext(file), ".go") {
			return slices.Concat(revPackages[path.Dir(file)], revFiles[file])
		}
		return revFiles[file]
	}

	changedSet := make(map[string]bool, len(changedFiles))
	directImporters := make(map[string]bool)
	directComps := make(map[string]bool)
	var queue []string

	for _, f := range changedFiles {
		norm := strings.TrimPrefix(filepath.ToSlash(f), "./")
		changedSet[norm] = true
	}
	for f := range changedSet {
		queue = append(queue, f)
		if owner := r.fileOwner[f]; owner != "" {
			directComps[owner] = true
		}
		for _, impFile := range importersOf(f) {
			if !changedSet[impFile] {
				directImporters[impFile] = true
			}
		}
	}

	visitedFiles := make(map[string]bool, len(changedSet))
	for f := range changedSet {
		visitedFiles[f] = true
	}
	transitiveFiles := make(map[string]bool)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range importersOf(cur) {
			if !visitedFiles[nxt] {
				visitedFiles[nxt] = true
				transitiveFiles[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}

	// Component-level transitive reverse dependents.
	visitedComps := make(map[string]bool, len(directComps))
	compQueue := make([]string, 0, len(directComps))
	for c := range directComps {
		visitedComps[c] = true
		compQueue = append(compQueue, c)
	}
	transComps := make(map[string]bool)
	for len(compQueue) > 0 {
		cur := compQueue[0]
		compQueue = compQueue[1:]
		for _, depBy := range r.revCompAdj[cur] {
			if !visitedComps[depBy] {
				visitedComps[depBy] = true
				transComps[depBy] = true
				compQueue = append(compQueue, depBy)
			}
		}
	}

	return BlastRadius{
		ChangedFiles:         mapKeysSorted(changedSet),
		DirectImporters:      mapKeysSorted(directImporters),
		TransitiveFiles:      mapKeysSorted(transitiveFiles),
		DirectComponents:     mapKeysSorted(directComps),
		TransitiveDependents: mapKeysSorted(transComps),
	}
}

// primaryOwnerOf picks the single most-specific owning component for a source file
// (preferring specific subsystem roots over root "." catch-all "**").
func primaryOwnerOf(cm *compmap.Map, relFile string) string {
	var best *compmap.Component
	bestScore := -1
	for i := range cm.Components {
		c := &cm.Components[i]
		if !compmap.MatchAnyGlob(c.Paths, relFile) {
			continue
		}
		score := len(c.Root) * 10
		if c.Root == "." && len(c.Paths) == 1 && c.Paths[0] == "**" {
			score = 0
		}
		if c.Provenance == compmap.ProvenanceDeclared {
			score += 2
		}
		if best == nil || score > bestScore || (score == bestScore && c.ID < best.ID) {
			best = c
			bestScore = score
		}
	}
	if best == nil {
		return ""
	}
	return best.ID
}

// MatchesComponentPattern reports whether a boundary selector matches a component ID.
func MatchesComponentPattern(pattern, compID string) bool {
	if pattern == "*" || pattern == "**" || pattern == compID {
		return true
	}
	if ok, err := filepath.Match(pattern, compID); err == nil && ok {
		return true
	}
	return false
}

func classifyCriticality(fanIn, fanOut int) string {
	switch {
	case fanIn >= 4:
		return "hub"
	case fanIn == 0 && fanOut > 0:
		return "entrypoint"
	case fanIn > 0 && fanOut == 0:
		return "leaf"
	case fanIn == 0 && fanOut == 0:
		return "isolated"
	default:
		return "standard"
	}
}

func detectObservedCycles(nodes []NodeMetrics, witnessFn func(u, v string) (ImportSite, bool)) []CycleWitness {
	adj := make(map[string][]string, len(nodes))
	for _, n := range nodes {
		adj[n.ID] = n.ObservedDependsOn
	}

	// Tarjan's algorithm. A node stays on the stack until its entire
	// strongly connected component has been identified.
	index := make(map[string]int, len(nodes))
	low := make(map[string]int, len(nodes))
	onStack := make(map[string]bool, len(nodes))
	stack := make([]string, 0, len(nodes))
	var cycles []CycleWitness
	var visit func(string)
	visit = func(u string) {
		index[u] = len(index) + 1
		low[u] = index[u]
		onStack[u] = true
		stack = append(stack, u)
		for _, v := range adj[u] {
			if index[v] == 0 {
				visit(v)
				low[u] = min(low[u], low[v])
			} else if onStack[v] {
				low[u] = min(low[u], index[v])
			}
		}
		if low[u] != index[u] {
			return
		}

		start := len(stack) - 1
		for stack[start] != u {
			start--
		}
		members := slices.Clone(stack[start:])
		stack = stack[:start]
		for _, member := range members {
			onStack[member] = false
		}
		if len(members) > 1 || slices.Contains(adj[u], u) {
			cycles = append(cycles, describeCycle(adj, members, witnessFn))
		}
	}

	for _, n := range nodes {
		if index[n.ID] == 0 {
			visit(n.ID)
		}
	}
	slices.SortFunc(cycles, func(a, b CycleWitness) int { return slices.Compare(a.Members, b.Members) })
	return cycles
}

func describeCycle(adj map[string][]string, members []string, witnessFn func(u, v string) (ImportSite, bool)) CycleWitness {
	slices.Sort(members)
	internal := make(map[string][]string, len(members))
	for _, u := range members {
		internal[u] = nil
	}
	cycle := CycleWitness{Members: members}
	for _, u := range members {
		for _, v := range adj[u] {
			if _, ok := internal[v]; ok {
				internal[u] = append(internal[u], v)
				cycle.Edges = append(cycle.Edges, CycleEdge{From: u, To: v})
			}
		}
	}
	sortCycleEdges(cycle.Edges)

	// Keep a real directed path for diagnostics. The first internal edge
	// has a return path because both endpoints are in the same SCC.
	first := cycle.Edges[0]
	parent := map[string]string{first.To: ""}
	queue := []string{first.To}
	for i := 0; i < len(queue) && queue[i] != first.From; i++ {
		u := queue[i]
		for _, v := range internal[u] {
			if _, seen := parent[v]; !seen {
				parent[v] = u
				queue = append(queue, v)
			}
		}
	}
	for u := first.From; u != first.To; u = parent[u] {
		cycle.Path = append(cycle.Path, u)
	}
	cycle.Path = append(cycle.Path, first.To)
	slices.Reverse(cycle.Path)
	cycle.Path = append([]string{first.From}, cycle.Path...)
	for i := 1; i < len(cycle.Path); i++ {
		if w, ok := witnessFn(cycle.Path[i-1], cycle.Path[i]); ok {
			cycle.Witnesses = append(cycle.Witnesses, w)
		}
	}
	return cycle
}

// RenderMermaid formats the live observed architecture graph as a clean Mermaid flowchart.
func RenderMermaid(r *Report) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	ids := make(map[string]bool)
	for _, n := range r.Nodes {
		ids[n.ID] = true
	}
	for _, e := range r.Edges {
		ids[e.From], ids[e.To] = true, true
	}
	nodeIDs := make(map[string]string, len(ids))
	used := make(map[string]bool, len(ids))
	for _, id := range mapKeysSorted(ids) {
		base := mermaidID(id)
		safe := base
		for suffix := 2; used[safe]; suffix++ {
			safe = fmt.Sprintf("%s_%d", base, suffix)
		}
		nodeIDs[id], used[safe] = safe, true
	}
	for _, n := range r.Nodes {
		if n.FanIn == 0 && n.FanOut == 0 && n.FileCount == 0 {
			continue
		}
		safeID := nodeIDs[n.ID]
		b.WriteString(fmt.Sprintf("  %s[\"%s (%s, %d files)\"]\n", safeID, n.ID, n.Criticality, n.FileCount))
	}
	for _, e := range r.Edges {
		b.WriteString(fmt.Sprintf("  %s -->|%d| %s\n", nodeIDs[e.From], e.ImportCount, nodeIDs[e.To]))
	}
	return b.String()
}

// RenderText formats a concise AI-first report of the live architecture & boundary checks.
func RenderText(r *Report) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Waypost Architecture Graph (files=%d, imports=%d, edges=%d, cycles=%d, violations=%d, boundaries=%s)\n",
		r.FilesScanned, r.ImportsScanned, len(r.Edges), len(r.Cycles), len(r.Violations), r.BoundariesMode))
	if r.BoundariesMode == "ratchet" {
		fmt.Fprintf(&b, "  baseline: %d grandfathered, %d resolved\n", r.GrandfatheredCount, r.ResolvedBaselineCount)
	}
	if len(r.Hubs) > 0 {
		b.WriteString(fmt.Sprintf("  high_fan_in_hubs: %s\n", strings.Join(r.Hubs, ", ")))
	}

	b.WriteString(fmt.Sprintf("\nSubsystems (%d):\n", len(r.Nodes)))
	for _, n := range r.Nodes {
		if n.FileCount == 0 && n.FanIn == 0 && n.FanOut == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("  - %s [%s, files=%d, fan_in=%d, fan_out=%d]\n", n.ID, n.Criticality, n.FileCount, n.FanIn, n.FanOut))
		if len(n.ObservedDependsOn) > 0 {
			b.WriteString(fmt.Sprintf("      imports:     %s\n", strings.Join(n.ObservedDependsOn, ", ")))
		}
		if len(n.ObservedDependedBy) > 0 {
			b.WriteString(fmt.Sprintf("      imported_by: %s\n", strings.Join(n.ObservedDependedBy, ", ")))
		}
		if len(n.UndeclaredImports) > 0 {
			b.WriteString(fmt.Sprintf("      undeclared:  %s\n", strings.Join(n.UndeclaredImports, ", ")))
		}
	}

	if len(r.Cycles) > 0 {
		b.WriteString(fmt.Sprintf("\nLive Import Cycles (%d):\n", len(r.Cycles)))
		for _, c := range r.Cycles {
			fmt.Fprintf(&b, "  - %s (witness: %s)\n", strings.Join(c.Members, ", "), strings.Join(c.Path, " -> "))
			for _, w := range c.Witnesses {
				b.WriteString(fmt.Sprintf("      at %s:%d (%q -> %s)\n", w.File, w.Line, w.Specifier, w.TargetFile))
			}
		}
	}

	if r.BoundariesMode == "off" && len(r.ScanErrors) > 0 {
		b.WriteString("\nScan errors:\n")
		for _, err := range r.ScanErrors {
			fmt.Fprintf(&b, "  - %s\n", err)
		}
	}
	if len(r.Violations) > 0 {
		b.WriteString(fmt.Sprintf("\nBoundary Violations (%d):\n", len(r.Violations)))
		maxShow := 30
		for i, v := range r.Violations {
			if i >= maxShow {
				b.WriteString(fmt.Sprintf("  ... +%d more violations\n", len(r.Violations)-maxShow))
				break
			}
			b.WriteString(fmt.Sprintf("  - [%s/%s] %s: %s\n", v.Severity, v.Kind, v.RuleID, v.Message))
		}
	}

	if r.Blast != nil {
		b.WriteString("\nBlast Radius (--changed):\n")
		b.WriteString(fmt.Sprintf("  changed_files:        %d\n", len(r.Blast.ChangedFiles)))
		b.WriteString(fmt.Sprintf("  direct_importers:     %d\n", len(r.Blast.DirectImporters)))
		b.WriteString(fmt.Sprintf("  transitive_files:     %d\n", len(r.Blast.TransitiveFiles)))
		if len(r.Blast.DirectComponents) > 0 {
			b.WriteString(fmt.Sprintf("  direct_components:    %s\n", strings.Join(r.Blast.DirectComponents, ", ")))
		}
		if len(r.Blast.TransitiveDependents) > 0 {
			b.WriteString(fmt.Sprintf("  transitive_dependents:%s\n", " "+strings.Join(r.Blast.TransitiveDependents, ", ")))
		}
		if len(r.Blast.DirectImporters) > 0 {
			limit := len(r.Blast.DirectImporters)
			if limit > 15 {
				limit = 15
			}
			b.WriteString("  directly_affected_files:\n")
			for _, f := range r.Blast.DirectImporters[:limit] {
				b.WriteString("    - " + f + "\n")
			}
			if len(r.Blast.DirectImporters) > limit {
				b.WriteString(fmt.Sprintf("    ... +%d more\n", len(r.Blast.DirectImporters)-limit))
			}
		}
	}

	return b.String()
}

func mermaidID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	id := b.String()
	if id == "" || id == "end" {
		return "component_" + id
	}
	return id
}

func mapKeysSorted(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
