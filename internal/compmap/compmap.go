package compmap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Farzin312/waypost/internal/config"
)

// Provenance labels how a component or dependency edge was discovered.
const (
	ProvenanceDeclared     = "declared"
	ProvenanceInferred     = "inferred"
	ProvenanceToolObserved = "tool-observed"
)

// BuildOptions controls optional external provider execution during component map construction.
type BuildOptions struct {
	// AllowProviders must be true (after lock/policy validation) for any authorized
	// external provider to execute. Defaults to false (safe read-only static inference).
	AllowProviders bool
	// AllowedProviderCommands optionally restricts execution in CI mode to exact
	// provider ID -> command pairs approved by the trusted base policy.
	AllowedProviderCommands map[string]string
}

// Component is one node in the repository's "what builds on what" map.
type Component struct {
	ID           string   `json:"id"`
	Root         string   `json:"root"`
	Kind         string   `json:"kind,omitempty"`
	Language     string   `json:"language,omitempty"`
	Description  string   `json:"description,omitempty"`
	DependsOn    []string `json:"depends_on,omitempty"`
	DependedBy   []string `json:"depended_by,omitempty"`
	Entrypoints  []string `json:"entrypoints,omitempty"`
	TrustPaths   []string `json:"trust_paths,omitempty"`
	Checks       []string `json:"checks,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	ManifestFile string   `json:"manifest_file,omitempty"`
	Provenance   string   `json:"provenance"` // declared | inferred | tool-observed
}

// ProviderStatus records whether an external graph provider ran or why it did not.
type ProviderStatus struct {
	ID         string `json:"id"`
	Tool       string `json:"tool"`
	Authorized bool   `json:"authorized"`
	Executed   bool   `json:"executed"`
	Note       string `json:"note"`
}

// Map is the complete component map for a repository.
type Map struct {
	Components       []Component           `json:"components"`
	Pins             []config.CrossRepoPin `json:"pins,omitempty"`
	UnmappedPaths    []string              `json:"unmapped_paths,omitempty"`
	CoverageGaps     []string              `json:"coverage_gaps,omitempty"`
	ProviderStatuses []ProviderStatus      `json:"provider_statuses,omitempty"`
}

// Impact summarizes what components, reverse dependents, and cross-repo pins are
// affected by a set of changed paths.
type Impact struct {
	DirectComponents     []string `json:"direct_components,omitempty"`
	TransitiveDependents []string `json:"transitive_dependents,omitempty"`
	TriggeredPins        []string `json:"triggered_pins,omitempty"`
	UnmappedPaths        []string `json:"unmapped_paths,omitempty"`
}

var skipDirs = map[string]bool{
	".git":             true,
	"node_modules":     true,
	"vendor":           true,
	".next":            true,
	".expo":            true,
	"dist":             true,
	"build":            true,
	"Binaries":         true,
	"Intermediate":     true,
	"Saved":            true,
	"DerivedDataCache": true,
	".venv":            true,
	"__pycache__":      true,
	"target":           true,
}

// Build constructs a Component Map with safe defaults (providers disabled unless BuildWithOptions enables them).
func Build(repoDir string, cfg *config.Config, trackedFiles []string) (*Map, error) {
	return BuildWithOptions(repoDir, cfg, trackedFiles, BuildOptions{})
}

// BuildWithOptions constructs a Component Map by combining:
// 1. Safe static manifest inference (no repo code execution),
// 2. Declared components and pins from effective .waypost.yaml (authoritative overlay),
// 3. Optional authorized external providers ONLY when opts.AllowProviders is true,
// 4. Reverse-dependency graph ("what builds on what") and coverage-gap audit.
func BuildWithOptions(repoDir string, cfg *config.Config, trackedFiles []string, opts BuildOptions) (*Map, error) {
	inferred, gaps, err := inferManifests(repoDir)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Component)
	byRoot := make(map[string]string)

	for _, c := range inferred {
		byID[c.ID] = c
		byRoot[normalizeRoot(c.Root)] = c.ID
	}

	// Overlay declared components (declared metadata wins over inferred).
	if cfg != nil {
		gaps = append(gaps, cfg.CoverageGaps...)
		for _, dc := range cfg.Components {
			normRoot := normalizeRoot(dc.Root)
			comp := Component{
				ID:          dc.ID,
				Root:        normRoot,
				Kind:        dc.Kind,
				Language:    dc.Language,
				Description: dc.Description,
				DependsOn:   uniqueSorted(dc.DependsOn),
				Entrypoints: uniqueSorted(dc.Entrypoints),
				TrustPaths:  uniqueSorted(dc.TrustPaths),
				Checks:      uniqueSorted(dc.Checks),
				Paths:       dc.Paths,
				Provenance:  ProvenanceDeclared,
			}
			if prevID, ok := byRoot[normRoot]; ok && prevID != dc.ID {
				prev := byID[prevID]
				if comp.ManifestFile == "" {
					comp.ManifestFile = prev.ManifestFile
				}
				if comp.Language == "" {
					comp.Language = prev.Language
				}
				if len(comp.Entrypoints) == 0 {
					comp.Entrypoints = prev.Entrypoints
				}
				delete(byID, prevID)
			} else if prev, ok := byID[dc.ID]; ok {
				if comp.ManifestFile == "" {
					comp.ManifestFile = prev.ManifestFile
				}
				if comp.Language == "" {
					comp.Language = prev.Language
				}
			}
			if len(comp.Paths) == 0 {
				comp.Paths = defaultPathsForRoot(normRoot)
			}
			byID[comp.ID] = comp
			byRoot[normRoot] = comp.ID
		}
	}

	// Optional external providers (ONLY when authorized AND explicitly allowed after lock/policy checks).
	var provStatuses []ProviderStatus
	if cfg != nil {
		for _, p := range cfg.Providers {
			ps := runProviderIfAuthorized(repoDir, p, opts, byID)
			provStatuses = append(provStatuses, ps)
		}
	}

	// Compute reverse dependencies ("what builds on this").
	rev := make(map[string][]string)
	for _, c := range byID {
		for _, dep := range c.DependsOn {
			rev[dep] = append(rev[dep], c.ID)
		}
	}
	comps := make([]Component, 0, len(byID))
	for _, c := range byID {
		c.DependsOn = uniqueSorted(c.DependsOn)
		c.DependedBy = uniqueSorted(rev[c.ID])
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].ID < comps[j].ID })

	m := &Map{
		Components:       comps,
		CoverageGaps:     uniqueSorted(gaps),
		ProviderStatuses: provStatuses,
	}
	if cfg != nil {
		m.Pins = append([]config.CrossRepoPin(nil), cfg.Pins...)
	}

	if len(trackedFiles) > 0 {
		for _, f := range trackedFiles {
			if len(m.OwnersOf(f)) == 0 {
				m.UnmappedPaths = append(m.UnmappedPaths, f)
			}
		}
		sort.Strings(m.UnmappedPaths)
	}
	if len(comps) == 0 {
		m.CoverageGaps = uniqueSorted(append(m.CoverageGaps,
			"no components inferred or declared; declare components in .waypost.yaml for path-scoped context and verification"))
	}

	return m, nil
}

// OwnersOf returns component IDs whose declared/inferred paths match relPath.
func (m *Map) OwnersOf(relPath string) []string {
	relPath = strings.TrimPrefix(filepath.ToSlash(relPath), "./")
	var exactMatches []Component
	var rootCatchAll []Component
	for _, c := range m.Components {
		if MatchAnyGlob(c.Paths, relPath) {
			if c.Root == "." && len(c.Paths) == 1 && c.Paths[0] == "**" {
				rootCatchAll = append(rootCatchAll, c)
			} else {
				exactMatches = append(exactMatches, c)
			}
		}
	}
	chosen := exactMatches
	if len(chosen) == 0 {
		chosen = rootCatchAll
	}
	ids := make([]string, 0, len(chosen))
	for _, c := range chosen {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	return ids
}

// ImpactedByPaths computes direct component hits, transitive reverse dependents
// ("what builds on what changed"), triggered cross-repo pins, and unmapped paths.
func (m *Map) ImpactedByPaths(changedPaths []string) Impact {
	directSet := make(map[string]bool)
	var unmapped []string
	for _, p := range changedPaths {
		owners := m.OwnersOf(p)
		if len(owners) == 0 {
			unmapped = append(unmapped, p)
			continue
		}
		for _, id := range owners {
			directSet[id] = true
		}
	}

	rev := make(map[string][]string, len(m.Components))
	for _, c := range m.Components {
		rev[c.ID] = c.DependedBy
	}

	depSet := make(map[string]bool)
	queue := make([]string, 0, len(directSet))
	for id := range directSet {
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, parent := range rev[curr] {
			if !directSet[parent] && !depSet[parent] {
				depSet[parent] = true
				queue = append(queue, parent)
			}
		}
	}

	pinSet := make(map[string]bool)
	for _, pin := range m.Pins {
		if directSet[pin.Consumer] || depSet[pin.Consumer] {
			pinSet[pin.ID] = true
			continue
		}
		for _, p := range changedPaths {
			if MatchAnyGlob(pin.Paths, p) {
				pinSet[pin.ID] = true
				break
			}
		}
	}

	return Impact{
		DirectComponents:     mapKeysSorted(directSet),
		TransitiveDependents: mapKeysSorted(depSet),
		TriggeredPins:        mapKeysSorted(pinSet),
		UnmappedPaths:        uniqueSorted(unmapped),
	}
}

type inferredItem struct {
	comp       Component
	nodePkg    string
	nodeDeps   []string
}

// inferManifests walks repoDir safely (read-only, max depth 4) and extracts
// manifest-level components without executing any repository code.
func inferManifests(repoDir string) ([]Component, []string, error) {
	var items []inferredItem
	var gaps []string

	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, nil, err
	}

	err = filepath.WalkDir(absRepo, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, err := filepath.Rel(absRepo, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			name := d.Name()
			if rel != "." && (skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".")) {
				return filepath.SkipDir
			}
			if rel != "." && strings.Count(rel, "/") >= 4 {
				return filepath.SkipDir
			}
			return nil
		}

		dirRel := normalizeRoot(filepath.ToSlash(filepath.Dir(rel)))
		base := d.Name()

		switch {
		case base == "go.mod":
			items = append(items, inferredItem{comp: parseGoMod(p, absRepo, dirRel, rel)})
		case base == "package.json":
			c, pkgName, deps := parsePackageJSON(p, dirRel, rel)
			items = append(items, inferredItem{comp: c, nodePkg: pkgName, nodeDeps: deps})
		case base == "Cargo.toml":
			items = append(items, inferredItem{comp: parseCargoToml(p, dirRel, rel)})
		case base == "pyproject.toml":
			items = append(items, inferredItem{comp: parsePyprojectToml(p, dirRel, rel)})
		case strings.HasSuffix(base, ".uproject"):
			c, gap := parseUProject(p, dirRel, rel)
			items = append(items, inferredItem{comp: c})
			if gap != "" {
				gaps = append(gaps, gap)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Assign final deduplicated IDs BEFORE wiring intra-repo Node package dependencies
	// so two manifests sharing a name (e.g. Cargo crate + package.json) never collide.
	usedIDs := make(map[string]bool, len(items))
	pkgNameToID := make(map[string]string)
	for i := range items {
		id := items[i].comp.ID
		if usedIDs[id] {
			cand := fmt.Sprintf("%s-%s", id, items[i].comp.Language)
			if usedIDs[cand] {
				for n := 2; ; n++ {
					alt := fmt.Sprintf("%s-%d", cand, n)
					if !usedIDs[alt] {
						cand = alt
						break
					}
				}
			}
			id = cand
			items[i].comp.ID = id
		}
		usedIDs[id] = true
		if items[i].nodePkg != "" {
			pkgNameToID[items[i].nodePkg] = id
		}
	}

	comps := make([]Component, 0, len(items))
	for i := range items {
		if len(items[i].nodeDeps) > 0 {
			for _, depName := range items[i].nodeDeps {
				if targetID, exists := pkgNameToID[depName]; exists && targetID != items[i].comp.ID {
					items[i].comp.DependsOn = append(items[i].comp.DependsOn, targetID)
				}
			}
			items[i].comp.DependsOn = uniqueSorted(items[i].comp.DependsOn)
		}
		comps = append(comps, items[i].comp)
	}

	return comps, gaps, nil
}

func parseGoMod(fullPath, repoRoot, dirRel, rel string) Component {
	modName := ""
	f, err := os.Open(fullPath)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "module ") {
				modName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
				break
			}
		}
	}
	id := slugFromRootOrName(dirRel, filepath.Base(modName), "go-module")
	var entrypoints []string
	cmdDir := filepath.Join(filepath.Dir(fullPath), "cmd")
	if entries, err := os.ReadDir(cmdDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				ep := filepath.ToSlash(filepath.Join(dirRel, "cmd", e.Name()))
				if dirRel == "." {
					ep = "cmd/" + e.Name()
				}
				entrypoints = append(entrypoints, ep)
			}
		}
	}
	return Component{
		ID:           id,
		Root:         dirRel,
		Kind:         "go-module",
		Language:     "go",
		Description:  modName,
		Entrypoints:  entrypoints,
		Paths:        defaultPathsForRoot(dirRel),
		ManifestFile: rel,
		Provenance:   ProvenanceInferred,
	}
}

func parsePackageJSON(fullPath, dirRel, rel string) (Component, string, []string) {
	type pkgJSON struct {
		Name            string            `json:"name"`
		Main            string            `json:"main"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var pj pkgJSON
	if raw, err := os.ReadFile(fullPath); err == nil {
		_ = json.Unmarshal(raw, &pj)
	}
	id := slugFromRootOrName(dirRel, pj.Name, "node-package")
	var eps []string
	if pj.Main != "" {
		eps = append(eps, joinRel(dirRel, pj.Main))
	}
	lang := "javascript"
	if _, err := os.Stat(filepath.Join(filepath.Dir(fullPath), "tsconfig.json")); err == nil {
		lang = "typescript"
	} else if _, ok := pj.DevDependencies["typescript"]; ok {
		lang = "typescript"
	}
	var allDeps []string
	for k := range pj.Dependencies {
		allDeps = append(allDeps, k)
	}
	for k := range pj.DevDependencies {
		allDeps = append(allDeps, k)
	}
	return Component{
		ID:           id,
		Root:         dirRel,
		Kind:         "package",
		Language:     lang,
		Description:  pj.Name,
		Entrypoints:  eps,
		Paths:        defaultPathsForRoot(dirRel),
		ManifestFile: rel,
		Provenance:   ProvenanceInferred,
	}, pj.Name, allDeps
}

func parseCargoToml(fullPath, dirRel, rel string) Component {
	name := extractTomlName(fullPath)
	return Component{
		ID:           slugFromRootOrName(dirRel, name, "rust-crate"),
		Root:         dirRel,
		Kind:         "crate",
		Language:     "rust",
		Description:  name,
		Paths:        defaultPathsForRoot(dirRel),
		ManifestFile: rel,
		Provenance:   ProvenanceInferred,
	}
}

func parsePyprojectToml(fullPath, dirRel, rel string) Component {
	name := extractTomlName(fullPath)
	return Component{
		ID:           slugFromRootOrName(dirRel, name, "python-package"),
		Root:         dirRel,
		Kind:         "python-package",
		Language:     "python",
		Description:  name,
		Paths:        defaultPathsForRoot(dirRel),
		ManifestFile: rel,
		Provenance:   ProvenanceInferred,
	}
}

func parseUProject(fullPath, dirRel, rel string) (Component, string) {
	type uModule struct {
		Name string `json:"Name"`
		Type string `json:"Type"`
	}
	type uProj struct {
		EngineAssociation string    `json:"EngineAssociation"`
		Modules           []uModule `json:"Modules"`
	}
	var up uProj
	if raw, err := os.ReadFile(fullPath); err == nil {
		_ = json.Unmarshal(raw, &up)
	}
	baseName := strings.TrimSuffix(filepath.Base(rel), ".uproject")
	var eps []string
	for _, m := range up.Modules {
		if m.Name != "" {
			eps = append(eps, joinRel(dirRel, "Source/"+m.Name))
		}
	}
	gap := fmt.Sprintf("Unreal project %s (%s): static inference reads .uproject metadata only; C++ Build.cs graphs, Blueprints, shaders, and binary assets require declared checks or engine tools", rel, up.EngineAssociation)
	return Component{
		ID:           slugFromRootOrName(dirRel, baseName, "unreal-project"),
		Root:         dirRel,
		Kind:         "unreal-project",
		Language:     "cpp",
		Description:  fmt.Sprintf("Unreal Engine %s project (%s)", up.EngineAssociation, baseName),
		Entrypoints:  eps,
		Paths:        defaultPathsForRoot(dirRel),
		ManifestFile: rel,
		Provenance:   ProvenanceInferred,
	}, gap
}

func extractTomlName(fullPath string) string {
	f, err := os.Open(fullPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "name") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			if val != "" {
				return val
			}
		}
	}
	return ""
}

// runProviderIfAuthorized executes an external read-only architecture provider ONLY
// when explicitly authorized in config AND allowed by verified lock/policy options.
func runProviderIfAuthorized(repoDir string, p config.ProviderConfig, opts BuildOptions, byID map[string]Component) ProviderStatus {
	ps := ProviderStatus{
		ID:         p.ID,
		Tool:       p.Tool,
		Authorized: p.Authorized,
	}
	if !p.Authorized {
		ps.Note = "not authorized (set authorized: true and update .waypost.lock to run)"
		return ps
	}
	if !opts.AllowProviders {
		ps.Note = "blocked: lockfile or policy verification required before executing authorized providers"
		return ps
	}
	if opts.AllowedProviderCommands != nil {
		allowedCmd, ok := opts.AllowedProviderCommands[p.ID]
		if !ok || allowedCmd != p.Command {
			ps.Note = "blocked: provider not approved with this command in trusted base policy"
			return ps
		}
	}
	if p.Tool != "" {
		if _, err := exec.LookPath(p.Tool); err != nil {
			ps.Note = fmt.Sprintf("tool %q not found in PATH", p.Tool)
			return ps
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", p.Command)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		ps.Note = fmt.Sprintf("provider execution failed: %v", err)
		return ps
	}
	ps.Executed = true

	var payload struct {
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		ps.Note = "executed, but JSON output did not contain standard {edges:[{from,to}]} structure"
		return ps
	}
	added := 0
	for _, e := range payload.Edges {
		if c, ok := byID[e.From]; ok && e.To != "" && e.To != e.From {
			c.DependsOn = uniqueSorted(append(c.DependsOn, e.To))
			if c.Provenance == ProvenanceInferred {
				c.Provenance = ProvenanceToolObserved
			}
			byID[e.From] = c
			added++
		}
	}
	ps.Note = fmt.Sprintf("executed successfully; merged %d tool-observed edges", added)
	return ps
}

func normalizeRoot(r string) string {
	r = strings.TrimSpace(filepath.ToSlash(r))
	if r == "" || r == "./" || r == "." {
		return "."
	}
	return strings.Trim(r, "/")
}

func defaultPathsForRoot(root string) []string {
	if root == "." {
		return []string{"**"}
	}
	return []string{root + "/**"}
}

func joinRel(root, sub string) string {
	sub = strings.TrimPrefix(filepath.ToSlash(sub), "./")
	if root == "." {
		return sub
	}
	return root + "/" + sub
}

func slugFromRootOrName(root, name, fallback string) string {
	cand := name
	if cand == "" && root != "." {
		cand = root
	}
	if cand == "" {
		cand = fallback
	}
	cand = strings.ToLower(cand)
	cand = strings.TrimPrefix(cand, "@")
	var b strings.Builder
	prevDash := false
	for _, r := range cand {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return fallback
	}
	return res
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
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
