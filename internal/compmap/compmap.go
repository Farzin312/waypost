package compmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/shellcmd"
)

// Provenance labels how a component or dependency edge was discovered.
const (
	ProvenanceDeclared     = "declared"
	ProvenanceInferred     = "inferred"
	ProvenanceToolObserved = "tool-observed"
)

// BuildOptions controls optional external provider execution during component map construction.
type BuildOptions struct {
	Context                 context.Context
	SkipInventoryOwnership  bool
	AllowProviders          bool
	AllowedProviderCommands map[string]string
	View                    *repoview.View
	AllowedFiles            map[string]bool // nil permits all static discovery inputs
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

// Map is the complete component map and ecosystem inventory for a repository.
// DiscoveryError describes a present manifest that could not be read or parsed.
type DiscoveryError struct {
	Path string
	Err  error
}

func (e DiscoveryError) Error() string { return fmt.Sprintf("manifest %s: %v", e.Path, e.Err) }

type Map struct {
	DiscoveryErrors  []DiscoveryError      `json:"-"`
	PinInputs        map[string][]string   `json:"-"`
	Components       []Component           `json:"components"`
	Pins             []config.CrossRepoPin `json:"pins,omitempty"`
	Ecosystem        EcosystemInfo         `json:"ecosystem"`
	UnmappedPaths    []string              `json:"unmapped_paths,omitempty"`
	CoverageGaps     []string              `json:"coverage_gaps,omitempty"`
	ownerCache       *sync.Map
	ownerPaths       [][]Glob
	ProviderStatuses []ProviderStatus `json:"provider_statuses,omitempty"`
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

// Build constructs a Component Map with safe defaults (providers disabled).
func Build(repoDir string, cfg *config.Config, trackedFiles []string) (*Map, error) {
	return BuildWithOptions(repoDir, cfg, trackedFiles, BuildOptions{})
}

// BuildWithOptions constructs a Component Map by combining:
// 1. Safe static manifest inference (zero code execution),
// 2. Native read-only `.bounds/manifests/*.yaml` subsystem graphs when present (tool-observed),
// 3. Declared components & pins from effective .waypost.yaml (authoritative overlay),
// 4. Optional authorized external providers ONLY when opts.AllowProviders is true,
// 5. Reverse-dependency graph ("what builds on what"), cycle detection, ecosystem scan, and coverage audit.
func BuildWithOptions(repoDir string, cfg *config.Config, trackedFiles []string, opts BuildOptions) (*Map, error) {
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Component)
	byRoot := make(map[string]string)
	read := func(rel string, max int) ([]byte, error) {
		return ReadBoundedRegularFile(absRepo, filepath.Join(absRepo, rel), max)
	}
	if opts.View != nil {
		opts.AllowedFiles = opts.View.Inventory()
		read = opts.View.Read
	}
	var discoveryErrors []DiscoveryError
	inferred, gaps, err := inferManifests(absRepo, opts.AllowedFiles, opts.View, read, &discoveryErrors)
	if err != nil {
		return nil, err
	}
	var eco EcosystemInfo
	if opts.View != nil {
		eco = inspectViewEcosystem(opts.View)
	} else {
		eco = inspectEcosystem(absRepo)
	}
	for _, c := range inferred {
		byID[c.ID] = c
		byRoot[normalizeRoot(c.Root)] = c.ID
	}

	// Merge static legacy subsystem declarations.
	if project, err := loadBoundsProject(absRepo, opts.AllowedFiles, func(_, full string, limit int) ([]byte, error) {
		rel, err := filepath.Rel(absRepo, full)
		if err != nil {
			return nil, err
		}
		return read(filepath.ToSlash(rel), limit)
	}); err == nil {
		gaps = append(gaps, project.Warnings...)
		discoveryErrors = append(discoveryErrors, project.Errors...)
		for _, subsystem := range project.Subsystems {
			c := subsystem.Component
			byID[c.ID] = c
			byRoot[normalizeRoot(c.Root)] = c.ID
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		var diagnostic DiscoveryError
		if !errors.As(err, &diagnostic) {
			diagnostic = DiscoveryError{".bounds/root.yaml", err}
		}
		discoveryErrors = append(discoveryErrors, diagnostic)
	}
	for _, diagnostic := range discoveryErrors {
		gaps = append(gaps, diagnostic.Error())
	}

	// Overlay declared components (declared metadata wins over inferred/tool-observed).
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
				delete(byRoot, normRoot)
			} else if prev, ok := byID[dc.ID]; ok {
				if comp.ManifestFile == "" {
					comp.ManifestFile = prev.ManifestFile
				}
				if comp.Language == "" {
					comp.Language = prev.Language
				}
				if len(comp.Entrypoints) == 0 {
					comp.Entrypoints = prev.Entrypoints
				}
				if dc.DependsOn == nil {
					comp.DependsOn = prev.DependsOn
				}
			}
			if len(comp.Paths) == 0 {
				comp.Paths = defaultPathsForRoot(normRoot)
			}
			byID[comp.ID] = comp
		}
	}

	// Optional external providers (ONLY when authorized AND explicitly allowed).
	var provStatuses []ProviderStatus
	if cfg != nil {
		for _, p := range cfg.Providers {
			ps := runProviderIfAuthorized(absRepo, p, opts, byID)
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

	// Detect cycles in component dependency graph and report transparently.
	gaps = append(gaps, detectComponentCycles(comps)...)
	if len(eco.DuplicateSkillPaths) > 0 {
		gaps = append(gaps, fmt.Sprintf("duplicate non-symlink skill directories found in .claude/skills/ (%d paths) alongside .agents/skills/; consolidate to a single source of truth", len(eco.DuplicateSkillPaths)))
	}

	m := &Map{
		Components:       comps,
		DiscoveryErrors:  discoveryErrors,
		ownerCache:       new(sync.Map),
		ownerPaths:       make([][]Glob, len(comps)),
		Ecosystem:        eco,
		CoverageGaps:     uniqueSorted(gaps),
		ProviderStatuses: provStatuses,
	}
	for i, c := range comps {
		m.ownerPaths[i] = CompileGlobs(c.Paths)
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
	owners, _ := m.pathOwners(relPath)
	return slices.Clone(owners)
}

// PrimaryOwner is the single most specific owner used for architecture edges.
func (m *Map) PrimaryOwner(relPath string) string {
	_, primary := m.pathOwners(relPath)
	return primary
}

type ownership struct {
	all     []string
	primary string
}

func (m *Map) pathOwners(relPath string) ([]string, string) {
	if m.ownerCache != nil {
		if v, ok := m.ownerCache.Load(relPath); ok {
			o := v.(ownership)
			return o.all, o.primary
		}
	}
	var primary string
	best := -1
	var owners, fallback []string
	for i, c := range m.Components {
		var matches bool
		if m.ownerPaths != nil {
			matches = MatchCompiled(m.ownerPaths[i], relPath)
		} else {
			matches = MatchAnyGlob(c.Paths, relPath)
		}
		if !matches {
			continue
		}
		catchAll := c.Root == "." && len(c.Paths) == 1 && c.Paths[0] == "**"
		score := len(c.Root) * 10
		if catchAll {
			score = 0
		}
		if c.Provenance == ProvenanceDeclared {
			score += 2
		}
		if score > best || (score == best && c.ID < primary) {
			primary, best = c.ID, score
		}
		if catchAll && c.Provenance != ProvenanceDeclared {
			fallback = append(fallback, c.ID)
		} else {
			owners = append(owners, c.ID)
		}
	}
	if len(owners) == 0 {
		owners = fallback
	}
	sort.Strings(owners)
	if m.ownerCache != nil {
		m.ownerCache.Store(relPath, ownership{owners, primary})
	}
	return owners, primary
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
		consumer := pin.ConsumerComponent
		if consumer == "" {
			consumer = pin.Consumer
		}
		if directSet[consumer] || depSet[consumer] {
			pinSet[pin.ID] = true
			continue
		}
		for _, p := range changedPaths {
			if m.PinTouched(pin, p) {
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
	comp      Component
	nodePkg   string
	nodeDeps  []string
	localDeps []string // relative repo root dirs (from go.mod replace or Cargo.toml path)
}

// inferManifests walks absRepo safely (read-only, max depth 4) and extracts
// manifest-level components without executing any repository code.
// StaticComponentInput identifies files used to infer component ownership and dependencies.
func StaticComponentInput(rel string) bool {
	switch rel {
	case ".bounds/root.yaml", "tsconfig.json", "requirements.txt":
		return true
	}
	dir, name := filepath.ToSlash(filepath.Dir(rel)), filepath.Base(rel)
	if dir == ".bounds/manifests" {
		return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
	}
	if (dir == "tools" || dir == "scripts") && strings.HasSuffix(name, ".py") {
		return true // presence only
	}
	if dir != "." {
		parts := strings.Split(dir, "/")
		if len(parts) > 4 {
			return false
		}
		for _, part := range parts {
			if skipDirs[part] || strings.HasPrefix(part, ".") {
				return false
			}
		}
	}
	switch name {
	case "go.mod", "package.json", "Cargo.toml", "pyproject.toml":
		return true
	}
	return strings.HasSuffix(name, ".uproject")
}

// PinTouched checks declared and discovered artifact inputs for a pin.
func (m *Map) PinTouched(pin config.CrossRepoPin, path string) bool {
	return slices.Contains(m.PinInputs[pin.ID], path) || PinTouches(pin, path)
}

// PinTouches reports direct artifact/source edits, separately from consumer impact.
func PinTouches(pin config.CrossRepoPin, rel string) bool {
	return (pin.Source != nil && (pin.Source.Manifest == rel ||
		filepath.ToSlash(filepath.Join(filepath.Dir(pin.Source.Manifest), "package-lock.json")) == rel)) ||
		pin.Artifact == rel || MatchAnyGlob(pin.Paths, rel)
}

func inferManifests(absRepo string, allowedFiles map[string]bool, view *repoview.View, read func(string, int) ([]byte, error), discoveryErrors *[]DiscoveryError) ([]Component, []string, error) {
	var items []inferredItem
	var gaps []string
	rootsWithManifest := make(map[string]bool)
	var paths []string
	if allowedFiles != nil {
		paths = mapKeysSorted(allowedFiles)
	} else {
		err := filepath.WalkDir(absRepo, func(full string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(absRepo, full)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel != "." && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") || strings.Count(rel, "/") >= 4) {
					return filepath.SkipDir
				}
				return nil
			}
			paths = append(paths, rel)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	tree := make(map[string]bool, len(paths))
	commands := make(map[string][]string)
	python := make(map[string]int)
	for _, rel := range paths {
		tree[rel] = true
		dir := filepath.ToSlash(filepath.Dir(rel))
		if (dir == "tools" || dir == "scripts") && strings.HasSuffix(rel, ".py") {
			python[dir]++
		}
		if parent := filepath.ToSlash(filepath.Dir(dir)); filepath.Base(parent) == "cmd" && !slices.Contains(commands[filepath.ToSlash(filepath.Dir(parent))], dir) {
			commands[filepath.ToSlash(filepath.Dir(parent))] = append(commands[filepath.ToSlash(filepath.Dir(parent))], dir)
		}
	}
	for _, rel := range paths {
		if !StaticComponentInput(rel) {
			continue
		}
		dirRel := normalizeRoot(filepath.ToSlash(filepath.Dir(rel)))
		base := filepath.Base(rel)
		if !slices.Contains([]string{"go.mod", "package.json", "Cargo.toml", "pyproject.toml"}, base) && !strings.HasSuffix(base, ".uproject") {
			continue
		}
		raw, err := read(rel, MaxStaticDiscoveryBytes)
		if err != nil {
			*discoveryErrors = append(*discoveryErrors, DiscoveryError{rel, err})
			continue
		}
		if base == "package.json" && !json.Valid(raw) {
			*discoveryErrors = append(*discoveryErrors, DiscoveryError{rel, errors.New("malformed JSON")})
			continue
		}
		var item inferredItem
		switch {
		case base == "go.mod":
			item.comp, item.localDeps = parseGoMod(raw, absRepo, dirRel, rel, commands[dirRel])
		case base == "package.json":
			item.comp, item.nodePkg, item.nodeDeps = parsePackageJSON(raw, dirRel, rel, tree[joinRel(dirRel, "tsconfig.json")], view)
		case base == "Cargo.toml":
			item.comp, item.localDeps = parseCargoToml(raw, dirRel, rel)
		case base == "pyproject.toml":
			item.comp = parsePyprojectToml(raw, dirRel, rel)
		default:
			var gap string
			var err error
			item.comp, gap, err = parseUProject(raw, dirRel, rel)
			if err != nil {
				*discoveryErrors = append(*discoveryErrors, DiscoveryError{rel, err})
				continue
			}
			gaps = append(gaps, gap)
		}
		items = append(items, item)
		rootsWithManifest[dirRel] = true
	}
	for _, dir := range []string{"tools", "scripts"} {
		if count := python[dir]; count > 0 && !rootsWithManifest[dir] {
			items = append(items, inferredItem{comp: Component{
				ID: dir + "-python", Root: dir, Kind: "python-tooling", Language: "python",
				Description: fmt.Sprintf("Python scripts/validators in %s/ (%d top-level .py files)", dir, count),
				Paths:       []string{dir + "/**"}, Provenance: ProvenanceInferred,
			}})
		}
	}

	// Assign final deduplicated IDs BEFORE wiring intra-repo dependencies.
	type rootLangKey struct {
		root string
		lang string
	}
	usedIDs := make(map[string]bool, len(items))
	pkgNameToID := make(map[string]string)
	rootLangToID := make(map[rootLangKey]string)
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
		rlk := rootLangKey{root: normalizeRoot(items[i].comp.Root), lang: items[i].comp.Language}
		if _, exists := rootLangToID[rlk]; !exists {
			rootLangToID[rlk] = id
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
		}
		if len(items[i].localDeps) > 0 {
			for _, depRoot := range items[i].localDeps {
				rlk := rootLangKey{root: normalizeRoot(depRoot), lang: items[i].comp.Language}
				if targetID, exists := rootLangToID[rlk]; exists && targetID != items[i].comp.ID {
					items[i].comp.DependsOn = append(items[i].comp.DependsOn, targetID)
				}
			}
		}
		items[i].comp.DependsOn = uniqueSorted(items[i].comp.DependsOn)
		comps = append(comps, items[i].comp)
	}

	return comps, gaps, nil
}

func parseGoMod(raw []byte, repoRoot, dirRel, rel string, entrypoints []string) (Component, []string) {
	modName := ""
	var localDeps []string
	if raw != nil {
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		inReplace := false
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if idx := strings.Index(line, "//"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "module ") {
				modName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			} else if strings.HasPrefix(line, "replace (") {
				inReplace = true
			} else if inReplace && line == ")" {
				inReplace = false
			} else if inReplace || strings.HasPrefix(line, "replace ") {
				spec := strings.TrimPrefix(line, "replace ")
				if parts := strings.Split(spec, "=>"); len(parts) == 2 {
					rhs := strings.TrimSpace(parts[1])
					fields := strings.Fields(rhs)
					if len(fields) >= 1 {
						target := strings.Trim(fields[0], `"`)
						if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
							joined := filepath.ToSlash(filepath.Clean(filepath.Join(dirRel, target)))
							if !strings.HasPrefix(joined, "../") && joined != ".." {
								localDeps = append(localDeps, joined)
							}
						} else if filepath.IsAbs(target) {
							if relTarget, err := filepath.Rel(repoRoot, target); err == nil {
								relSlash := filepath.ToSlash(filepath.Clean(relTarget))
								if !strings.HasPrefix(relSlash, "../") && relSlash != ".." {
									localDeps = append(localDeps, relSlash)
								}
							}
						}
					}
				}
			}
		}
	}
	id := slugFromRootOrName(dirRel, filepath.Base(modName), "go-module")

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
	}, localDeps
}

func parsePackageJSON(raw []byte, dirRel, rel string, tsconfig bool, view *repoview.View) (Component, string, []string) {
	type pkgJSON struct {
		Name            string            `json:"name"`
		Main            string            `json:"main"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var pj pkgJSON
	if view == nil || !view.CachedParse(rel, "package.json", &pj) {
		if json.Unmarshal(raw, &pj) == nil && view != nil {
			view.CacheParse(rel, "package.json", pj)
		}
	}
	id := slugFromRootOrName(dirRel, pj.Name, "node-package")
	var eps []string
	if pj.Main != "" {
		eps = append(eps, joinRel(dirRel, pj.Main))
	}
	lang := "javascript"
	if tsconfig {
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

var cargoPathDepRE = regexp.MustCompile(`\bpath\s*=\s*(?:"([^"]+)"|'([^']+)')`)

func isCargoDepSection(section string) bool {
	s := strings.TrimSpace(section)
	if s == "dependencies" || s == "dev-dependencies" || s == "build-dependencies" || s == "workspace.dependencies" {
		return true
	}
	return strings.HasSuffix(s, ".dependencies") || strings.HasSuffix(s, ".dev-dependencies") || strings.HasSuffix(s, ".build-dependencies") ||
		strings.HasPrefix(s, "dependencies.") || strings.HasPrefix(s, "dev-dependencies.") || strings.HasPrefix(s, "build-dependencies.")
}

func parseCargoToml(raw []byte, dirRel, rel string) (Component, []string) {
	name := extractTomlName(raw)
	var localDeps []string
	if raw != nil {
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		inDepSection := false
		for sc.Scan() {
			line := sc.Text()
			if idx := strings.IndexByte(line, '#'); idx >= 0 {
				line = line[:idx]
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				sec := strings.Trim(trimmed, "[]")
				inDepSection = isCargoDepSection(sec)
				continue
			}
			if !inDepSection {
				continue
			}
			for _, m := range cargoPathDepRE.FindAllStringSubmatch(trimmed, -1) {
				depPath := m[1]
				if depPath == "" {
					depPath = m[2]
				}
				if depPath != "" {
					joined := filepath.ToSlash(filepath.Clean(filepath.Join(dirRel, depPath)))
					if !strings.HasPrefix(joined, "../") && joined != ".." {
						localDeps = append(localDeps, joined)
					}
				}
			}
		}
	}
	return Component{
		ID:           slugFromRootOrName(dirRel, name, "rust-crate"),
		Root:         dirRel,
		Kind:         "crate",
		Language:     "rust",
		Description:  name,
		Paths:        defaultPathsForRoot(dirRel),
		ManifestFile: rel,
		Provenance:   ProvenanceInferred,
	}, localDeps
}

func parsePyprojectToml(raw []byte, dirRel, rel string) Component {
	name := extractTomlName(raw)
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

func parseUProject(raw []byte, dirRel, rel string) (Component, string, error) {
	type uModule struct {
		Name string `json:"Name"`
		Type string `json:"Type"`
	}
	type uProj struct {
		EngineAssociation string    `json:"EngineAssociation"`
		Modules           []uModule `json:"Modules"`
	}
	var up *uProj
	if err := json.Unmarshal(raw, &up); err != nil {
		return Component{}, "", err
	}
	if up == nil {
		return Component{}, "", errors.New("expected an Unreal project object")
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
	}, gap, nil
}

func extractTomlName(raw []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
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
	parent := opts.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cmd := shellcmd.CommandContext(ctx, p.Command)
	cmd.Dir = repoDir
	cmd.Env = shellcmd.Environment()
	out, err := boundedProviderOutput(cmd)
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

// Cap provider output before JSON decoding.
func boundedProviderOutput(cmd *exec.Cmd) ([]byte, error) {
	var data providerOutput
	cmd.Stdout = &data
	if err := shellcmd.Run(cmd); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		return nil, err
	}
	return data.Bytes(), nil
}

type providerOutput struct{ bytes.Buffer }

func (p *providerOutput) Write(data []byte) (int, error) {
	const maxOutput = 1 << 20
	room := maxOutput - p.Len()
	if len(data) > room {
		n, _ := p.Buffer.Write(data[:room])
		return n, fmt.Errorf("provider output exceeds %d bytes", maxOutput)
	}
	return p.Buffer.Write(data)
}
