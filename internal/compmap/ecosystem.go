package compmap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const MaxStaticDiscoveryBytes = 512 * 1024 // 512 KiB per static manifest/skill file

// DiscoveredSkill describes a local AAIF SKILL.md discovered under .agents/skills/
// without executing any code.
type DiscoveredSkill struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

// EcosystemInfo summarizes detected agent standards and verification tooling in the repo.
type EcosystemInfo struct {
	HasAgentsMD         bool              `json:"has_agents_md"`
	HasClaudeMD         bool              `json:"has_claude_md"`
	HasBounds           bool              `json:"has_bounds"`
	HasGitleaks         bool              `json:"has_gitleaks"`
	HasGitHubWorkflows  bool              `json:"has_github_workflows"`
	PackageManager      string            `json:"package_manager,omitempty"`
	DiscoveredSkills    []DiscoveredSkill `json:"discovered_skills,omitempty"`
	DuplicateSkillPaths []string          `json:"duplicate_skill_paths,omitempty"`
}

type BoundsInterface struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"`
	Path string `yaml:"path"`
	File string `yaml:"file"`
}

func (i *BoundsInterface) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&i.Name)
	}
	type mapping BoundsInterface
	return node.Decode((*mapping)(i))
}

type boundsConsume struct {
	Subsystem string `yaml:"subsystem"`
}

func (c *boundsConsume) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&c.Subsystem)
	}
	type mapping boundsConsume
	return node.Decode((*mapping)(c))
}

type boundsManifestYAML struct {
	Name        string            `yaml:"name"`
	Role        string            `yaml:"role"`
	Description string            `yaml:"description"`
	Paths       []string          `yaml:"paths"`
	Files       []string          `yaml:"files"`
	Consumes    []boundsConsume   `yaml:"consumes"`
	Exposes     []BoundsInterface `yaml:"exposes"`
}

type BoundsSubsystem struct {
	Component Component
	Exposes   []BoundsInterface
}

type BoundsProject struct {
	Enforce    string
	Subsystems []BoundsSubsystem
	Warnings   []string
}

func insideRepo(absRepo, targetPath string) error {
	repo, err := filepath.EvalSymlinks(absRepo)
	if err != nil {
		return err
	}
	target, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(repo, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q resolves outside repository", targetPath)
	}
	return nil
}

// ReadBoundedRegularFile reads a regular file inside the repository up to maxBytes.
func ReadBoundedRegularFile(absRepo, targetPath string, maxBytes int) ([]byte, error) {
	info, err := os.Lstat(targetPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", targetPath)
	}
	if err := insideRepo(absRepo, targetPath); err != nil {
		return nil, err
	}
	if info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("%q exceeds %d bytes", targetPath, maxBytes)
	}
	rel, err := filepath.Rel(absRepo, targetPath)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenInRoot(absRepo, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%q changed while opening", targetPath)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("%q exceeds %d bytes", targetPath, maxBytes)
	}
	return raw, nil
}

// ReadSameRepoRegularFile follows symlinks for explicit legacy migration.
func ReadSameRepoRegularFile(repo, filename string, maxBytes int) ([]byte, error) {
	resolvedRepo, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filename); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve legacy file %q: %v", filename, err)
	}
	if err := insideRepo(resolvedRepo, resolved); err != nil {
		return nil, err
	}
	if resolved == resolvedRepo {
		return nil, fmt.Errorf("%q resolves to the repository directory", filename)
	}
	return ReadBoundedRegularFile(resolvedRepo, resolved, maxBytes)
}

// LoadBoundsProject reads legacy manifests and retains their interface metadata for migration.
func LoadBoundsProject(absRepo string, allowedFiles map[string]bool) (*BoundsProject, error) {
	return loadBoundsProject(absRepo, allowedFiles, ReadBoundedRegularFile)
}

func LoadBoundsProjectForMigration(absRepo string) (*BoundsProject, error) {
	return loadBoundsProject(absRepo, nil, ReadSameRepoRegularFile)
}

func loadBoundsProject(absRepo string, allowedFiles map[string]bool, readManifest func(string, string, int) ([]byte, error)) (*BoundsProject, error) {
	result := &BoundsProject{}
	var root struct {
		Enforce    string   `yaml:"enforce"`
		Subsystems []string `yaml:"subsystems"`
	}
	const rootFile = ".bounds/root.yaml"
	if allowedFiles == nil || allowedFiles[rootFile] {
		raw, err := ReadBoundedRegularFile(absRepo, filepath.Join(absRepo, rootFile), MaxStaticDiscoveryBytes)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(raw, &root); err != nil {
				return nil, fmt.Errorf("%s: %w", rootFile, err)
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	result.Enforce = root.Enforce
	allowedSubsystems := make(map[string]bool, len(root.Subsystems))
	for _, id := range root.Subsystems {
		allowedSubsystems[id] = true
	}

	manifestsDir := filepath.Join(absRepo, ".bounds", "manifests")
	if err := insideRepo(absRepo, manifestsDir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		return nil, err
	}
	knownDirs := make(map[string]bool)
	for f := range allowedFiles {
		for dir := filepath.Dir(f); dir != "." && !knownDirs[dir]; dir = filepath.Dir(dir) {
			knownDirs[dir] = true
		}
	}
	loaded := make(map[string]bool)
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), ext)
		if len(allowedSubsystems) > 0 && !allowedSubsystems[stem] {
			continue
		}
		rel := ".bounds/manifests/" + e.Name()
		if allowedFiles != nil && !allowedFiles[rel] {
			continue
		}
		raw, err := readManifest(absRepo, filepath.Join(manifestsDir, e.Name()), MaxStaticDiscoveryBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		var bm boundsManifestYAML
		if err := yaml.Unmarshal(raw, &bm); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		id := nonEmptyStr(bm.Name, stem)
		if len(allowedSubsystems) > 0 {
			id = stem
		}
		if loaded[id] {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s duplicates subsystem %q", rel, id))
			continue
		}
		loaded[id] = true
		var globs []string
		root := "."
		paths := append(bm.Paths, bm.Files...)
		for _, p := range paths {
			clean := strings.Trim(strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(p)), "./"), "/")
			if clean == "" || clean == "." {
				continue
			}
			prefix := clean
			switch idx := strings.IndexAny(clean, "*?["); {
			case idx >= 0:
				prefix = strings.TrimSuffix(clean[:idx], "/")
				if idx == 0 || clean[idx-1] != '/' {
					prefix = filepath.ToSlash(filepath.Dir(prefix))
				}
				globs = append(globs, clean)
			default:
				isDir, isFile := knownDirs[filepath.FromSlash(clean)], allowedFiles[clean]
				if allowedFiles == nil {
					if info, err := os.Stat(filepath.Join(absRepo, clean)); err == nil {
						isDir, isFile = info.IsDir(), !info.IsDir()
					}
				}
				if isFile || (!isDir && filepath.Ext(clean) != "" && !strings.HasSuffix(p, "/")) {
					prefix = filepath.ToSlash(filepath.Dir(clean))
					globs = append(globs, clean)
				} else {
					globs = append(globs, clean+"/**")
				}
			}
			if root == "." {
				root = normalizeRoot(prefix)
			}
		}
		if len(globs) == 0 {
			globs = defaultPathsForRoot(root)
		}

		var deps []string
		for _, c := range bm.Consumes {
			deps = append(deps, c.Subsystem)
		}
		desc := strings.TrimSpace(bm.Description)
		if strings.HasPrefix(strings.ToUpper(desc), "TODO") {
			desc = ""
		}
		result.Subsystems = append(result.Subsystems, BoundsSubsystem{
			Component: Component{
				ID:           id,
				Root:         root,
				Kind:         nonEmptyStr(bm.Role, "subsystem"),
				Language:     inferBoundsLanguage(absRepo, paths),
				Description:  desc,
				DependsOn:    uniqueSorted(deps),
				Paths:        uniqueSorted(globs),
				ManifestFile: rel,
				Provenance:   ProvenanceToolObserved,
			},
			Exposes: bm.Exposes,
		})
	}
	for _, id := range root.Subsystems {
		if !loaded[id] {
			result.Warnings = append(result.Warnings, fmt.Sprintf("listed subsystem %q could not be loaded", id))
		}
	}
	return result, nil
}

// DetectPackageManager inspects lockfiles statically without running any tool.
func DetectPackageManager(absRepo string) string {
	switch {
	case fileExists(filepath.Join(absRepo, "pnpm-lock.yaml")):
		return "pnpm"
	case fileExists(filepath.Join(absRepo, "bun.lock")) || fileExists(filepath.Join(absRepo, "bun.lockb")):
		return "bun"
	case fileExists(filepath.Join(absRepo, "yarn.lock")):
		return "yarn"
	case fileExists(filepath.Join(absRepo, "package-lock.json")):
		return "npm"
	case fileExists(filepath.Join(absRepo, "package.json")):
		return "npm"
	default:
		return ""
	}
}

func inspectEcosystem(absRepo string) EcosystemInfo {
	info := EcosystemInfo{
		HasAgentsMD:        fileExists(filepath.Join(absRepo, "AGENTS.md")),
		HasClaudeMD:        fileExists(filepath.Join(absRepo, "CLAUDE.md")),
		HasBounds:          dirExists(filepath.Join(absRepo, ".bounds")),
		HasGitleaks:        fileExists(filepath.Join(absRepo, ".gitleaks.toml")),
		HasGitHubWorkflows: dirExists(filepath.Join(absRepo, ".github", "workflows")),
		PackageManager:     DetectPackageManager(absRepo),
	}

	// Discover AAIF local skills under .agents/skills/*/SKILL.md (bounded, inside-repo only).
	agentsSkillsDir := filepath.Join(absRepo, ".agents", "skills")
	agentsSkillNames := make(map[string]bool)
	if entries, err := os.ReadDir(agentsSkillsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			skillMD := filepath.Join(agentsSkillsDir, e.Name(), "SKILL.md")
			raw, err := ReadBoundedRegularFile(absRepo, skillMD, MaxStaticDiscoveryBytes)
			if err != nil {
				continue
			}
			name, desc := parseSkillFrontmatterBytes(raw)
			if name == "" {
				name = e.Name()
			}
			agentsSkillNames[e.Name()] = true
			info.DiscoveredSkills = append(info.DiscoveredSkills, DiscoveredSkill{
				Name:        name,
				Path:        filepath.ToSlash(filepath.Join(".agents", "skills", e.Name(), "SKILL.md")),
				Description: desc,
			})
		}
		sort.Slice(info.DiscoveredSkills, func(i, j int) bool {
			return info.DiscoveredSkills[i].Name < info.DiscoveredSkills[j].Name
		})
	}

	// Detect duplicate non-symlink skill directories in .claude/skills/ when .agents/skills/ exists.
	if len(agentsSkillNames) > 0 {
		claudeSkillsDir := filepath.Join(absRepo, ".claude", "skills")
		if entries, err := os.ReadDir(claudeSkillsDir); err == nil {
			for _, e := range entries {
				full := filepath.Join(claudeSkillsDir, e.Name())
				linfo, err := os.Lstat(full)
				if err != nil {
					continue
				}
				if linfo.Mode()&os.ModeSymlink != 0 {
					continue
				}
				if linfo.IsDir() && agentsSkillNames[e.Name()] {
					info.DuplicateSkillPaths = append(info.DuplicateSkillPaths, ".claude/skills/"+e.Name())
				}
			}
			sort.Strings(info.DuplicateSkillPaths)
		}
	}

	return info
}

func parseSkillFrontmatterBytes(raw []byte) (name, description string) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "---" {
		return "", ""
	}
	var lines []string
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "---" {
			break
		}
		lines = append(lines, line)
		if len(lines) > 80 {
			break
		}
	}
	var fm struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &fm); err != nil {
		return "", ""
	}
	desc := strings.TrimSpace(fm.Description)
	if len(desc) > 140 {
		desc = desc[:137] + "..."
	}
	return strings.TrimSpace(fm.Name), desc
}

// detectComponentCycles finds any dependency cycles among components (including self-cycles) using 3-color DFS.
func detectComponentCycles(comps []Component) []string {
	adj := make(map[string][]string, len(comps))
	for _, c := range comps {
		adj[c.ID] = c.DependsOn
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(comps))
	var cycles []string
	seenCycle := make(map[string]bool)

	var dfs func(u string, stack []string)
	dfs = func(u string, stack []string) {
		color[u] = gray
		stack = append(stack, u)
		for _, v := range adj[u] {
			if _, exists := adj[v]; !exists {
				continue
			}
			switch color[v] {
			case gray:
				for i, node := range stack {
					if node == v {
						cyc := strings.Join(append(append([]string(nil), stack[i:]...), v), " -> ")
						if !seenCycle[cyc] {
							seenCycle[cyc] = true
							cycles = append(cycles, "component dependency cycle detected: "+cyc)
						}
						break
					}
				}
			case white:
				dfs(v, stack)
			}
		}
		color[u] = black
	}

	for _, c := range comps {
		if color[c.ID] == white {
			dfs(c.ID, nil)
		}
	}
	sort.Strings(cycles)
	return cycles
}

func inferBoundsLanguage(absRepo string, paths []string) string {
	for _, p := range paths {
		lp := strings.ToLower(p)
		switch {
		case strings.Contains(lp, ".ts") || strings.Contains(lp, ".tsx"):
			return "typescript"
		case strings.Contains(lp, ".py"):
			return "python"
		case strings.Contains(lp, ".go"):
			return "go"
		case strings.Contains(lp, ".rs"):
			return "rust"
		}
	}
	switch {
	case fileExists(filepath.Join(absRepo, "tsconfig.json")):
		return "typescript"
	case fileExists(filepath.Join(absRepo, "pyproject.toml")) || fileExists(filepath.Join(absRepo, "requirements.txt")):
		return "python"
	case fileExists(filepath.Join(absRepo, "go.mod")):
		return "go"
	case fileExists(filepath.Join(absRepo, "Cargo.toml")):
		return "rust"
	case fileExists(filepath.Join(absRepo, "package.json")):
		return "javascript"
	default:
		return ""
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func nonEmptyStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.TrimSpace(s)
}
