package compmap

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxStaticDiscoveryBytes = 512 * 1024 // 512 KiB per static manifest/skill file

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

type boundsManifestYAML struct {
	Name        string   `yaml:"name"`
	Role        string   `yaml:"role"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`
	Consumes    []struct {
		Subsystem string `yaml:"subsystem"`
	} `yaml:"consumes"`
}

// readBoundedRegularFile reads a regular file strictly inside absRepo (rejecting symlinks
// escaping the repo, FIFOs, sockets, and oversized files) up to maxStaticDiscoveryBytes.
func readBoundedRegularFile(absRepo, targetPath string) ([]byte, bool) {
	linfo, err := os.Lstat(targetPath)
	if err != nil {
		return nil, false
	}
	resolved := targetPath
	if linfo.Mode()&os.ModeSymlink != 0 {
		evalRepo, err := filepath.EvalSymlinks(absRepo)
		if err != nil {
			return nil, false
		}
		evalTarget, err := filepath.EvalSymlinks(targetPath)
		if err != nil {
			return nil, false
		}
		rel, err := filepath.Rel(evalRepo, evalTarget)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return nil, false
		}
		resolved = evalTarget
		linfo, err = os.Lstat(resolved)
		if err != nil {
			return nil, false
		}
	}
	if !linfo.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxStaticDiscoveryBytes+1))
	if err != nil || len(raw) > maxStaticDiscoveryBytes {
		return nil, false
	}
	return raw, true
}

// loadBoundsManifests reads `.bounds/manifests/*.yaml` statically (zero code execution)
// when present, returning tool-observed components with exact subsystem dependencies.
func loadBoundsManifests(absRepo string) ([]Component, bool) {
	manifestsDir := filepath.Join(absRepo, ".bounds", "manifests")
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		return nil, false
	}

	var comps []Component
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		full := filepath.Join(manifestsDir, e.Name())
		raw, ok := readBoundedRegularFile(absRepo, full)
		if !ok {
			continue
		}
		var bm boundsManifestYAML
		if err := yaml.Unmarshal(raw, &bm); err != nil {
			continue
		}
		id := strings.TrimSpace(bm.Name)
		if id == "" {
			id = strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".yaml"), ".yml")
		}
		if id == "" {
			continue
		}

		var globs []string
		root := "."
		for _, p := range bm.Paths {
			clean := strings.TrimSpace(filepath.ToSlash(p))
			for strings.HasPrefix(clean, "./") {
				clean = strings.TrimPrefix(clean, "./")
			}
			clean = strings.Trim(clean, "/")
			if clean == "" || clean == "." {
				continue
			}
			if root == "." {
				r := clean
				if idx := strings.IndexAny(r, "*?["); idx >= 0 {
					r = strings.TrimSuffix(filepath.ToSlash(filepath.Dir(r[:idx])), "/")
				}
				r = normalizeRoot(r)
				if r != "" && r != "." {
					root = r
				}
			}
			if strings.ContainsAny(clean, "*?[") {
				globs = append(globs, clean)
			} else {
				globs = append(globs, clean+"/**")
			}
		}
		if len(globs) == 0 {
			globs = defaultPathsForRoot(root)
		}

		var deps []string
		for _, c := range bm.Consumes {
			sub := strings.TrimSpace(c.Subsystem)
			if sub != "" {
				deps = append(deps, sub)
			}
		}

		desc := strings.TrimSpace(bm.Description)
		if strings.HasPrefix(strings.ToUpper(desc), "TODO") {
			desc = ""
		}

		comps = append(comps, Component{
			ID:           id,
			Root:         root,
			Kind:         nonEmptyStr(bm.Role, "subsystem"),
			Language:     inferBoundsLanguage(absRepo, bm.Paths),
			Description:  desc,
			DependsOn:    uniqueSorted(deps),
			Paths:        uniqueSorted(globs),
			ManifestFile: ".bounds/manifests/" + e.Name(),
			Provenance:   ProvenanceToolObserved,
		})
	}
	if len(comps) == 0 {
		return nil, false
	}
	return comps, true
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
			raw, ok := readBoundedRegularFile(absRepo, skillMD)
			if !ok {
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
