package syncer

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/repoview"
)

func (s *inspection) inspectComponents(cfg *config.Config, cm *compmap.Map) error {
	if len(cfg.Components) == 0 {
		return nil
	}
	used := make(map[string]bool, len(cm.Components))
	roots := make(map[string]bool, len(cm.Components))
	catchAll := false
	for _, c := range cm.Components {
		used[c.ID], roots[path.Clean(c.Root)] = true, true
		catchAll = catchAll || slices.Contains(c.Paths, "**") || slices.Contains(c.Paths, "**/*")
	}
	if err := s.inspectMissingRoots(cfg, cm); err != nil {
		return err
	}
	if catchAll {
		return nil
	}
	var ignore []string
	if cfg.Boundaries != nil {
		ignore = cfg.Boundaries.IgnorePaths
	}
	dirs := make(map[string]string)
	ignoreGlobs := compmap.CompileGlobs(ignore)
	for rel, file := range s.view.Files {
		language := archgraph.SourceLanguage(rel)
		if !file.Regular() || language == "" || compmap.MatchCompiled(ignoreGlobs, rel) || len(cm.OwnersOf(rel)) > 0 {
			continue
		}
		dir := path.Dir(rel)
		if dirs[dir] == "" || language == "typescript" || dirs[dir] != "typescript" && language < dirs[dir] {
			dirs[dir] = language
		}
	}
	for _, rel := range sortedKeys(dirs) {
		hint := applyHint
		if rel == "." || roots[rel] || strings.ContainsAny(rel, "*?[]\\") {
			hint = "declare paths for the unowned source files in " + config.ConfigFileName
		} else {
			id := componentID(rel, used)
			s.additions[rel] = config.ComponentConfig{ID: id, Root: rel, Language: dirs[rel]}
		}
		s.add("unmapped_dir", rel, fmt.Sprintf("unowned source directory %q", rel), hint)
	}
	return nil
}

func (s *inspection) inspectMissingRoots(cfg *config.Config, cm *compmap.Map) error {
	roots := make(map[string]bool)
	hasProjectFiles := false
	for rel := range s.view.Files {
		roots[rel] = true
		for dir := path.Dir(rel); dir != "." && !roots[dir]; dir = path.Dir(dir) {
			roots[dir] = true
		}
		if rel != config.ConfigFileName && rel != config.LocalConfigFileName && rel != lockfile.LockFileName &&
			rel != cfg.Boundaries.BaselinePath() && !strings.HasPrefix(rel, ".waypost/") {
			hasProjectFiles = true
		}
	}
	var missing []compmap.Component
	for _, c := range cm.Components {
		if c.Provenance == compmap.ProvenanceDeclared && c.Root != "." && c.Root != "**" && !roots[c.Root] {
			missing = append(missing, c)
		}
	}
	live := make(map[string]bool)
	for _, c := range missing {
		globs := compmap.CompileGlobs(c.Paths)
		for rel := range s.view.Files {
			if compmap.MatchCompiled(globs, rel) {
				live[c.ID] = true
				break
			}
		}
	}
	for _, c := range missing {
		if live[c.ID] {
			continue
		}
		detail := fmt.Sprintf("component %q has no live root at %q or files matching paths", c.ID, c.Root)
		if len(c.Checks) > 0 || len(c.TrustPaths) > 0 {
			s.add("empty_component", c.ID, detail, "review its root and paths; component policy is retained")
			continue
		}
		// A config-only repository can describe a scaffold before its
		// project files are checked in.
		if !hasProjectFiles {
			continue
		}
		hint := applyHint
		if componentReferenced(cfg, c.ID) {
			hint = "update references to the component or restore its root"
		}
		s.add("stale_component", c.ID, detail, hint)
	}
	return nil
}

func componentID(rel string, used map[string]bool) string {
	slug := func(text string) string {
		return strings.Join(strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
		}), "-")
	}
	id := slug(path.Base(rel))
	if used[id] || id == "" {
		id = slug(rel)
	}
	if id == "" {
		id = "component"
	}
	base := id
	for suffix := 2; used[id]; suffix++ {
		id = fmt.Sprintf("%s-%d", base, suffix)
	}
	used[id] = true
	return id
}

func componentReferenced(cfg *config.Config, id string) bool {
	for _, check := range cfg.Checks {
		if slices.Contains(check.Components, id) {
			return true
		}
	}
	for _, c := range cfg.Components {
		if slices.Contains(c.DependsOn, id) {
			return true
		}
	}
	for _, pin := range cfg.Pins {
		if pin.Consumer == id || pin.ConsumerComponent == id {
			return true
		}
	}
	if cfg.Boundaries != nil {
		for _, rule := range cfg.Boundaries.Rules {
			patterns := append([]string{rule.From, rule.Target}, rule.DenyDependsOn...)
			if rule.AllowDependsOn != nil {
				patterns = append(patterns, (*rule.AllowDependsOn)...)
			}
			for _, p := range patterns {
				if archgraph.MatchesComponentPattern(p, id) {
					return true
				}
			}
		}
	}
	return false
}

func inferDependencies(view *repoview.View, cfg config.Config, additions map[string]config.ComponentConfig) error {
	cm, err := compmap.BuildWithOptions(view.Repo, &cfg, nil, compmap.BuildOptions{View: view})
	if err != nil {
		return err
	}
	report, err := archgraph.AnalyzeLive(view.Repo, cm, cfg.Boundaries, archgraph.AnalyzeOptions{View: view, SkipNonRegularFiles: true})
	if err != nil {
		return err
	}
	if len(report.ScanErrors) > 0 {
		return fmt.Errorf("infer dependencies: %s", report.ScanErrors[0])
	}
	declared, observed := make(map[string][]string), make(map[string][]string)
	for _, n := range report.Nodes {
		declared[n.ID], observed[n.ID] = slices.Clone(n.DeclaredDependsOn), n.ObservedDependsOn
	}
	for _, rel := range sortedKeys(additions) {
		c := additions[rel]
		for _, to := range observed[c.ID] {
			if !reaches(observed, to, c.ID) && !reaches(declared, to, c.ID) {
				c.DependsOn = append(c.DependsOn, to)
				declared[c.ID] = append(declared[c.ID], to)
			}
		}
		additions[rel] = c
	}
	return nil
}

func reaches(graph map[string][]string, from, target string) bool {
	stack := []string{from}
	seen := map[string]bool{from: true}
	for len(stack) > 0 {
		last := len(stack) - 1
		node := stack[last]
		stack = stack[:last]
		if node == target {
			return true
		}
		for _, next := range graph[node] {
			if !seen[next] {
				seen[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}
