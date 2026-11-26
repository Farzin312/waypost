package archgraph

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

// BoundsMigration holds native Waypost policy translated from a legacy .bounds directory.
type BoundsMigration struct {
	Components []config.ComponentConfig
	Boundaries *config.BoundariesConfig
	Subsystems int
	Warnings   []string
}

// MigrateFromBounds translates legacy subsystem manifests, enforcement mode, and exclusions.
func MigrateFromBounds(repoDir string) (*BoundsMigration, error) {
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, err
	}
	project, err := compmap.LoadBoundsProjectForMigration(absRepo)
	if err != nil {
		return nil, fmt.Errorf("load .bounds: %w", err)
	}
	if len(project.Subsystems) == 0 {
		return nil, fmt.Errorf("no valid subsystem manifests found under %s/.bounds/manifests: %s", absRepo, strings.Join(project.Warnings, "; "))
	}

	mode := "warn"
	switch strings.ToLower(strings.TrimSpace(project.Enforce)) {
	case "on", "true", "enforce":
		mode = "enforce"
	}

	ignores := make(map[string]bool)
	for _, name := range []string{".bounds/ignore", ".boundsignore"} {
		raw, err := compmap.ReadSameRepoRegularFile(absRepo, filepath.Join(absRepo, name), maxSourceFileBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read legacy exclusions: %w", err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimPrefix(strings.TrimSpace(line), "/")
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasSuffix(line, "/") || !strings.ContainsAny(line, "*?[") {
				line = strings.TrimRight(line, "/") + "/**"
			}
			ignores[line] = true
		}
	}

	result := &BoundsMigration{
		Subsystems: len(project.Subsystems),
		Warnings:   project.Warnings,
		Boundaries: &config.BoundariesConfig{
			Enabled:             config.BoolPtr(true),
			Mode:                mode,
			NoCycles:            config.BoolPtr(true),
			EnforceDeclaredDeps: config.BoolPtr(true),
			IgnorePaths:         mapKeysSorted(ignores),
		},
	}
	sort.Slice(project.Subsystems, func(i, j int) bool {
		return project.Subsystems[i].Component.ID < project.Subsystems[j].Component.ID
	})
	for _, subsystem := range project.Subsystems {
		c := subsystem.Component
		result.Components = append(result.Components, config.ComponentConfig{
			ID:          c.ID,
			Root:        c.Root,
			Kind:        c.Kind,
			Language:    c.Language,
			Description: c.Description,
			DependsOn:   c.DependsOn,
			Paths:       c.Paths,
		})
		entrypoints, hasSymbols := migratedEntrypoints(absRepo, subsystem)
		if len(entrypoints) > 0 {
			result.Boundaries.Rules = append(result.Boundaries.Rules, config.BoundaryRule{
				ID:                c.ID + "-public-entrypoints",
				Target:            c.ID,
				PublicEntrypoints: entrypoints,
			})
		}
		if hasSymbols {
			msg := fmt.Sprintf("subsystem %q has symbol-level exposes restrictions that Waypost cannot enforce", c.ID)
			if len(entrypoints) > 0 {
				msg += " with file-level public_entrypoints"
			} else {
				msg += "; no public entrypoint files could be identified"
			}
			result.Warnings = append(result.Warnings, msg)
		}
	}
	return result, nil
}

var conventionalEntrypoints = []string{"index.ts", "index.tsx", "index.js", "index.jsx", "index.mts", "index.cts", "__init__.py", "mod.rs", "lib.rs"}

func migratedEntrypoints(repo string, subsystem compmap.BoundsSubsystem) ([]string, bool) {
	c := subsystem.Component
	entrypoints := make(map[string]bool)
	hasSymbols, needsBarrel := false, false
	for _, expose := range subsystem.Exposes {
		file := expose.Path
		if file == "" {
			file = expose.File
		}
		if file == "" && isSupportedSource(expose.Name) {
			file = expose.Name
		}
		if file == "" || (expose.Name != "" && !isSupportedSource(expose.Name)) {
			hasSymbols = true
		}
		if file == "" {
			needsBarrel = true
			continue
		}
		validFile := false
		file = path.Clean(filepath.ToSlash(file))
		for _, candidate := range []string{file, path.Join(c.Root, file)} {
			if candidate != ".." && !strings.HasPrefix(candidate, "../") && !path.IsAbs(candidate) &&
				!strings.ContainsAny(candidate, "*?[") && compmap.MatchAnyGlob(c.Paths, candidate) {
				entrypoints[candidate] = true
				validFile = true
				break
			}
		}
		if !validFile {
			hasSymbols, needsBarrel = true, true
		}
	}
	if needsBarrel {
		dirs := map[string]bool{c.Root: true}
		for _, pattern := range c.Paths {
			if idx := strings.IndexAny(pattern, "*?["); idx >= 0 {
				dirs[path.Dir(pattern[:idx]+"_")] = true
			} else {
				dirs[path.Dir(pattern)] = true
			}
		}
		for dir := range dirs {
			for _, name := range conventionalEntrypoints {
				candidate := path.Join(dir, name)
				if compmap.MatchAnyGlob(c.Paths, candidate) {
					if _, err := compmap.ReadBoundedRegularFile(repo, filepath.Join(repo, candidate), maxSourceFileBytes); err == nil {
						entrypoints[candidate] = true
					}
				}
			}
		}
	}
	return mapKeysSorted(entrypoints), hasSymbols
}
