package archgraph

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
)

const maxSourceFileBytes = 1024 * 1024

// RawImport represents one statically resolved intra-repository import.
type RawImport struct {
	File             string `json:"file"`
	Line             int    `json:"line"`
	Specifier        string `json:"specifier"`
	TargetFile       string `json:"target_file"`
	TargetPackageDir string `json:"target_package_dir,omitempty"` // Go imports address the package.'
}

var scanSkipDirs = map[string]bool{
	".git":             true,
	".bounds":          true,
	".waypost":         true,
	".agents":          true,
	".claude":          true,
	".next":            true,
	".expo":            true,
	".venv":            true,
	"node_modules":     true,
	"vendor":           true,
	"dist":             true,
	"build":            true,
	"target":           true,
	"coverage":         true,
	"__pycache__":      true,
	"Binaries":         true,
	"Intermediate":     true,
	"Saved":            true,
	"DerivedDataCache": true,
	"ios":              true,
	"android":          true,
}

type parsedRef struct {
	line int
	spec string
}

type scanResult struct {
	files      map[string]bool
	goPackages map[string][]string
	imports    []RawImport
	errors     []string
}

// AnalyzeOptions optionally restricts scanning to a repository-relative file inventory.
// A nil allowlist scans the live tree.
type AnalyzeOptions struct {
	AllowedFiles      map[string]bool
	AllowMissingFiles bool // Local inventories can include files deleted from the worktree.
}

type goModuleInfo struct {
	dirRel     string
	modulePath string
}

func scanRepoImports(repo string, cm *compmap.Map, ignore []string, opts AnalyzeOptions) (scanResult, error) {
	resolved, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return scanResult{}, err
	}
	repo = resolved
	info, err := os.Stat(repo)
	if err != nil {
		return scanResult{}, err
	}
	if !info.IsDir() {
		return scanResult{}, fmt.Errorf("scan root %q is not a directory", repo)
	}

	result := scanResult{files: make(map[string]bool), goPackages: make(map[string][]string)}
	refsByFile := make(map[string][]parsedRef)
	var goModules []goModuleInfo
	rustCrates := make(map[string]string)
	tsFiles := make(map[string]string)
	addError := func(rel string, err error) {
		result.errors = append(result.errors, fmt.Sprintf("%s: %v", rel, err))
	}

	scanFile := func(rel string) {
		if compmap.MatchAnyGlob(ignore, rel) {
			return
		}
		dir, base := path.Dir(rel), path.Base(rel)
		switch base {
		case "tsconfig.json", "tsconfig.base.json", "jsconfig.json":
			if opts.AllowMissingFiles {
				if _, err := os.Lstat(filepath.Join(repo, rel)); errors.Is(err, os.ErrNotExist) {
					return
				}
			}
			current := tsFiles[dir]
			if current == "" || tsConfigPriority(base) < tsConfigPriority(path.Base(current)) {
				tsFiles[dir] = rel
			}
			return
		}
		if !isSupportedSource(rel) && base != "go.mod" && base != "Cargo.toml" {
			return
		}
		src, err := compmap.ReadBoundedRegularFile(repo, filepath.Join(repo, rel), maxSourceFileBytes)
		if err != nil {
			if !opts.AllowMissingFiles || !errors.Is(err, os.ErrNotExist) {
				addError(rel, err)
			}
			return
		}
		switch base {
		case "go.mod":
			if mod := goModulePath(src); mod != "" {
				goModules = append(goModules, goModuleInfo{dirRel: dir, modulePath: mod})
			}
			return
		case "Cargo.toml":
			if name := rustCrateName(src); name != "" {
				if _, exists := rustCrates[name]; !exists {
					rustCrates[name] = path.Join(dir, "src")
				}
			}
			return
		}
		result.files[rel] = true
		switch strings.ToLower(path.Ext(rel)) {
		case ".go":
			result.goPackages[dir] = append(result.goPackages[dir], rel)
			refsByFile[rel] = extractGoImports(rel, src)
		case ".py":
			refsByFile[rel] = extractPythonImports(src)
		case ".rs":
			refsByFile[rel] = extractRustImports(src)
		default:
			refsByFile[rel] = extractTSImports(src)
		}
	}

	if opts.AllowedFiles != nil {
		skipped := make(map[string]bool)
		for _, rel := range mapKeysSorted(opts.AllowedFiles) {
			if !opts.AllowedFiles[rel] {
				continue
			}
			if !validRepoPath(rel) {
				addError(rel, errors.New("invalid repository-relative path"))
				continue
			}
			skip := false
			for dir := path.Dir(rel); dir != "."; dir = path.Dir(dir) {
				value, cached := skipped[dir]
				if !cached {
					value = skipScanDir(cm, dir)
					skipped[dir] = value
				}
				if value {
					skip = true
					break
				}
			}
			if !skip {
				scanFile(rel)
			}
		}
	} else {
		err = filepath.WalkDir(repo, func(full string, d fs.DirEntry, walkErr error) error {
			rel, err := filepath.Rel(repo, full)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if walkErr != nil {
				if rel == "." {
					return walkErr
				}
				addError(rel, walkErr)
				return nil
			}
			if d.IsDir() {
				if rel != "." && skipScanDir(cm, rel) {
					return filepath.SkipDir
				}
				return nil
			}
			scanFile(rel)
			return nil
		})
		if err != nil {
			return scanResult{}, err
		}
	}

	var tsConfigs []tsAliasConfig
	loader := tsConfigLoader{repo: repo, ignore: ignore, allowedFiles: opts.AllowedFiles}
	for _, rel := range tsFiles {
		tc, err := loader.load(rel, nil)
		if err != nil {
			if !opts.AllowMissingFiles || !errors.Is(err, os.ErrNotExist) {
				addError(rel, err)
			}
			continue
		}
		tsConfigs = append(tsConfigs, tc)
	}
	sort.Slice(tsConfigs, func(i, j int) bool {
		if len(tsConfigs[i].baseDir) != len(tsConfigs[j].baseDir) {
			return len(tsConfigs[i].baseDir) > len(tsConfigs[j].baseDir)
		}
		return tsConfigs[i].baseDir < tsConfigs[j].baseDir
	})
	sort.SliceStable(goModules, func(i, j int) bool { return len(goModules[i].modulePath) > len(goModules[j].modulePath) })
	for _, files := range result.goPackages {
		sort.Strings(files)
	}

	for rel, refs := range refsByFile {
		tc := matchingTSConfig(rel, tsConfigs)
		for _, ref := range refs {
			imp := RawImport{File: rel, Line: ref.line, Specifier: ref.spec}
			switch strings.ToLower(path.Ext(rel)) {
			case ".go":
				imp.TargetPackageDir = resolveGoPackage(rel, ref.spec, goModules, result.goPackages)
				if files := result.goPackages[imp.TargetPackageDir]; len(files) > 0 {
					imp.TargetFile = files[0]
				}
			case ".py":
				imp.TargetFile = resolvePythonImport(rel, ref.spec, result.files)
			case ".rs":
				imp.TargetFile = resolveRustImport(rel, ref.spec, result.files, rustCrates)
			default:
				imp.TargetFile = resolveTSImport(rel, ref.spec, tc, result.files)
			}
			if imp.TargetFile != "" && imp.TargetFile != rel {
				result.imports = append(result.imports, imp)
			}
		}
	}
	sort.Strings(result.errors)
	sort.Slice(result.imports, func(i, j int) bool {
		a, b := result.imports[i], result.imports[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.TargetFile != b.TargetFile {
			return a.TargetFile < b.TargetFile
		}
		return a.Specifier < b.Specifier
	})
	return result, nil
}

func validRepoPath(rel string) bool {
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") &&
		!filepath.IsAbs(rel) && path.Clean(rel) == rel
}

func skipScanDir(cm *compmap.Map, dir string) bool {
	name := path.Base(dir)
	if name == ".git" {
		return true
	}
	if !scanSkipDirs[name] && !strings.HasPrefix(name, ".") {
		return false
	}
	for _, c := range cm.Components {
		if c.Provenance != compmap.ProvenanceDeclared {
			continue
		}
		if c.Root == dir || strings.HasPrefix(c.Root, dir+"/") {
			return false
		}
		for _, glob := range c.Paths {
			segments := strings.Split(strings.ReplaceAll(glob, "\\", "/"), "/")
			for i, segment := range segments {
				if segment == name && compmap.MatchGlob(strings.Join(segments[:i+1], "/"), dir) {
					return false
				}
			}
		}
	}
	return true
}

func isJSSource(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts":
		return true
	}
	return false
}

func isSupportedSource(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".go", ".py", ".rs":
		return true
	}
	return isJSSource(rel)
}

func resolveTSImport(fromFile, spec string, tc *tsAliasConfig, fileSet map[string]bool) string {
	// Strip query/hash suffixes (e.g. ?raw).
	if len(spec) > 0 {
		if idx := strings.IndexAny(spec[1:], "?#"); idx >= 0 {
			spec = spec[:idx+1]
		}
	}
	if spec == "" {
		return ""
	}

	var candidates []string
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		dir := filepath.ToSlash(filepath.Dir(fromFile))
		joined := filepath.ToSlash(filepath.Clean(filepath.Join(dir, spec)))
		if !strings.HasPrefix(joined, "../") && joined != ".." {
			candidates = append(candidates, joined)
		}
	} else if tc != nil {
		// Try tsconfig paths aliases first.
		for _, m := range tc.paths {
			if m.hasStar {
				if strings.HasPrefix(spec, m.prefix) && strings.HasSuffix(spec, m.suffix) && len(spec) >= len(m.prefix)+len(m.suffix) {
					matched := spec[len(m.prefix) : len(spec)-len(m.suffix)]
					for _, t := range m.targets {
						sub := strings.Replace(t, "*", matched, 1)
						joined := filepath.ToSlash(filepath.Clean(filepath.Join(m.baseURL, sub)))
						if !strings.HasPrefix(joined, "../") && joined != ".." {
							candidates = append(candidates, joined)
						}
					}
				}
			} else if spec == m.prefix {
				for _, t := range m.targets {
					joined := filepath.ToSlash(filepath.Clean(filepath.Join(m.baseURL, t)))
					if !strings.HasPrefix(joined, "../") && joined != ".." {
						candidates = append(candidates, joined)
					}
				}
			}
		}
		// Fallback to baseUrl lookup if no alias matched (skipping bare scoped external packages unless file exists).
		if len(candidates) == 0 && tc.baseURL != "" {
			joined := filepath.ToSlash(filepath.Clean(filepath.Join(tc.baseURL, spec)))
			if !strings.HasPrefix(joined, "../") && joined != ".." {
				candidates = append(candidates, joined)
			}
		}
	}

	tsExts := []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".d.ts"}
	for _, base := range candidates {
		base = strings.TrimPrefix(base, "./")
		if fileSet[base] {
			return base
		}
		// ESM TypeScript imports often write `./foo.js` to reference `./foo.ts` / `./foo.tsx`.
		for _, jsExt := range []string{".js", ".jsx", ".mjs", ".cjs"} {
			if strings.HasSuffix(base, jsExt) {
				stem := strings.TrimSuffix(base, jsExt)
				for _, tsExt := range []string{".ts", ".tsx", ".mts", ".cts"} {
					if fileSet[stem+tsExt] {
						return stem + tsExt
					}
				}
			}
		}
		for _, ext := range tsExts {
			if fileSet[base+ext] {
				return base + ext
			}
		}
		for _, ext := range tsExts {
			idxPath := base + "/index" + ext
			if fileSet[idxPath] {
				return idxPath
			}
		}
	}
	return ""
}

func goModulePath(src []byte) string {
	for line := range strings.SplitSeq(string(src), "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`)
		}
	}
	return ""
}

func extractGoImports(relFile string, src []byte) []parsedRef {
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, relFile, src, parser.ImportsOnly)
	if file == nil {
		return nil
	}
	refs := make([]parsedRef, 0, len(file.Imports))
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		val, err := strconv.Unquote(imp.Path.Value)
		if err != nil || val == "" {
			continue
		}
		line := fset.PositionFor(imp.Pos(), false).Line
		refs = append(refs, parsedRef{line: line, spec: val})
	}
	return refs
}

func resolveGoPackage(from, spec string, modules []goModuleInfo, packages map[string][]string) string {
	// A nested module can share its module name with another fixture or module.
	// Prefer the importer's enclosing module when both names resolve.
	target := ""
	bestModuleLen, bestDirLen := 0, 0
	for _, mod := range modules {
		if len(mod.modulePath) < bestModuleLen {
			break
		}
		sub, ok := strings.CutPrefix(spec, mod.modulePath)
		if !ok || (sub != "" && !strings.HasPrefix(sub, "/")) {
			continue
		}
		dir := path.Join(mod.dirRel, strings.TrimPrefix(sub, "/"))
		if len(packages[dir]) == 0 {
			continue
		}
		enclosing := 0
		if mod.dirRel == "." || strings.HasPrefix(from, mod.dirRel+"/") {
			enclosing = len(mod.dirRel)
		}
		if target == "" || enclosing > bestDirLen {
			target = dir
			bestModuleLen, bestDirLen = len(mod.modulePath), enclosing
		}
	}
	return target
}
