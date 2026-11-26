package syncer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/pins"
	"github.com/Farzin312/waypost/internal/repopath"
)

var signalScripts = []string{"typecheck", "lint", "test", "test:unit", "check:security-predicates", "check:migrations", "check:contract-sync", "docs:check"}

func (s *inspection) inspectManifests(repo string, cfg *config.Config) {
	manifests := make(map[string]*pins.Manifest)
	broken := make(map[string]bool)
	read := func(rel string) *pins.Manifest {
		if pkg, ok := manifests[rel]; ok {
			return pkg
		}
		pkg, err := pins.ReadManifest(s.view, rel)
		if err == nil && s.view.Kind == "worktree" {
			// Worktree inventory can contain links through a replaced parent.
			err = repopath.CheckRegular(repo, rel)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			broken[rel] = true
			s.add("manifest_error", rel, fmt.Sprintf("%q: %v", rel, err), "fix the package manifest")
		}
		manifests[rel] = pkg
		return pkg
	}
	root := read("package.json")
	for _, rel := range s.view.Paths() {
		if path.Base(rel) == "package.json" && compmap.StaticComponentInput(rel) {
			read(rel)
		}
	}
	wired := make(map[string]map[string]bool)
	for _, check := range cfg.Checks {
		rel := path.Join(check.Workdir, "package.json")
		for _, command := range []string{check.Command, check.LocalCommand} {
			refs, unknown := scriptReferences(command)
			if unknown {
				s.add("script_unknown", check.ID, "script wiring could not be resolved statically", "check shell-dependent script references")
				continue
			}
			for _, ref := range refs {
				manifest := rel
				if ref.workspace != "" {
					var err error
					manifest, err = workspaceManifest(rel, ref.workspace, s.view.Paths(), read)
					if err != nil {
						s.add("missing_script", check.ID, err.Error(), "fix the check workspace or restore its manifest")
						continue
					}
				}
				pkg := read(manifest)
				if broken[manifest] {
					continue
				}
				if wired[manifest] == nil {
					wired[manifest] = make(map[string]bool)
				}
				wired[manifest][ref.name] = true
				if pkg == nil || strings.TrimSpace(pkg.Scripts[ref.name]) == "" {
					s.add("missing_script", check.ID, fmt.Sprintf("check %q references missing script %q in %s", check.ID, ref.name, manifest),
						"fix the check command or restore the script")
				}
			}
		}
	}
	for _, rel := range sortedKeys(manifests) {
		if pkg := manifests[rel]; pkg != nil {
			for _, script := range signalScripts {
				if strings.TrimSpace(pkg.Scripts[script]) != "" && !wired[rel][script] {
					s.add("unwired_script", script, fmt.Sprintf("script %q in %s has no configured check", script, rel), "wire it if required by repository policy")
				}
			}
		}
	}
	if len(cfg.Pins) == 0 {
		return
	}
	contracts := read("contracts/package.json")
	for _, pin := range cfg.Pins {
		version := pins.LegacyVersion(pin, root, contracts)
		if pin.Source != nil {
			observation := pins.Inspect(s.view, pin)
			if observation.Status == "drift" && observation.Detail != "declared and observed versions differ" {
				s.add("pin_source_error", pin.ID, observation.Detail, "repair the declared pin source or artifact")
				continue
			}
			version = observation.Observed
		}
		if version != "" && pin.Version != version {
			s.pinVersions[pin.ID] = version
			s.add("pin_drift", pin.ID, fmt.Sprintf("pin %q is %q; live version is %q", pin.ID, pin.Version, version), applyHint)
		}
	}
}

func workspaceManifest(manifest, selector string, paths []string, read func(string) *pins.Manifest) (string, error) {
	for dir := path.Dir(manifest); ; dir = path.Dir(dir) {
		current := path.Join(dir, "package.json")
		root := read(current)
		if root != nil && len(root.Workspaces) > 0 {
			var patterns []string
			if err := json.Unmarshal(root.Workspaces, &patterns); err != nil {
				var config struct {
					Packages []string `json:"packages"`
				}
				if err := json.Unmarshal(root.Workspaces, &config); err != nil {
					return "", fmt.Errorf("invalid workspaces in %s", current)
				}
				patterns = config.Packages
			}
			for _, pattern := range patterns {
				if err := repopath.ValidateGlob(pattern); err != nil {
					return "", err
				}
			}
			var matches []string
			for _, candidate := range paths {
				if path.Base(candidate) != "package.json" || candidate == current {
					continue
				}
				rel := path.Dir(candidate)
				if dir != "." {
					var ok bool
					rel, ok = strings.CutPrefix(rel, dir+"/")
					if !ok {
						continue
					}
				}
				if !compmap.MatchAnyGlob(patterns, rel) {
					continue
				}
				pkg := read(candidate)
				if pkg != nil && (pkg.Name == selector || rel == strings.TrimPrefix(selector, "./")) {
					matches = append(matches, candidate)
				}
			}
			if len(matches) == 1 {
				return matches[0], nil
			}
			if len(matches) > 1 {
				return "", fmt.Errorf("workspace %q is ambiguous in %s", selector, current)
			}
		}
		if dir == "." {
			break
		}
	}
	return "", fmt.Errorf("no manifest matches workspace %q for %s", selector, manifest)
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
var shellTokens = regexp.MustCompile(`#[^\n]*|&&|\|\||[;|&\n()]|(?:[^\s;|&()'"]+|"([^"\\]|\\.)*"|'[^']*')+`)
var dynamicShell = regexp.MustCompile(`\$|[` + "\x60" + `]|<<|>>|[{}]|(?:^|[;&|\n])\s*(?:cd|if|for|while|eval|source|sh|bash)\s`)

var yarnCommands = []string{"add", "bin", "cache", "config", "dedupe", "dlx", "exec", "explain", "help", "info", "init", "install",
	"link", "node", "pack", "patch", "plugin", "rebuild", "remove", "set", "unlink", "up", "upgrade", "version", "why", "workspace", "workspaces"}

type scriptReference struct{ name, workspace string }

func scriptReferences(command string) ([]scriptReference, bool) {
	var refs []scriptReference
	var words []string
	unknown := false
	collect := func() {
		for len(words) > 0 && (envAssignment.MatchString(words[0]) || words[0] == "env") {
			words = words[1:]
		}
		if len(words) < 2 {
			return
		}
		pm, action := words[0], words[1]
		if pm != "npm" && pm != "pnpm" && pm != "yarn" && pm != "bun" {
			return
		}
		var ref scriptReference
		var rest []string
		switch {
		case action == "run" || action == "run-script":
			if len(words) < 3 {
				return
			}
			ref.name, rest = words[2], words[3:]
		case action == "test" || pm == "yarn" && !slices.Contains(yarnCommands, action):
			ref.name, rest = action, words[2:]
		default:
			if strings.HasPrefix(action, "-") || action == "workspace" || action == "workspaces" {
				unknown = true
			}
			return
		}
		if ref.name == "" || strings.HasPrefix(ref.name, "-") || strings.ContainsAny(ref.name, "$"+string(rune(96))) {
			unknown = true
			return
		}
		for len(rest) > 0 && rest[0] != "--" {
			arg := rest[0]
			rest = rest[1:]
			if arg == "-w" || arg == "--workspace" {
				if len(rest) == 0 || ref.workspace != "" {
					unknown = true
					return
				}
				ref.workspace, rest = rest[0], rest[1:]
			} else if value, ok := strings.CutPrefix(arg, "--workspace="); ok {
				if value == "" || ref.workspace != "" {
					unknown = true
					return
				}
				ref.workspace = value
			} else if arg == "--workspaces" || arg == "--prefix" || strings.HasPrefix(arg, "--prefix=") || strings.HasPrefix(arg, "-w") {
				unknown = true
				return
			}
		}
		if !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
	}
	end := 0
	for _, pos := range shellTokens.FindAllStringIndex(command, -1) {
		if strings.TrimSpace(command[end:pos[0]]) != "" {
			unknown = true
		}
		end = pos[1]
		token := command[pos[0]:pos[1]]
		switch token {
		case "&&", "||", ";", "|", "&", "\n", "(", ")":
			collect()
			words = nil
		default:
			if !strings.HasPrefix(token, "#") {
				words = append(words, strings.Trim(token, "\"'"))
			}
		}
	}
	collect()
	if strings.TrimSpace(command[end:]) != "" {
		unknown = true
	}
	if (strings.Contains(command, "npm ") || strings.Contains(command, "yarn ") || strings.Contains(command, "bun ") || strings.Contains(command, "pnpm ")) && dynamicShell.MatchString(command) {
		unknown = true
	}
	return refs, unknown
}

func commandScripts(command string) []string {
	refs, _ := scriptReferences(command)
	var out []string
	for _, ref := range refs {
		if !slices.Contains(out, ref.name) {
			out = append(out, ref.name)
		}
	}
	return out
}

func dependencyVersion(spec string) string {
	if strings.HasPrefix(spec, "file:") && !strings.HasPrefix(spec, "file:./vendor/") {
		return ""
	}
	return pins.DependencyVersion(spec)
}
