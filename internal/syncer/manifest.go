package syncer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
)

type packageManifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

var signalScripts = []string{"typecheck", "lint", "test", "test:unit", "check:security-predicates", "check:migrations", "check:contract-sync", "docs:check"}

func (s *inspection) inspectManifests(repo string, cfg *config.Config) {
	manifests := make(map[string]*packageManifest)
	broken := make(map[string]bool)
	read := func(rel string) *packageManifest {
		if pkg, ok := manifests[rel]; ok {
			return pkg
		}
		var pkg *packageManifest
		if filepath.IsLocal(rel) {
			raw, err := compmap.ReadBoundedRegularFile(repo, filepath.Join(repo, rel), compmap.MaxStaticDiscoveryBytes)
			if err == nil {
				err = json.Unmarshal(raw, &pkg)
				if err == nil && pkg == nil {
					err = errors.New("expected a package manifest object")
				}
			}
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				broken[rel] = true
				s.add("manifest_error", rel, fmt.Sprintf("%q: %v", rel, err), "fix the package manifest")
			}
		} else {
			broken[rel] = true
			s.add("manifest_error", rel, fmt.Sprintf("package manifest %q is outside the repository", rel), "fix the check workdir")
		}
		manifests[rel] = pkg
		return pkg
	}

	root := read("package.json")
	wired := make(map[string]map[string]bool)
	for _, check := range cfg.Checks {
		scripts := commandScripts(check.Command)
		if len(scripts) == 0 {
			continue
		}
		rel := path.Join(filepath.ToSlash(check.Workdir), "package.json")
		pkg := read(rel)
		if broken[rel] {
			continue
		}
		if wired[rel] == nil {
			wired[rel] = make(map[string]bool)
		}
		for _, script := range scripts {
			wired[rel][script] = true
			if pkg == nil || strings.TrimSpace(pkg.Scripts[script]) == "" {
				s.add("missing_script", check.ID, fmt.Sprintf("check %q references missing script %q in %s", check.ID, script, rel),
					"fix the check command or restore the script")
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
		if version := pinVersion(pin, root, contracts); version != "" && pin.Version != version {
			s.pinVersions[pin.ID] = version
			s.add("pin_drift", pin.ID, fmt.Sprintf("pin %q is %q; live version is %q", pin.ID, pin.Version, version), applyHint)
		}
	}
}

// A check can compose commands, quote script names, or prefix environment assignments.
// Recognize direct invocations at shell command boundaries without executing them.
var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
var shellTokens = regexp.MustCompile(`#[^\n]*|&&|\|\||[;|&\n()]|(?:[^\s;|&()'"]+|"([^"\\]|\\.)*"|'[^']*')+`)

var yarnCommands = []string{"add", "bin", "cache", "config", "dedupe", "dlx", "exec", "explain", "help", "info", "init", "install",
	"link", "node", "pack", "patch", "plugin", "rebuild", "remove", "set", "unlink", "up", "upgrade", "version", "why", "workspace", "workspaces"}

func commandScripts(command string) []string {
	var scripts, words []string
	collect := func() {
		for len(words) > 0 && (envAssignment.MatchString(words[0]) || words[0] == "env") {
			words = words[1:]
		}
		if len(words) < 2 {
			return
		}
		pm, script := words[0], words[1]
		switch pm {
		case "npm", "pnpm", "yarn", "bun":
		default:
			return
		}
		switch {
		case script == "run" || script == "run-script":
			if len(words) < 3 {
				return
			}
			script = words[2]
		case script == "test", pm == "yarn" && !slices.Contains(yarnCommands, script):
		default:
			return
		}
		if script != "" && !strings.HasPrefix(script, "-") && !strings.ContainsAny(script, "$`") && !slices.Contains(scripts, script) {
			scripts = append(scripts, script)
		}
	}
	for _, token := range shellTokens.FindAllString(command, -1) {
		switch token {
		case "&&", "||", ";", "|", "&", "\n", "(", ")":
			collect()
			words = words[:0]
		default:
			if !strings.HasPrefix(token, "#") {
				words = append(words, strings.Trim(token, "\"'"))
			}
		}
	}
	collect()
	return scripts
}

const semver = `(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`

var exactVersion = regexp.MustCompile(`^` + semver + `$`)
var vendoredVersion = regexp.MustCompile(`^file:\./vendor/[^/]+?-((?:` + semver + `))\.tgz$`)

func dependencyVersion(spec string) string {
	if exactVersion.MatchString(spec) {
		return spec
	}
	if m := vendoredVersion.FindStringSubmatch(spec); m != nil {
		return m[1]
	}
	return ""
}

func pinVersion(pin config.CrossRepoPin, root, contracts *packageManifest) string {
	if root != nil {
		for _, name := range []string{pin.Artifact, pin.ID} {
			dep, dev := root.Dependencies[name], root.DevDependencies[name]
			if dep != "" && dev != "" && dependencyVersion(dep) != dependencyVersion(dev) {
				return ""
			}
			if dep == "" {
				dep = dev
			}
			if dep != "" {
				if version := dependencyVersion(dep); version != "" {
					return version
				}
				break
			}
		}
	}
	artifact := strings.TrimPrefix(pin.Artifact, "./")
	if contracts != nil && (pin.ID == "contracts" || artifact == "contracts" || strings.HasPrefix(artifact, "contracts/") ||
		(contracts.Name != "" && (contracts.Name == pin.Artifact || contracts.Name == pin.ID))) && exactVersion.MatchString(contracts.Version) {
		return contracts.Version
	}
	return ""
}
