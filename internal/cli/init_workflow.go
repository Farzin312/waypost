package cli

import (
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/version"
)

const (
	starterWorkflowPath = ".github/workflows/waypost.yml"
	checkoutAction      = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
	goAction            = "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff"
	nodeAction          = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
	pythonAction        = "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
	bunAction           = "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"
)

func starterWorkflow(view *repoview.View, checks []config.Check) []byte {
	branches, _ := json.Marshal(starterBranches(view))
	var w strings.Builder
	fmt.Fprintf(&w, `name: Waypost
on:
  pull_request:
    branches: %[1]s
  push:
    branches: %[1]s
permissions: { contents: read }
concurrency:
  group: ${{ github.event_name == 'push' && github.run_id || github.workflow_ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: %[2]s
        with: { fetch-depth: 0, persist-credentials: false }
      - name: Validate committed Waypost policy
        run: |
          WP="$(mktemp -d)"; trap 'rm -rf "$WP"' EXIT
          GOBIN="$WP" CGO_ENABLED=0 GOENV=off GOWORK=off GOTOOLCHAIN=auto go install github.com/Farzin312/waypost/cmd/waypost@v%[3]s
          "$WP/waypost" sync --check --offline --ref HEAD
`, branches, checkoutAction, version.CLIVersion)

	paths := view.Paths()
	var goFile string
	for _, rel := range paths {
		if view.Files[rel].Regular() && path.Base(rel) == "go.mod" && compmap.StaticComponentInput(rel) {
			goFile = rel
			if rel == "go.mod" {
				break
			}
		}
	}
	if goFile != "" {
		fmt.Fprintf(&w, "      - uses: %s\n        with: { go-version-file: %q, cache: false }\n", goAction, goFile)
	}

	packages := make(map[string]string)
	for _, rel := range paths {
		if view.Files[rel].Regular() && path.Base(rel) == "package.json" && compmap.StaticComponentInput(rel) {
			dir := path.Dir(rel)
			// A workspace's root lock installs its member packages.
			if dir != "." && hasNodeWorkspaceLock(view) && !hasNodeLock(view, dir) {
				continue
			}
			packages[dir] = starterPackageManager(view, dir, starterPackageManager(view, ".", "npm"))
		}
	}
	if len(packages) > 0 {
		nodeVersion := `node-version: "22"`
		for _, rel := range []string{".nvmrc", ".node-version"} {
			if view.Files[rel].Regular() {
				nodeVersion = "node-version-file: " + rel
				break
			}
		}
		fmt.Fprintf(&w, "      - uses: %s\n        with: { %s }\n", nodeAction, nodeVersion)
		packageDirs := slices.Sorted(maps.Keys(packages))
		if slices.ContainsFunc(packageDirs, func(dir string) bool { return packages[dir] == "bun" }) {
			fmt.Fprintf(&w, "      - uses: %s\n", bunAction)
		}
		if slices.ContainsFunc(packageDirs, func(dir string) bool { return packages[dir] == "pnpm" || packages[dir] == "yarn" }) {
			w.WriteString("      - run: corepack enable\n")
		}
		for _, dir := range packageDirs {
			var install string
			switch packages[dir] {
			case "npm":
				install = "npm install --no-package-lock"
				if view.Files[path.Join(dir, "package-lock.json")].Regular() || view.Files[path.Join(dir, "npm-shrinkwrap.json")].Regular() {
					install = "npm ci"
				}
			case "pnpm":
				install = "pnpm install --frozen-lockfile"
				if !view.Files[path.Join(dir, "pnpm-lock.yaml")].Regular() {
					install = "pnpm install --lockfile=false"
				}
			case "yarn":
				install = "yarn install --frozen-lockfile"
				if view.Files[path.Join(dir, ".yarnrc.yml")].Regular() || view.Files[".yarnrc.yml"].Regular() {
					install = "yarn install --immutable"
				}
			case "bun":
				install = "bun install --no-save"
				if view.Files[path.Join(dir, "bun.lock")].Regular() || view.Files[path.Join(dir, "bun.lockb")].Regular() {
					install = "bun install --frozen-lockfile"
				}
			}
			fmt.Fprintf(&w, "      - run: %s\n", install)
			if dir != "." {
				fmt.Fprintf(&w, "        working-directory: %q\n", dir)
			}
		}
	}

	if slices.ContainsFunc(paths, func(rel string) bool {
		if !view.Files[rel].Regular() {
			return false
		}
		return path.Base(rel) == "pytest.ini" || path.Base(rel) == "pyproject.toml" ||
			strings.HasSuffix(rel, ".py") && !strings.Contains("/"+rel, "/node_modules/") && !strings.Contains("/"+rel, "/.venv/")
	}) {
		pythonVersion := `python-version: "3.12"`
		if view.Files[".python-version"].Regular() {
			pythonVersion = "python-version-file: .python-version"
		}
		fmt.Fprintf(&w, "      - uses: %s\n        with: { %s }\n", pythonAction, pythonVersion)
		var requirements []string
		for _, rel := range []string{"requirements.txt", "requirements-dev.txt"} {
			if view.Files[rel].Regular() {
				requirements = append(requirements, "-r "+rel)
			}
		}
		for _, bin := range []string{"pytest", "ruff"} {
			if slices.ContainsFunc(checks, func(c config.Check) bool { return c.RequiresBin == bin }) {
				requirements = append(requirements, bin)
			}
		}
		if len(requirements) > 0 {
			fmt.Fprintf(&w, "      - run: python -m pip install %s\n", strings.Join(requirements, " "))
		}
	}

	fmt.Fprintf(&w, `      - name: Verify Waypost policy
        env:
          EVENT_BASE: ${{ github.event.pull_request.base.sha || github.event.before }}
        run: |
          unset WAYPOST_CI_BASE
          WP="$(mktemp -d)"; trap 'rm -rf "$WP"' EXIT
          GOBIN="$WP" CGO_ENABLED=0 GOENV=off GOWORK=off GOTOOLCHAIN=auto go install github.com/Farzin312/waypost/cmd/waypost@v%s
          [[ "$EVENT_BASE" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]
          BASE="$EVENT_BASE"
          if [[ ! "$BASE" =~ ^(0{40}|0{64})$ ]]; then
            BASE="$(git rev-parse --verify --end-of-options "$BASE^{commit}")"
            git update-ref refs/waypost/base "$BASE"
            BASE=refs/waypost/base
          fi
          "$WP/waypost" verify --mode ci --frozen --offline --allow-bootstrap --base "$BASE" --receipt "$RUNNER_TEMP/receipt.v1.json"
`, version.CLIVersion)
	return []byte(w.String())
}

func hasNodeWorkspaceLock(view *repoview.View) bool {
	if !hasNodeLock(view, ".") {
		return false
	}
	var pkg struct{ Workspaces json.RawMessage }
	raw, err := view.Read("package.json", compmap.MaxStaticDiscoveryBytes)
	return view.Files["pnpm-workspace.yaml"].Regular() || err == nil && json.Unmarshal(raw, &pkg) == nil && len(pkg.Workspaces) > 0
}

func hasNodeLock(view *repoview.View, dir string) bool {
	return slices.ContainsFunc([]string{"pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "package-lock.json", "npm-shrinkwrap.json"}, func(rel string) bool {
		return view.Files[path.Join(dir, rel)].Regular()
	})
}

func starterPackageManager(view *repoview.View, dir, fallback string) string {
	var pkg struct{ PackageManager string }
	if raw, err := view.Read(path.Join(dir, "package.json"), compmap.MaxStaticDiscoveryBytes); err == nil && json.Unmarshal(raw, &pkg) == nil {
		manager, _, _ := strings.Cut(pkg.PackageManager, "@")
		if slices.Contains([]string{"npm", "pnpm", "yarn", "bun"}, manager) {
			return manager
		}
	}
	for _, item := range []struct{ file, manager string }{
		{"pnpm-lock.yaml", "pnpm"}, {"yarn.lock", "yarn"}, {"bun.lock", "bun"}, {"bun.lockb", "bun"}, {"package-lock.json", "npm"}, {"npm-shrinkwrap.json", "npm"},
	} {
		if view.Files[path.Join(dir, item.file)].Regular() {
			return item.manager
		}
	}
	if fallback != "" {
		return fallback
	}
	return "npm"
}

var workflowBranch = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func starterBranches(view *repoview.View) []string {
	var names []string
	add := func(name string) {
		if workflowBranch.MatchString(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if view.GitDir != "" {
		if remote, err := gitdiff.Git(view.Repo, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"); err == nil {
			add(strings.TrimPrefix(strings.TrimSpace(string(remote)), "refs/remotes/origin/"))
		}
		refs, _ := gitdiff.Git(view.Repo, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes/origin")
		lines := strings.Fields(string(refs))
		for _, branch := range []string{"main", "master", "dev"} {
			if slices.Contains(lines, "refs/heads/"+branch) || slices.Contains(lines, "refs/remotes/origin/"+branch) {
				add(branch)
			}
		}
		if len(names) == 0 {
			current, _ := gitdiff.Git(view.Repo, "symbolic-ref", "--quiet", "--short", "HEAD")
			add(strings.TrimSpace(string(current)))
		}
	}
	if len(names) == 0 {
		return []string{"main"}
	}
	return names
}
