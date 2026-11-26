package cli

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/repoview"
	"gopkg.in/yaml.v3"
)

func TestInitWorkflowSelectsPinnedRuntimeAndBranches(t *testing.T) {
	for _, fixture := range []struct {
		name            string
		files           map[string]string
		action, install string
	}{
		{"bare", nil, "", ""},
		{"Go", map[string]string{"go/go.mod": "module example.test/app\n\ngo 1.26.3\n"}, goAction, "go/go.mod"},
		{"Python", map[string]string{"app.py": "", "pytest.ini": "[pytest]\n"}, pythonAction, "python -m pip install pytest"},
		{"npm", map[string]string{"package.json": `{}`, "package-lock.json": `{}`}, nodeAction, "npm ci"},
		{"pnpm", map[string]string{"package.json": `{"packageManager":"pnpm@10.3.0"}`, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"}, nodeAction, "pnpm install --frozen-lockfile"},
		{"yarn", map[string]string{"package.json": `{}`, "yarn.lock": "", ".yarnrc.yml": ""}, nodeAction, "yarn install --immutable"},
		{"bun", map[string]string{"package.json": `{}`, "bun.lock": ""}, nodeAction, "bun install --frozen-lockfile"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			dir := t.TempDir()
			mustGit(t, dir, "init", "-b", "main")
			mustGit(t, dir, "commit", "--allow-empty", "-m", "base")
			mustGit(t, dir, "branch", "dev")
			mustGit(t, dir, "update-ref", "refs/remotes/origin/trunk", "HEAD")
			mustGit(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
			for rel, body := range fixture.files {
				mustWriteFile(t, filepath.Join(dir, rel), body)
			}
			view, err := repoview.Working(dir)
			if err != nil {
				t.Fatal(err)
			}
			cm, err := compmap.BuildWithOptions(dir, nil, nil, compmap.BuildOptions{View: view})
			if err != nil {
				t.Fatal(err)
			}
			raw := starterWorkflow(view, inferStarterChecks(view, cm))
			var parsed struct {
				On   map[string]struct{ Branches []string }             `yaml:"on"`
				Jobs map[string]struct{ Steps []struct{ Uses string } } `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(raw, &parsed); err != nil {
				t.Fatal(err)
			}
			for _, event := range []string{"push", "pull_request"} {
				if want := []string{"trunk", "main", "dev"}; !slices.Equal(parsed.On[event].Branches, want) {
					t.Fatalf("%s branches: %+v", event, parsed.On[event])
				}
			}
			var actions []string
			for _, step := range parsed.Jobs["verify"].Steps {
				if step.Uses == "" {
					continue
				}
				if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(step.Uses) {
					t.Fatalf("floating action: %s", step.Uses)
				}
				actions = append(actions, step.Uses)
			}
			expected := []string{checkoutAction}
			if fixture.action != "" {
				expected = append(expected, fixture.action)
			}
			if fixture.name == "bun" {
				expected = append(expected, bunAction)
			}
			if !slices.Equal(actions, expected) {
				t.Fatalf("unexpected actions: %v, want %v", actions, expected)
			}
			body := string(raw)
			preflight := strings.Index(body, "sync --check --offline --ref HEAD")
			if fixture.install != "" && strings.Index(body, fixture.install) < preflight {
				t.Fatalf("missing or premature install %q: %s", fixture.install, body)
			}
			for _, needle := range []string{"permissions: { contents: read }", "fetch-depth: 0", "persist-credentials: false", "git update-ref refs/waypost/base", "github.run_id", "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "unset WAYPOST_CI_BASE", "mktemp -d"} {
				if !strings.Contains(body, needle) {
					t.Fatalf("missing %q: %s", needle, body)
				}
			}
			for _, forbidden := range []string{"GITHUB_ENV", "$RUNNER_TEMP/waypost"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("workflow must not trust install-writable state %q: %s", forbidden, body)
				}
			}
			if len(strings.Split(body, "\n")) > 52 {
				t.Fatalf("workflow exceeded 51 lines: %s", body)
			}
		})
	}
}
