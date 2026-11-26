package project

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/repoview"
)

func TestProofLinksRequireRegularTrackedFilesAndResolvedChecks(t *testing.T) {
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	dir := t.TempDir()
	git(dir, "init")
	write := func(name, data string) {
		t.Helper()
		file := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("policy.yaml", "schema_version: '1'\nchecks: [{id: proof, command: echo ok}]\n")
	root := `schema_version: "1"
extends: policy.yaml
rules:
  - id: invariant
    kind: invariant
    summary: prove the contract
    verified_by: {checks: [proof], tests: ["tests/*.go"]}
`
	write(config.ConfigFileName, root)
	write("tests/seam.go", "package fixture")
	load := func() (*Snapshot, error) {
		t.Helper()
		view, err := repoview.Working(dir)
		if err != nil {
			t.Fatal(err)
		}
		return Load(view, config.LoadOptions{}, compmap.BuildOptions{})
	}
	p, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProofs(p.View, p.Config()); err == nil || !strings.Contains(err.Error(), "no regular tracked match") {
		t.Fatalf("untracked test accepted: %v", err)
	}
	git(dir, "add", "tests/seam.go")
	p, err = load()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProofs(p.View, p.Config()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("seam.go", filepath.Join(dir, "tests/link.go")); err == nil {
		git(dir, "add", "tests/link.go")
		p, err = load()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateProofs(p.View, p.Config()); err == nil || !strings.Contains(err.Error(), "non-regular tracked path") {
			t.Fatalf("symlink proof accepted: %v", err)
		}
	}
	write(config.ConfigFileName, root+"disable_checks: [proof]\n")
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "unknown verified_by check") {
		t.Fatalf("disabled proof check accepted: %v", err)
	}
	for _, pattern := range []string{"../seam.go", "tests/[missing.go", "tests/seam.go, ./tests/seam.go"} {
		bad := strings.Replace(root, `"tests/*.go"`, pattern, 1)
		if _, err := config.ParseBytes([]byte(bad), "fixture"); err == nil {
			t.Fatalf("invalid proof pattern %q accepted", pattern)
		}
	}
	if _, err := config.ParseBytes([]byte(root+"---\nname: second\n"), "fixture"); err == nil {
		t.Fatal("trailing YAML document accepted")
	}
}
