package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionUsesPinnedBuildAndRunsSyncBeforeChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses Bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("Bash unavailable")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "action", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				ID, Run, Uses string
				Env           map[string]string
			}
		}
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	var setup, build, gate, report string
	for _, step := range action.Runs.Steps {
		if step.Uses != "" && !regexp.MustCompile(`^actions/setup-go@[a-f0-9]{40}$`).MatchString(step.Uses) {
			t.Fatalf("unpinned toolchain: %s", step.Uses)
		}
		if strings.Contains(step.Run, "${{") {
			t.Fatalf("inline workflow expression in %s", step.ID)
		}
		if step.ID == "setup" {
			setup = step.Run
		}
		if step.ID == "report" {
			report = step.Run
		}
		if step.ID == "verifier" {
			build = step.Run
			if step.Env["ACTION_PATH"] != "${{ github.action_path }}" {
				t.Fatal("build does not use pinned Action path")
			}
		}
		if step.ID == "gate" {
			gate = step.Run
		}
	}
	if !strings.Contains(build, `go -C "$SOURCE_DIR" build`) || strings.Contains(build, "GITHUB_PATH") || gate == "" || setup == "" || report == "" || strings.Contains(setup, "GITHUB_PATH") {
		t.Fatal("missing isolated verifier build or gate")
	}
	t.Run("source build without a SHA ref", func(t *testing.T) {
		dir := t.TempDir()
		actionDir := filepath.Join(dir, "action")
		if err := os.Mkdir(actionDir, 0o755); err != nil {
			t.Fatal(err)
		}
		tools := t.TempDir()
		log := filepath.Join(dir, "go-args")
		if err := os.WriteFile(filepath.Join(tools, "go"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$TEST_LOG\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, "outputs")
		cmd := exec.Command(bash, "--noprofile", "--norc", "-c", build)
		cmd.Env = append(os.Environ(), "ACTION_PATH="+actionDir, "ACTION_REF=", "RUNNER_OS=Linux", "RUNNER_TEMP="+dir, "GITHUB_OUTPUT="+output, "TEST_LOG="+log, "PATH="+tools+string(os.PathListSeparator)+os.Getenv("PATH"))
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("tagged source build: %v %s", err, raw)
		}
		raw, err := os.ReadFile(log)
		if err != nil || !strings.Contains(string(raw), "build -mod=readonly -trimpath") {
			t.Fatalf("build arguments: %q %v", raw, err)
		}
	})

	for _, fixture := range []struct{ name, syncCode, verifyCode, outcome, stage, event, alias, syncCheck string }{
		{"sync blocks execution", "1", "0", "PASS", "sync", "push", "", "true"},
		{"passing receipt", "0", "0", "PASS", "complete", "pull_request", "refs/waypost/base", "true"},
		{"failing check", "0", "1", "FAIL", "verify", "push", "", "true"},
		{"forged build identity", "0", "0", "FORGED", "receipt", "push", "", "true"},
		{"moving PR base", "0", "0", "PASS", "preflight", "pull_request", "HEAD", "true"},
		{"moving push base", "0", "0", "PASS", "preflight", "push", "HEAD", "true"},
		{"mandatory sync", "0", "0", "PASS", "preflight", "push", "", "false"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			dir := t.TempDir()
			mustGit(t, dir, "init", "-b", "main")
			mustGit(t, dir, "commit", "--allow-empty", "-m", "base")
			base := strings.TrimSpace(runGitOutput(t, dir, "rev-parse", "HEAD"))
			mustGit(t, dir, "commit", "--allow-empty", "-m", "head")
			head := strings.TrimSpace(runGitOutput(t, dir, "rev-parse", "HEAD"))
			mustGit(t, dir, "update-ref", "refs/waypost/base", base)
			tmp := t.TempDir()
			bin := filepath.Join(tmp, "waypost")
			const stub = `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_LOG"
if [ "$1" = sync ]; then exit "$SYNC_CODE"; fi
while [ "$1" != --receipt ]; do shift; done
printf '{"receipt_version":"1","authority":"ci","verifier":{"binary_sha256":"%s"},"git":{"head_sha":"%s","target_sha":"%s"},"summary":{"outcome":"%s"},"plan_complete":true}\n' "$TEST_IDENTITY" "$TEST_HEAD" "$EVENT_BASE" "$TEST_OUTCOME" > "$2"
exit "$VERIFY_CODE"
`
			if err := os.WriteFile(bin, []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			outcome, identity := fixture.outcome, fmt.Sprintf("%x", sha256.Sum256([]byte(stub)))
			if outcome == "FORGED" {
				outcome, identity = "PASS", strings.Repeat("0", 64)
			}
			output, log := filepath.Join(tmp, "outputs"), filepath.Join(tmp, "commands")
			cmd := exec.Command(bash, "--noprofile", "--norc", "-c", gate)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "BIN="+bin, "OUTPUT_DIR="+tmp, "INPUT_BASE="+fixture.alias, "INPUT_ALL=true", "INPUT_FROZEN=true",
				"INPUT_SYNC_CHECK="+fixture.syncCheck, "EVENT_KIND="+fixture.event, "PR_BASE="+base, "PUSH_BASE="+base, "INPUT_BOOTSTRAP=false", "RECEIPT_NAME=receipt.json", "MARKDOWN_NAME=receipt.md", "EVENT_BASE="+base,
				"GITHUB_OUTPUT="+output, "TEST_HEAD="+head, "TEST_LOG="+log, "TEST_OUTCOME="+outcome, "TEST_IDENTITY="+identity,
				"SYNC_CODE="+fixture.syncCode, "VERIFY_CODE="+fixture.verifyCode)
			std, err := cmd.CombinedOutput()
			if (err == nil) != (fixture.stage == "complete") {
				t.Fatalf("unexpected gate result %v, %s", err, std)
			}
			data, _ := os.ReadFile(output)
			if !strings.Contains(string(data), "stage="+fixture.stage+"\n") {
				t.Fatalf("outputs %s, stderr %s", data, std)
			}
			calls, _ := os.ReadFile(log)
			if fixture.stage == "preflight" {
				if len(calls) > 0 {
					t.Fatalf("executed before valid preflight: %s", calls)
				}
				return
			}
			if !strings.HasPrefix(string(calls), "sync --check --offline --ref "+head+"\n") || (strings.Contains(string(calls), "verify") != (fixture.syncCode == "0")) {
				t.Fatalf("unexpected check order: %s", calls)
			}
		})
	}
	for _, f := range []struct{ setup, build, want string }{{"failure", "skipped", "setup"}, {"success", "failure", "build"}, {"success", "success", "complete"}} {
		output := filepath.Join(t.TempDir(), "outputs")
		cmd := exec.Command(bash, "-c", report)
		cmd.Env = append(os.Environ(), "SETUP_OUTCOME="+f.setup, "BUILD_OUTCOME="+f.build, "GATE_OUTCOME=PASS", "GATE_STAGE=complete", "GITHUB_OUTPUT="+output)
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("report failed: %v %s", err, raw)
		}
		raw, err := os.ReadFile(output)
		if err != nil || !strings.Contains(string(raw), "stage="+f.want+"\n") || (f.want != "complete" && !strings.Contains(string(raw), "outcome=FAIL")) {
			t.Fatalf("report: %q %v", raw, err)
		}
	}

}
