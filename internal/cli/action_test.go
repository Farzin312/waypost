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

func TestActionFrozenSyncRunsOffline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses a Unix executable")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "action", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name, Run string
				Env       map[string]string
			}
		}
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "Check Waypost drift" {
			if step.Env["INPUT_FROZEN"] != "${{ inputs.frozen }}" {
				t.Fatalf("sync step does not receive the frozen input: %+v", step)
			}
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing sync step")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "waypost"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for frozen, want := range map[string]string{"true": "sync --check --offline", "false": "sync --check"} {
		t.Run(frozen, func(t *testing.T) {
			cmd := exec.Command(bash, "--noprofile", "--norc", "-e", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "INPUT_FROZEN="+frozen)
			out, err := cmd.CombinedOutput()
			if got := strings.TrimSpace(string(out)); err != nil || got != want {
				t.Fatalf("got %q, want %q: %v", got, want, err)
			}
		})
	}
}

func TestActionReleaseDownloadVerifiesChecksumBeforePublishing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses Unix filesystem paths")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "action", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Inputs map[string]struct{ Default string } `yaml:"inputs"`
		Runs   struct {
			Steps []struct {
				ID, Run, Uses string
				Env           map[string]string
			}
		}
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	if action.Inputs["waypost-ref"].Default != "v0.2.0" || action.Inputs["sync-check"].Default != "false" {
		t.Fatalf("unexpected action inputs: %+v", action.Inputs)
	}
	var download string
	for _, step := range action.Runs.Steps {
		if strings.HasPrefix(step.Uses, "actions/setup-go@") && !regexp.MustCompile(`^actions/setup-go@[0-9a-f]{40}$`).MatchString(step.Uses) {
			t.Fatalf("Go action is not pinned: %s", step.Uses)
		}
		if strings.Contains(step.Run, "${{") {
			t.Fatalf("workflow expressions must enter shell through env: %s", step.ID)
		}
		if step.ID == "download" {
			if step.Env["WAYPOST_REF"] != "${{ inputs.waypost-ref }}" {
				t.Fatalf("missing safe ref environment: %+v", step.Env)
			}
			download = step.Run
		}
	}
	if download == "" {
		t.Fatal("missing release download step")
	}

	const asset = "waypost-linux-amd64"
	const binary = "#!/bin/sh\necho verified\n"
	const curlFixture = `#!/bin/sh
printf '%s\n' "$*" >> "$CURL_LOG"
while [ "$1" != "--output" ]; do shift; done
case "$3" in
  */waypost-linux-amd64)
    [ "$FAIL_ASSET" != binary ] || exit 22
    printf '%s' "$BINARY" > "$2" ;;
  */SHA256SUMS.txt)
    [ "$FAIL_ASSET" != sums ] || exit 22
    printf '%s' "$SUMS" > "$2" ;;
  *) exit 22 ;;
esac
`
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(binary)))
	checksum := digest + "  " + asset + "\n"
	for _, tc := range []struct {
		name, ref, sums, missing string
		calls                    int
		publishes, fails         bool
	}{
		{"verified", "v0.2.0", checksum, "", 2, true, false},
		{"mismatch", "v0.2.0", strings.Repeat("0", 64) + "  " + asset + "\n", "", 2, false, true},
		{"missing checksum entry", "v0.2.0", digest + "  other\n", "", 2, false, true},
		{"ambiguous checksums", "v0.2.0", checksum + checksum, "", 2, false, true},
		{"missing binary", "v0.2.0", checksum, "binary", 1, false, false},
		{"missing checksum asset", "v0.2.0", checksum, "sums", 2, false, false},
		{"branch", "feature/test", checksum, "", 0, false, false},
		{"latest", "latest", checksum, "", 0, false, false},
		{"ref injection", "v0.2.0;touch should-not-exist", checksum, "", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			curl := filepath.Join(dir, "curl")
			if err := os.WriteFile(curl, []byte(curlFixture), 0o755); err != nil {
				t.Fatal(err)
			}
			output, pathFile, curlLog := filepath.Join(dir, "output"), filepath.Join(dir, "path"), filepath.Join(dir, "curl.log")
			cmd := exec.Command(bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", download)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"),
				"WAYPOST_REF="+tc.ref, "RUNNER_OS=Linux", "RUNNER_ARCH=X64", "RUNNER_TEMP="+dir,
				"GITHUB_OUTPUT="+output, "GITHUB_PATH="+pathFile, "CURL_LOG="+curlLog,
				"BINARY="+binary, "SUMS="+tc.sums, "FAIL_ASSET="+tc.missing)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fails {
				t.Fatalf("expected fails=%t, err=%v, out=%s", tc.fails, err, out)
			}
			logged, _ := os.ReadFile(curlLog)
			if strings.Count(string(logged), "\n") != tc.calls {
				t.Fatalf("expected %d downloads, got %s", tc.calls, logged)
			}
			path, pathErr := os.ReadFile(pathFile)
			if (pathErr == nil) != tc.publishes {
				t.Fatalf("expected publishes=%t, PATH entry=%q, err=%v", tc.publishes, path, pathErr)
			}
			if tc.publishes {
				file := filepath.Join(strings.TrimSpace(string(path)), "waypost")
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm()&0o111 == 0 {
					t.Fatalf("verified binary not executable: %v", err)
				}
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "found=true\n" {
					t.Fatalf("wrong found output: %q, %v", data, err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "should-not-exist")); !os.IsNotExist(err) {
				t.Fatalf("untrusted ref executed shell: %v", err)
			}
		})
	}
}
