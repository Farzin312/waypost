package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
)

func TestRedactSecrets(t *testing.T) {
	in := "Authorization: Bearer supersecret_token_12345\nAPI_KEY=my-secret-value\nghp_1234567890abcdefghij123456\nsk-proj-abcdef1234567890"
	out := RedactAndTrim(in, 500)
	for _, leaked := range []string{"supersecret_token_12345", "my-secret-value", "ghp_1234567890", "sk-proj-abcdef"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("secret leaked in redacted output: %q\nout=%s", leaked, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] markers in %s", out)
	}
}

func TestVerifyHonestFourStateStatuses(t *testing.T) {
	dir := t.TempDir()
	cfgYAML := `schema_version: "1"
name: verify-test
extends: "builtin:base@1.0.0"
checks:
  - id: pass-check
    command: "echo ok"
    required: true
  - id: missing-bin-req
    command: "echo never"
    requires_bin: "waypost_nonexistent_binary_xyz"
    required: true
  - id: optional-fail
    command: "exit 1"
    required: false
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockfile.Write(dir, lockfile.Generate(res)); err != nil {
		t.Fatal(err)
	}

	rec, err := Run(dir, Options{Mode: "local", Frozen: true})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rec.Summary.Outcome != StatusFail {
		t.Fatalf("expected overall FAIL when required binary missing, got %s", rec.Summary.Outcome)
	}
	if rec.Summary.Passed != 1 || rec.Summary.Failed != 1 || rec.Summary.Warned != 1 {
		t.Fatalf("unexpected counts: %+v", rec.Summary)
	}
}
