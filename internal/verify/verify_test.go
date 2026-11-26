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

func TestCappedBufferBoundsMemoryAndRetainsHeadAndTail(t *testing.T) {
	buf := newCappedBuffer(1024)
	_, _ = buf.Write([]byte("HEAD_MARKER_START\n"))
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = 'x'
	}
	for i := 0; i < 64; i++ {
		_, _ = buf.Write(chunk)
	}
	_, _ = buf.Write([]byte("\nTAIL_FAILURE_SUMMARY: AssertionError\n"))

	out := buf.String()
	if len(out) > 1200 {
		t.Fatalf("expected cappedBuffer output to stay bounded near 1024 bytes, got %d", len(out))
	}
	if !strings.Contains(out, "HEAD_MARKER_START") {
		t.Fatal("expected head marker to be preserved")
	}
	if !strings.Contains(out, "TAIL_FAILURE_SUMMARY: AssertionError") {
		t.Fatal("expected trailing failure summary to be preserved")
	}
	if !strings.Contains(out, "bytes omitted") {
		t.Fatal("expected omission marker")
	}

	excerpt := RedactAndTrim("HEAD_INFO\n"+strings.Repeat("a", 500)+"TOKEN=supersecret12345678\nFINAL_ERROR_LINE", 120)
	if strings.Contains(excerpt, "supersecret12345678") {
		t.Fatal("secret leaked in trimmed excerpt")
	}
	if !strings.Contains(excerpt, "FINAL_ERROR_LINE") {
		t.Fatalf("expected trailing error line to be preserved in excerpt: %q", excerpt)
	}
}

func TestRedactQuotedSecretsAndPaddedBearerTokens(t *testing.T) {
	raw := `Authorization: Bearer dG9rZW4xMjM0NTY3ODkw==
API_TOKEN="quoted-super-secret-value"
DB_PASSWORD='single-quoted-secret'
`
	out := RedactAndTrim(raw, 500)
	for _, leaked := range []string{"dG9rZW4xMjM0NTY3ODkw", "quoted-super-secret-value", "single-quoted-secret"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("secret %q leaked in redacted output:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "Bearer [REDACTED]") {
		t.Fatalf("expected Bearer [REDACTED] in output:\n%s", out)
	}
}
