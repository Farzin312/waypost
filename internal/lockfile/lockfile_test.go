package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
)

func TestGenerateWriteAndVerifyLockfile(t *testing.T) {
	dir := t.TempDir()
	cfgYAML := `schema_version: "1"
name: lock-test
extends: "builtin:base@1.0.0"
providers:
  - id: bounds-arch
    tool: bounds
    command: "bounds report --json"
    authorized: false
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	lf := Generate(res)
	digest, err := Write(dir, lf)
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("expected non-empty digest")
	}

	v := Verify(dir, res)
	if !v.Present || !v.Valid || v.LockDigest != digest {
		t.Fatalf("expected valid lockfile, got %+v", v)
	}

	// Now flip authorized: true without updating lockfile -> must detect escalation and drift
	cfgAuth := `schema_version: "1"
name: lock-test
extends: "builtin:base@1.0.0"
providers:
  - id: bounds-arch
    tool: bounds
    command: "bounds report --json"
    authorized: true
`
	if err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte(cfgAuth), 0o644); err != nil {
		t.Fatal(err)
	}
	res2, err := config.Load(dir, config.LoadOptions{Mode: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	v2 := Verify(dir, res2)
	if v2.Valid {
		t.Fatalf("expected invalid lockfile after tampering, got %+v", v2)
	}
	if len(v2.AuthorizationEscalation) == 0 {
		t.Fatalf("expected authorization escalation warning, got %+v", v2)
	}
}
