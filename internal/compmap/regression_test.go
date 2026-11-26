package compmap

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGlobLinearTimeAdversarial(t *testing.T) {
	pat := "**/a/**/b/**/c/**/d/**/e/**/z"
	tgt := "a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b"
	start := time.Now()
	if MatchGlob(pat, tgt) {
		t.Fatal("expected non-match")
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("MatchGlob took too long (%s), backtracking regression", elapsed)
	}
}

func TestInferIDDedupBeforeNodeDepWiring(t *testing.T) {
	dir := t.TempDir()
	// Create a Rust crate AND a Node package both named "shared", plus a Node "web" package depending on "shared".
	if err := os.MkdirAll(filepath.Join(dir, "crates/shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "packages/shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "packages/web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crates/shared/Cargo.toml"), []byte("[package]\nname = \"shared\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages/shared/package.json"), []byte(`{"name":"shared"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages/web/package.json"), []byte(`{"name":"web","dependencies":{"shared":"workspace:*"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := Build(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var nodeSharedID, rustSharedID string
	var webDeps []string
	for _, c := range m.Components {
		if c.Root == "packages/shared" {
			nodeSharedID = c.ID
		}
		if c.Root == "crates/shared" {
			rustSharedID = c.ID
		}
		if c.Root == "packages/web" {
			webDeps = c.DependsOn
		}
	}
	if nodeSharedID == "" || rustSharedID == "" || nodeSharedID == rustSharedID {
		t.Fatalf("expected distinct IDs for node and rust shared, got node=%q rust=%q", nodeSharedID, rustSharedID)
	}
	if len(webDeps) != 1 || webDeps[0] != nodeSharedID {
		t.Fatalf("expected web to depend on node package %q, got %v (rust=%q)", nodeSharedID, webDeps, rustSharedID)
	}
}
