package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/verify"
)

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v in %s failed: %v\n%s", args, dir, err, string(out))
	}
}

// TestOnePresetUpgradeAcrossTwoUnlikeRepos proves the core scalability invariant:
// a single shared preset upgrade flows cleanly across two completely different
// repositories (a TypeScript mobile/web repo with a cross-repo backend pin AND
// an Unreal C++/Python polyglot repo) while preserving repo-local overrides,
// component maps, pins, and frozen CI verification.
func TestOnePresetUpgradeAcrossTwoUnlikeRepos(t *testing.T) {
	root := t.TempDir()
	presetsDir := filepath.Join(root, "org-presets")
	if err := os.MkdirAll(presetsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Shared org preset v1.0.0
	presetV1 := filepath.Join(presetsDir, "org-v1.yaml")
	if err := os.WriteFile(presetV1, []byte(`schema_version: "1"
name: org-delivery
preset_version: "1.0.0"
extends: "builtin:base@1.0.0"
rules:
  - id: legacy-checklist-crutch
    kind: crutch
    summary: "Temporary checklist crutch for older models"
checks:
  - id: policy-smoke
    command: "echo org-v1-ok"
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Shared org preset v1.1.0: prunes crutch, adds new invariant & upgrades check
	presetV2 := filepath.Join(presetsDir, "org-v1.1.yaml")
	if err := os.WriteFile(presetV2, []byte(`schema_version: "1"
name: org-delivery
preset_version: "1.1.0"
extends: "builtin:base@1.0.0"
rules:
  - id: receipt-provenance-v2
    kind: invariant
    summary: "All CI merges must attach receipt.v1.json bound to tree_hash and lock_digest."
checks:
  - id: policy-smoke
    command: "echo org-v1.1-ok"
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Repo A: TypeScript mobile/web app with cross-repo backend pin
	repoTS := filepath.Join(root, "mobile-app")
	if err := os.MkdirAll(filepath.Join(repoTS, "src/api"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoTS, "package.json"), []byte(`{"name":"mobile-app","devDependencies":{"typescript":"^5.8.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoTS, "src/api/client.ts"), []byte("export const v = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoTS, ".waypost.yaml"), []byte(`schema_version: "1"
name: mobile-app
extends: "org-presets/org-v1.yaml"
components:
  - id: api-client
    root: src/api
    language: typescript
    paths: ["src/api/**"]
    checks: ["contract-compat"]
  - id: app-shell
    root: src
    language: typescript
    depends_on: ["api-client"]
    paths: ["src/**"]
pins:
  - id: backend-openapi
    producer: "org/backend"
    artifact: "openapi/v2.json"
    consumer: "api-client"
    compatibility_check: "contract-compat"
    paths: ["src/api/**"]
checks:
  - id: contract-compat
    command: "echo contract-ok"
    paths: ["src/api/**"]
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{presetV1, presetV2} {
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, filepath.Join(repoTS, "org-presets", filepath.Base(source)), string(raw))
	}
	mustGit(t, repoTS, "init", "-b", "main")
	mustGit(t, repoTS, "add", ".")
	mustGit(t, repoTS, "commit", "-m", "init ts repo")

	// Repo B: Unreal C++ + Python validator polyglot repo
	repoUE := filepath.Join(root, "game-repo")
	if err := os.MkdirAll(filepath.Join(repoUE, "game"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoUE, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoUE, "game/Dream.uproject"), []byte(`{"EngineAssociation":"5.6","Modules":[{"Name":"Dream","Type":"Runtime"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoUE, "tools/pyproject.toml"), []byte("[project]\nname = \"validators\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoUE, ".waypost.yaml"), []byte(`schema_version: "1"
name: game-repo
extends: "org-presets/org-v1.yaml"
components:
  - id: validators
    root: tools
    language: python
    paths: ["tools/**"]
    checks: ["py-validate"]
  - id: game
    root: game
    language: cpp
    depends_on: ["validators"]
    paths: ["game/**"]
checks:
  - id: py-validate
    command: "echo py-ok"
    paths: ["tools/**"]
    required: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{presetV1, presetV2} {
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, filepath.Join(repoUE, "org-presets", filepath.Base(source)), string(raw))
	}
	mustGit(t, repoUE, "init", "-b", "main")
	mustGit(t, repoUE, "add", ".")
	mustGit(t, repoUE, "commit", "-m", "init unreal repo")

	// Lock & upgrade BOTH repos cleanly to org-v1.1.yaml and verify frozen CI passes in both.
	for _, repo := range []string{repoTS, repoUE} {
		var out, errBuf bytes.Buffer
		// First generate v1 lock
		if code := Run([]string{"upgrade", "--dir", repo, "--apply"}, &out, &errBuf); code != 0 {
			t.Fatalf("initial lock failed in %s: %s", repo, errBuf.String())
		}
		mustGit(t, repo, "add", ".waypost.lock")
		mustGit(t, repo, "commit", "-m", "freeze legacy preset")
		// Dry-run upgrade to v1.1
		out.Reset()
		errBuf.Reset()
		if code := Run([]string{"upgrade", "--dir", repo, "--target", "org-presets/org-v1.1.yaml", "--format", "json"}, &out, &errBuf); code != 0 {
			t.Fatalf("dry-run upgrade failed in %s: %s", repo, errBuf.String())
		}
		if !strings.Contains(out.String(), "receipt-provenance-v2") || !strings.Contains(out.String(), "legacy-checklist-crutch") {
			t.Fatalf("expected added invariant & removed crutch in dry-run output for %s:\n%s", repo, out.String())
		}

		// Apply upgrade to v1.1
		out.Reset()
		errBuf.Reset()
		if code := Run([]string{"upgrade", "--dir", repo, "--target", "org-presets/org-v1.1.yaml", "--apply"}, &out, &errBuf); code != 0 {
			t.Fatalf("apply upgrade failed in %s: %s", repo, errBuf.String())
		}

		// Commit lock + upgraded config
		mustGit(t, repo, "add", ".")
		mustGit(t, repo, "commit", "-m", "upgrade to org-v1.1")

		// Verify frozen CI receipt passes
		out.Reset()
		errBuf.Reset()
		receiptFile := filepath.Join(repo, ".waypost/receipt.v1.json")
		if code := Run([]string{"verify", "--dir", repo, "--mode", "ci", "--frozen", "--base", "HEAD^", "--all", "--receipt", receiptFile, "--format", "json"}, &out, &errBuf); code != 0 {
			t.Fatalf("frozen CI verify failed in %s: %s\nstdout: %s", repo, errBuf.String(), out.String())
		}
		var rec verify.Receipt
		if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
			t.Fatalf("parse receipt json in %s: %v", repo, err)
		}
		if rec.Summary.Outcome != verify.StatusPass || !rec.Policy.LockValid {
			t.Fatalf("unexpected receipt in %s: %+v", repo, rec)
		}
	}

	// Verify context JSON on repoTS reports reverse dependency (api-client -> depended_by: [app-shell]) and pin!
	var ctxOut, ctxErr bytes.Buffer
	if code := Run([]string{"context", "--dir", repoTS, "--format", "json"}, &ctxOut, &ctxErr); code != 0 {
		t.Fatalf("context failed: %s", ctxErr.String())
	}
	var ctxObj ContextOutput
	if err := json.Unmarshal(ctxOut.Bytes(), &ctxObj); err != nil {
		t.Fatal(err)
	}
	foundRev := false
	for _, c := range ctxObj.Components {
		if c.ID == "api-client" && len(c.DependedBy) == 1 && c.DependedBy[0] == "app-shell" {
			foundRev = true
		}
	}
	if !foundRev {
		t.Fatalf("expected api-client depended_by=[app-shell], got %+v", ctxObj.Components)
	}
}

func TestInitCreatesConfigLockAndAgentsPointer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/demo\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("# Existing Agents Guide\nKeep this.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := Run([]string{"init", "--dir", dir}, &out, &errBuf); code != 0 {
		t.Fatalf("init failed: %s", errBuf.String())
	}
	agentsBytes, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	agentsStr := string(agentsBytes)
	if !strings.Contains(agentsStr, "Keep this.") || !strings.Contains(agentsStr, agentsBeginMarker) {
		t.Fatalf("expected preserved AGENTS.md content + waypost pointer block, got:\n%s", agentsStr)
	}
}
