package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Farzin312/waypost/internal/archgraph"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/lockfile"
	"github.com/Farzin312/waypost/internal/remote"
	"github.com/Farzin312/waypost/internal/verify"
	"gopkg.in/yaml.v3"
)

// validateAgainstSchema validates a parsed JSON/YAML value against our Draft 2020-12
// JSON Schema subset exercised by the Waypost schemas.
func validateAgainstSchema(schema map[string]any, val any, path string) []string {
	var errs []string
	if path == "" {
		path = "$"
	}

	if alternatives, ok := schema["anyOf"].([]any); ok {
		matched := false
		for _, candidate := range alternatives {
			if len(validateAgainstSchema(candidate.(map[string]any), val, path)) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			errs = append(errs, fmt.Sprintf("%s: no anyOf branch matched", path))
		}
	}
	if c, ok := schema["const"]; ok {
		if fmt.Sprint(val) != fmt.Sprint(c) {
			errs = append(errs, fmt.Sprintf("%s: got %v, want const %v", path, val, c))
		}
	}
	if enumRaw, ok := schema["enum"].([]any); ok {
		matched := false
		for _, e := range enumRaw {
			if fmt.Sprint(val) == fmt.Sprint(e) {
				matched = true
				break
			}
		}
		if !matched {
			errs = append(errs, fmt.Sprintf("%s: value %v not in enum %v", path, val, enumRaw))
		}
	}

	if reqs, ok := schema["required"].([]any); ok {
		if object, ok := val.(map[string]any); ok {
			for _, r := range reqs {
				key := r.(string)
				if _, exists := object[key]; !exists {
					errs = append(errs, fmt.Sprintf("%s: missing required property %q", path, key))
				}
			}
		}
	}

	if typ, ok := schema["type"].(string); ok {
		switch typ {
		case "object":
			m, ok := val.(map[string]any)
			if !ok {
				return append(errs, fmt.Sprintf("%s: expected object, got %T", path, val))
			}

			if dependencies, ok := schema["dependentRequired"].(map[string]any); ok {
				for field, raw := range dependencies {
					if _, present := m[field]; present {
						for _, dependency := range raw.([]any) {
							if _, found := m[dependency.(string)]; !found {
								errs = append(errs, fmt.Sprintf("%s: %q requires %q", path, field, dependency))
							}
						}
					}
				}
			}
			props, _ := schema["properties"].(map[string]any)
			addlAllowed := true
			if ap, ok := schema["additionalProperties"].(bool); ok {
				addlAllowed = ap
			}
			for k, v := range m {
				if pSchema, ok := props[k].(map[string]any); ok {
					errs = append(errs, validateAgainstSchema(pSchema, v, path+"."+k)...)
				} else if !addlAllowed {
					errs = append(errs, fmt.Sprintf("%s: unexpected property %q (additionalProperties=false)", path, k))
				}
			}
		case "array":
			arr, ok := val.([]any)
			if !ok {
				return append(errs, fmt.Sprintf("%s: expected array, got %T", path, val))
			}
			if minimum, ok := schema["minItems"].(float64); ok && len(arr) < int(minimum) {
				errs = append(errs, fmt.Sprintf("%s: length %d < minItems %g", path, len(arr), minimum))
			}
			if itemSchema, ok := schema["items"].(map[string]any); ok {
				for i, item := range arr {
					errs = append(errs, validateAgainstSchema(itemSchema, item, fmt.Sprintf("%s[%d]", path, i))...)
				}
			}
		case "string":
			s, ok := val.(string)
			if !ok {
				return append(errs, fmt.Sprintf("%s: expected string, got %T", path, val))
			}
			if ml, ok := schema["minLength"].(float64); ok && len(s) < int(ml) {
				errs = append(errs, fmt.Sprintf("%s: string len %d < minLength %d", path, len(s), int(ml)))
			}
			if pat, ok := schema["pattern"].(string); ok && pat != "" {
				re, err := regexp.Compile(pat)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s: invalid schema pattern %q: %v", path, pat, err))
				} else if !re.MatchString(s) {
					errs = append(errs, fmt.Sprintf("%s: string %q does not match pattern %q", path, s, pat))
				}
			}
		case "boolean":
			if _, ok := val.(bool); !ok {
				errs = append(errs, fmt.Sprintf("%s: expected boolean, got %T", path, val))
			}
		case "integer":
			f, ok := val.(float64)
			if !ok || f != float64(int64(f)) {
				errs = append(errs, fmt.Sprintf("%s: expected integer, got %T (%v)", path, val, val))
			} else if minV, ok := schema["minimum"].(float64); ok && f < minV {
				errs = append(errs, fmt.Sprintf("%s: value %v < minimum %v", path, f, minV))
			}
		}
	}
	return errs
}

func loadJSONSchema(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read schema %s: %v", p, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse schema %s: %v", p, err)
	}
	return m
}

func yamlFileToJSONGeneric(t *testing.T, p string) any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read yaml %s: %v", p, err)
	}
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse yaml %s: %v", p, err)
	}
	jb, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal json %s: %v", p, err)
	}
	var out any
	if err := json.Unmarshal(jb, &out); err != nil {
		t.Fatalf("unmarshal json %s: %v", p, err)
	}
	return out
}

func TestJSONSchemaConformanceAcrossConfigsPresetsLockAndReceipt(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repoRoot: %v", err)
	}

	cfgSchema := loadJSONSchema(t, filepath.Join(repoRoot, "schemas", "waypost.v1.schema.json"))
	lockSchema := loadJSONSchema(t, filepath.Join(repoRoot, "schemas", "lock.v1.schema.json"))
	receiptSchema := loadJSONSchema(t, filepath.Join(repoRoot, "schemas", "receipt.v1.schema.json"))

	configFiles := []string{
		filepath.Join(repoRoot, ".waypost.yaml"),
		filepath.Join(repoRoot, "internal", "presets", "base.yaml"),
		filepath.Join(repoRoot, "internal", "presets", "app-ts.yaml"),
		filepath.Join(repoRoot, "internal", "presets", "polyglot-native.yaml"),
		filepath.Join(repoRoot, "examples", "app-ts", ".waypost.yaml"),
		filepath.Join(repoRoot, "examples", "polyglot-native", ".waypost.yaml"),
	}
	for _, cf := range configFiles {
		val := yamlFileToJSONGeneric(t, cf)
		if errs := validateAgainstSchema(cfgSchema, val, filepath.Base(cf)); len(errs) > 0 {
			t.Errorf("schema violations in %s:\n  %s", cf, strings.Join(errs, "\n  "))
		}
	}

	// Validate committed .waypost.lock against lock.v1.schema.json.
	lockVal := yamlFileToJSONGeneric(t, filepath.Join(repoRoot, ".waypost.lock"))
	if errs := validateAgainstSchema(lockSchema, lockVal, ".waypost.lock"); len(errs) > 0 {
		t.Errorf("schema violations in .waypost.lock:\n  %s", strings.Join(errs, "\n  "))
	}

	// Negative check: validator rejects malformed sha256 pattern & null values.
	badLock := map[string]any{
		"lock_version":     "1",
		"schema_version":   "1",
		"resolver_version": "1",
		"config_sha256":    "not-a-sha",
		"policy_digest":    nil,
		"chain":            []any{},
	}
	if errs := validateAgainstSchema(lockSchema, badLock, "bad-lock"); len(errs) < 2 {
		t.Fatalf("expected schema validator to catch invalid sha256 pattern and null property, got %v", errs)
	}

	// Validate live `waypost verify --format json` output against receipt.v1.schema.json.
	tmpRepo := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpRepo, ".waypost.yaml"), `schema_version: "1"
name: schema-demo
extends: builtin:base@1.0.0
components:
  - id: app
    root: .
    paths: ["**"]
checks:
  - id: ok
    command: "echo ok"
    required: true
`)
	var upOut, upErr bytes.Buffer
	if code := Run([]string{"upgrade", "--dir", tmpRepo, "--apply"}, &upOut, &upErr); code != 0 {
		t.Fatalf("upgrade failed: %s", upErr.String())
	}
	var verOut, verErr bytes.Buffer
	if code := Run([]string{"verify", "--dir", tmpRepo, "--frozen", "--all", "--format", "json"}, &verOut, &verErr); code != 0 {
		t.Fatalf("verify failed (%d): %s", code, verErr.String())
	}
	var receiptVal any
	if err := json.Unmarshal(verOut.Bytes(), &receiptVal); err != nil {
		t.Fatalf("parse receipt json: %v", err)
	}
	if errs := validateAgainstSchema(receiptSchema, receiptVal, "receipt.v1.json"); len(errs) > 0 {
		t.Errorf("schema violations in receipt.v1.json:\n  %s", strings.Join(errs, "\n  "))
	}
}

func TestRemotePresetUpgradeOfflineBaseFloorAndLocalEscapeGuard(t *testing.T) {
	t.Setenv("WAYPOST_CACHE_DIR", t.TempDir())
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repoRoot: %v", err)
	}
	lockSchema := loadJSONSchema(t, filepath.Join(repoRoot, "schemas", "lock.v1.schema.json"))

	currentPreset := `schema_version: "1"
name: remote-org-preset
extends: builtin:base@1.0.0
rules:
  - id: remote-org-rule
    kind: invariant
    summary: "Base remote org invariant."
checks:
  - id: org-base-check
    command: "echo remote-base-ok"
    required: true
`
	badRemoteYAML := `schema_version: "1"
name: bad-remote
extends: ../local-secret.yaml
`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/org.yaml":
			_, _ = w.Write([]byte(currentPreset))
		case "/bad.yaml":
			_, _ = w.Write([]byte(badRemoteYAML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	defer remote.SetTestHTTPClient(srv.Client())()

	repoDir := t.TempDir()
	mustWriteFile(t, filepath.Join(repoDir, ".waypost.yaml"), fmt.Sprintf(`schema_version: "1"
name: consumer-repo
extends: %s/org.yaml
components:
  - id: app
    root: .
    paths: ["**"]
`, srv.URL))

	// Step 1: upgrade --apply resolves remote preset over HTTPS, caches it, and pins SHA-256 in .waypost.lock.
	var out, errBuf bytes.Buffer
	if code := Run([]string{"upgrade", "--dir", repoDir, "--apply"}, &out, &errBuf); code != 0 {
		t.Fatalf("upgrade remote preset failed: %s", errBuf.String())
	}
	// Validate generated remote .waypost.lock against lock.v1.schema.json!
	remoteLockVal := yamlFileToJSONGeneric(t, filepath.Join(repoDir, ".waypost.lock"))
	if errs := validateAgainstSchema(lockSchema, remoteLockVal, "remote .waypost.lock"); len(errs) > 0 {
		t.Fatalf("schema violations in remote .waypost.lock: %v", errs)
	}
	lf, _, err := lockfile.Read(repoDir)
	if err != nil {
		t.Fatalf("read lockfile: %v", err)
	}
	if len(lf.Chain) < 2 || lf.Chain[1].Source != "remote" || !remote.IsValidSHA256Hex(lf.Chain[1].SHA256) {
		t.Fatalf("expected locked remote chain step with valid sha256, got %+v", lf.Chain)
	}

	// Commit base branch with base remote preset (org-base-check required).
	runGitCmd(t, repoDir, "init")
	runGitCmd(t, repoDir, "config", "user.email", "test@example.com")
	runGitCmd(t, repoDir, "config", "user.name", "Test")
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "base")
	baseSHA := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	// Step 2: Distinct head commit where remote preset removed org-base-check!
	currentPreset = `schema_version: "1"
name: remote-org-preset
extends: builtin:base@1.0.0
rules:
  - id: remote-org-rule
    kind: invariant
    summary: "Updated remote preset with check removed."
checks: []
`
	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"upgrade", "--dir", repoDir, "--apply"}, &out, &errBuf); code != 0 {
		t.Fatalf("second upgrade failed: %s", errBuf.String())
	}
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "pr-weaken-remote")

	// Shut down server completely: both base & head SHAs are cached!
	srv.Close()

	// Step 3: verify --mode ci --frozen --offline --base <baseSHA> MUST read base:.waypost.lock,
	// detect removal of org-base-check, enforce it from base floor, and pass offline!
	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"verify", "--dir", repoDir, "--mode", "ci", "--frozen", "--offline", "--base", baseSHA, "--format", "json"}, &out, &errBuf); code != 0 {
		t.Fatalf("offline frozen CI verify failed (%d):\nstdout=%s\nstderr=%s", code, out.String(), errBuf.String())
	}
	var rec verify.Receipt
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("parse receipt: %v", err)
	}
	if !rec.Policy.PolicyFloorEnforced || len(rec.Policy.TamperingFindings) == 0 {
		t.Fatalf("expected base remote floor to detect removed org-base-check, got %+v", rec.Policy)
	}

	// Step 4: Verify remote preset extending an EXISTING local file is explicitly blocked by security guard!
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(badRemoteYAML))
	}))
	defer srv2.Close()
	defer remote.SetTestHTTPClient(srv2.Client())()

	parentDir := t.TempDir()
	mustWriteFile(t, filepath.Join(parentDir, "local-secret.yaml"), "schema_version: \"1\"\nname: secret\n")
	badRepo := filepath.Join(parentDir, "repo")
	mustWriteFile(t, filepath.Join(badRepo, ".waypost.yaml"), fmt.Sprintf(`schema_version: "1"
name: bad-consumer
extends: %s/bad.yaml
`, srv2.URL))
	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"upgrade", "--dir", badRepo, "--apply"}, &out, &errBuf); code == 0 {
		t.Fatal("expected remote preset extending local file to be rejected")
	}
	if !strings.Contains(errBuf.String(), "remote preset cannot extend local file path") {
		t.Fatalf("expected specific local-escape error, got: %s", errBuf.String())
	}
}

func TestBoundsManifestChangeEscalatesFullRepoInCI(t *testing.T) {
	repoDir := t.TempDir()
	mustWriteFile(t, filepath.Join(repoDir, ".waypost.yaml"), `schema_version: "1"
name: bounds-trust-demo
extends: builtin:base@1.0.0
components:
  - id: root-app
    root: .
    paths: ["**"]
    checks: ["root-check"]
checks:
  - id: root-check
    command: "echo root-ok"
    components: ["root-app"]
    required: true
`)
	mustWriteFile(t, filepath.Join(repoDir, "src", "app.ts"), "export const x = 1;\n")

	var out, errBuf bytes.Buffer
	if code := Run([]string{"upgrade", "--dir", repoDir, "--apply"}, &out, &errBuf); code != 0 {
		t.Fatalf("upgrade failed: %s", errBuf.String())
	}
	runGitCmd(t, repoDir, "init")
	runGitCmd(t, repoDir, "config", "user.email", "test@example.com")
	runGitCmd(t, repoDir, "config", "user.name", "Test")
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "base")
	baseSHA := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	// PR adds a .bounds manifest trying to shadow src/app.ts away from root-app!
	mustWriteFile(t, filepath.Join(repoDir, ".bounds", "manifests", "shadow.yaml"), `name: shadow
role: library
paths:
  - src
  - .bounds
`)
	mustWriteFile(t, filepath.Join(repoDir, "src", "app.ts"), "export const x = 2;\n")
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "pr-add-bounds")

	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"verify", "--dir", repoDir, "--mode", "ci", "--frozen", "--base", baseSHA, "--format", "json"}, &out, &errBuf); code != 0 {
		t.Fatalf("verify failed (%d): %s", code, errBuf.String())
	}
	var rec verify.Receipt
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("parse receipt: %v", err)
	}
	if !rec.Policy.TrustBoundaryTriggered || !rec.Policy.FullRepoEscalated {
		t.Fatalf("expected .bounds edit to trigger trust boundary and full repo escalation, got %+v", rec.Policy)
	}
	if len(rec.Checks) != 1 || rec.Checks[0].Status != verify.StatusPass {
		t.Fatalf("expected root-check to execute and PASS, got %+v", rec.Checks)
	}
}

func TestSmartInitWithBoundsClaudeMDAndAbsentScripts(t *testing.T) {
	// Case 1: Full TS scripts + .bounds + --claude-md
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")
	mustWriteFile(t, filepath.Join(dir, "package.json"), `{
  "name": "smart-app",
  "scripts": {
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "lint": "eslint ."
  }
}`)
	mustWriteFile(t, filepath.Join(dir, ".bounds", "manifests", "auth.yaml"), "name: auth\nrole: library\npaths:\n  - src/auth\n")

	var out, errBuf bytes.Buffer
	if code := Run([]string{"init", "--dir", dir, "--claude-md"}, &out, &errBuf); code != 0 {
		t.Fatalf("init failed: %s", errBuf.String())
	}

	cfgBytes, err := os.ReadFile(filepath.Join(dir, ".waypost.yaml"))
	if err != nil {
		t.Fatalf("read .waypost.yaml: %v", err)
	}
	cfgText := string(cfgBytes)
	if !strings.Contains(cfgText, "pnpm run typecheck") {
		t.Fatalf("expected pnpm run typecheck in generated config:\n%s", cfgText)
	}
	if strings.Contains(cfgText, "id: auth") {
		t.Fatalf("expected .bounds subsystem 'auth' NOT to be duplicated into .waypost.yaml:\n%s", cfgText)
	}
	claudeBytes, err := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if err != nil || strings.TrimSpace(string(claudeBytes)) != "@AGENTS.md" {
		t.Fatalf("expected CLAUDE.md pointer '@AGENTS.md', got %q (err=%v)", string(claudeBytes), err)
	}

	// Case 2: pnpm repo with ONLY lint script -> must NOT inherit broken npm run typecheck / npm test!
	dir2 := t.TempDir()
	mustWriteFile(t, filepath.Join(dir2, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")
	mustWriteFile(t, filepath.Join(dir2, "package.json"), `{"name": "lint-only", "scripts": {"lint": "eslint ."}}`)
	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"init", "--dir", dir2}, &out, &errBuf); code != 0 {
		t.Fatalf("init lint-only failed: %s", errBuf.String())
	}
	cfg2, _ := os.ReadFile(filepath.Join(dir2, ".waypost.yaml"))
	if strings.Contains(string(cfg2), "builtin:app-ts") {
		t.Fatalf("expected lint-only repo to extend builtin:base rather than app-ts:\n%s", string(cfg2))
	}

	// Case 3: dangling CLAUDE.md symlink pointing outside repo must NEVER be written through!
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "should-not-exist.md")
	dir3 := t.TempDir()
	if err := os.Symlink(outsideTarget, filepath.Join(dir3, "CLAUDE.md")); err == nil {
		out.Reset()
		errBuf.Reset()
		if code := Run([]string{"init", "--dir", dir3, "--claude-md"}, &out, &errBuf); code != 0 {
			t.Fatalf("init with dangling symlink failed: %s", errBuf.String())
		}
		if _, err := os.Stat(outsideTarget); err == nil {
			t.Fatal("init --claude-md followed dangling symlink outside repository!")
		}
	}
}

func mustWriteFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func runGitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return string(out)
}

func TestBuiltInBoundariesVerifyAndBaseFloorTamperingProtection(t *testing.T) {
	repoDir := t.TempDir()
	mustWriteFile(t, filepath.Join(repoDir, "tsconfig.json"), `{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}`)
	mustWriteFile(t, filepath.Join(repoDir, "src", "ui", "btn.ts"), `export const Btn = 1;`)
	mustWriteFile(t, filepath.Join(repoDir, "src", "chat", "screen.ts"), `import { Btn } from "@/ui/btn"; export const s = Btn;`)
	mustWriteFile(t, filepath.Join(repoDir, ".waypost.yaml"), `schema_version: "1"
name: boundaries-demo
extends: builtin:base@1.0.0
boundaries:
  enabled: true
  mode: enforce
  no_cycles: true
  rules:
    - id: ui-no-chat
      from: ui
      deny_depends_on: ["chat"]
      reason: "UI primitives cannot import feature modules"
components:
  - id: ui
    root: src/ui
    paths: ["src/ui/**"]
  - id: chat
    root: src/chat
    paths: ["src/chat/**"]
    depends_on: ["ui"]
`)

	var out, errBuf bytes.Buffer
	if code := Run([]string{"upgrade", "--dir", repoDir, "--apply"}, &out, &errBuf); code != 0 {
		t.Fatalf("upgrade failed: %s", errBuf.String())
	}
	runGitCmd(t, repoDir, "init")
	runGitCmd(t, repoDir, "config", "user.email", "test@example.com")
	runGitCmd(t, repoDir, "config", "user.name", "Test")
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "base")
	baseSHA := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	// Clean base passes built-in waypost-boundaries check!
	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"verify", "--dir", repoDir, "--mode", "ci", "--frozen", "--all", "--format", "json"}, &out, &errBuf); code != 0 {
		t.Fatalf("clean verify failed (%d): %s\n%s", code, errBuf.String(), out.String())
	}
	var cleanRec verify.Receipt
	if err := json.Unmarshal(out.Bytes(), &cleanRec); err != nil {
		t.Fatalf("parse receipt: %v", err)
	}
	if len(cleanRec.Checks) != 1 || cleanRec.Checks[0].ID != "waypost-boundaries" || cleanRec.Checks[0].Status != verify.StatusPass {
		t.Fatalf("expected built-in waypost-boundaries PASS, got %+v", cleanRec.Checks)
	}

	// PR introduces a forbidden ui -> chat import AND tries to downgrade boundaries.mode to warn!
	mustWriteFile(t, filepath.Join(repoDir, "src", "ui", "btn.ts"), `import { s } from "@/chat/screen"; export const Btn = s;`)
	mustWriteFile(t, filepath.Join(repoDir, ".waypost.yaml"), `schema_version: "1"
name: boundaries-demo
extends: builtin:base@1.0.0
boundaries:
  enabled: true
  mode: warn
  no_cycles: false
  rules: []
components:
  - id: ui
    root: src/ui
    paths: ["src/ui/**"]
  - id: chat
    root: src/chat
    paths: ["src/chat/**"]
    depends_on: ["ui"]
`)
	out.Reset()
	errBuf.Reset()
	if code := Run([]string{"upgrade", "--dir", repoDir, "--apply"}, &out, &errBuf); code != 0 {
		t.Fatalf("PR upgrade failed: %s", errBuf.String())
	}
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "pr-break-boundary")

	// CI mode MUST detect boundary tampering, enforce base rule ui-no-chat + no_cycles, and FAIL!
	out.Reset()
	errBuf.Reset()
	code := Run([]string{"verify", "--dir", repoDir, "--mode", "ci", "--frozen", "--base", baseSHA, "--format", "json"}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected CI verify to FAIL on forbidden import + tampered boundary policy; got PASS:\n%s", out.String())
	}
	var failRec verify.Receipt
	if err := json.Unmarshal(out.Bytes(), &failRec); err != nil {
		t.Fatalf("parse fail receipt: %v", err)
	}
	if len(failRec.Policy.TamperingFindings) < 2 {
		t.Fatalf("expected boundary tampering findings, got %+v", failRec.Policy.TamperingFindings)
	}
	if failRec.Summary.Failed == 0 {
		t.Fatalf("expected failed check count > 0, got %+v", failRec.Summary)
	}
}

func TestBoundaryRuleJSONSchemaConformance(t *testing.T) {
	schema := loadJSONSchema(t, filepath.Join("..", "..", "schemas", "waypost.v1.schema.json"))
	for _, tc := range []struct {
		name, rule string
		valid      bool
	}{
		{"allow-list", "from: app, allow_depends_on: [api]", true},
		{"pure-leaf", "from: api, allow_depends_on: []", true},
		{"deny-list", "from: app, deny_depends_on: [internal]", true},
		{"entrypoints", "target: api, public_entrypoints: [src/api/index.ts]", true},
		{"entrypoints-with-caller-scope", "from: 'app-*', target: api, public_entrypoints: [src/api/index.ts]", true},
		{"combined", "from: app, allow_depends_on: [api], target: api, public_entrypoints: [src/api/index.ts]", true},
		{"id-only", "", false},
		{"selector-only", "from: app", false},
		{"target-only", "target: api", false},
		{"deny-without-from", "target: api, deny_depends_on: [internal]", false},
		{"allow-without-from-even-with-public-rule", "allow_depends_on: [], target: api, public_entrypoints: [index.ts]", false},
		{"entrypoints-without-target", "from: app, deny_depends_on: [internal], public_entrypoints: [index.ts]", false},
		{"empty-entrypoints", "target: api, public_entrypoints: []", false},
		{"empty-deny-list", "from: app, deny_depends_on: []", false},
		{"blank-from", "from: '  ', deny_depends_on: [internal]", false},
		{"blank-optional-target", "from: app, allow_depends_on: [], target: ''", false},
		{"null-allow", "from: app, allow_depends_on: null, deny_depends_on: [internal]", false},
		{"numeric-target", "target: 123, public_entrypoints: [index.ts]", false},
		{"non-string-deny-entry", "from: app, deny_depends_on: [1]", false},
		{"unknown-field", "from: app, allow_depends_on: [], unknown: true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf("schema_version: '1'\nboundaries:\n  rules:\n    - {id: rule, %s}\n", tc.rule))
			var yamlDoc any
			if err := yaml.Unmarshal(raw, &yamlDoc); err != nil {
				t.Fatal(err)
			}
			schemaErrors := validateAgainstSchema(schema, yamlDoc, "")
			_, configErr := config.ParseBytes(raw, "boundary conformance fixture")
			if (len(schemaErrors) == 0) != tc.valid || (configErr == nil) != tc.valid {
				t.Fatalf("want valid=%t, schema errors=%v, config error=%v", tc.valid, schemaErrors, configErr)
			}
		})
	}
}

func TestGraphChangedRejectsUnknownBase(t *testing.T) {
	dir := t.TempDir()
	runGitCmd(t, dir, "init", "-b", "main")
	runGitCmd(t, dir, "config", "user.name", "Test")
	runGitCmd(t, dir, "config", "user.email", "test@example.com")
	mustWriteFile(t, filepath.Join(dir, "app.ts"), "export const app = 1;")
	runGitCmd(t, dir, "add", ".")
	runGitCmd(t, dir, "commit", "-m", "base")

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"graph", "--dir", dir, "--changed", "--base", "ref-that-does-not-exist", "--format", "json"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "unable to resolve base ref") || stdout.Len() != 0 {
		t.Fatalf("invalid graph base: exit=%d, stdout=%q, stderr=%q", code, &stdout, &stderr)
	}
}

func TestGraphCheckBoundariesReportsIncompleteScans(t *testing.T) {
	for mode, want := range map[string]int{"enforce": 1, "warn": 0} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			mustWriteFile(t, filepath.Join(dir, config.ConfigFileName), fmt.Sprintf("schema_version: '1'\nboundaries: {enabled: true, mode: %s}\n", mode))
			mustWriteFile(t, filepath.Join(dir, "oversized.ts"), strings.Repeat(" ", 1024*1024+1))
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"graph", "--dir", dir, "--check-boundaries", "--format", "json"}, &stdout, &stderr); code != want {
				t.Fatalf("exit=%d, want %d, stderr=%q", code, want, &stderr)
			}
			var graph archgraph.Report
			if err := json.Unmarshal(stdout.Bytes(), &graph); err != nil {
				t.Fatal(err)
			}
			if graph.FilesScanned != 0 || len(graph.ScanErrors) != 1 || len(graph.Violations) != 1 ||
				graph.Violations[0].RuleID != "incomplete-scan" || (graph.Violations[0].Severity == "error") != (mode == "enforce") {
				t.Fatalf("incomplete scan was not reported: %+v", graph)
			}
		})
	}
}

func TestInitFromBoundsSurfacesSymbolMigrationWarnings(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, ".bounds/manifests/api.yaml"), "name: api\npaths: [src/api]\nexposes: [{name: openAPI, kind: function}]\n")
	mustWriteFile(t, filepath.Join(dir, "src/api/index.ts"), "export function openAPI() {}")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"init", "--dir", dir, "--preset", "base", "--from-bounds"}, &stdout, &stderr); code != 0 {
		t.Fatalf("migration failed: %s", &stderr)
	}
	if !strings.Contains(stdout.String(), `Warning: subsystem "api" has symbol-level exposes restrictions`) {
		t.Fatalf("warning missing from CLI output: %s", &stdout)
	}
	res, err := config.Load(dir, config.LoadOptions{})
	if err != nil || !res.Effective.Boundaries.IsEnabled() || len(res.Effective.Boundaries.Rules) != 1 ||
		res.Effective.Boundaries.Rules[0].PublicEntrypoints[0] != "src/api/index.ts" {
		t.Fatalf("generated policy failed to load public entrypoints: %+v, %v", res, err)
	}
}

func TestPolyglotExampleFrozenLock(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "polyglot-native")
	res, err := config.Load(dir, config.LoadOptions{Mode: "ci", Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if lock := lockfile.Verify(dir, res); !lock.Valid {
		t.Fatalf("example's frozen lock is invalid: %v", lock.Mismatches)
	}
}
