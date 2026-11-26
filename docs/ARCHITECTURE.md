# Waypost Architecture (v1 Contract)

Waypost is a single-binary, pure-Go (`CGO_ENABLED=0`) control plane for **agent-first repositories**. It replaces vendored per-repo delivery scripts and bloated passive markdown rules with three small, deterministic primitives:

1. **Inheritable Policy & Frozen Lockfile** (`.waypost.yaml` + `.waypost.lock`)
2. **Honest Component Map ("What Builds on What")** (`waypost context`)
3. **Fail-Closed Verification & Provenance Receipts** (`waypost verify` → `receipt.v1.json`)

## Strict v1 Scope

Waypost v1 intentionally ships a tight, auditable surface:

- **5 CLI commands:** `init`, `context`, `verify`, `upgrade`, `version`
- **3 versioned JSON schemas:** `waypost.v1.schema.json`, `lock.v1.schema.json`, `receipt.v1.schema.json`
- **3 embedded presets:** `builtin:base@1.0.0`, `builtin:app-ts@1.0.0`, `builtin:polyglot-native@1.0.0`
- **1 composite GitHub Action:** `action/action.yml`

### Explicitly Deferred Beyond v1

To avoid premature complexity, v1 explicitly does **not** include:

- Multi-parent / diamond preset inheritance (v1 enforces single-parent `extends` only)
- Client-specific hook compilers (Claude/Cursor/Codex hook syntax varies across releases)
- Built-in MCP server, cockpit UI, or dashboard server
- Cross-family AI review orchestration or sandbox container runtimes
- Static skill/prompt "security scanners" marketed as security boundaries

## Policy Authority & Threat Model

Passive markdown rules fail reliably under long context and agent drift, and **a pull request can modify `.waypost.yaml`, `.waypost.lock`, check scripts, or CI workflows**. Waypost defends against accidental and adversarial weakening via five rules:

1. **Base-Branch Policy Floor (`--mode ci`):** Waypost reads `git show <base>:.waypost.yaml` and compares required checks and `trust_paths` against the PR head. If a PR removes a required check or downgrades `required: true` to `false`, Waypost records a `tampering_finding`, restores the check from the base floor, and escalates to full repository verification.
2. **Both Sides of Renames & Deletions:** Diff evaluation uses `git diff -M --name-status` and inspects both `old_path` and `new_path` on renames/copies as well as deletions, preventing a PR from moving a file out of a trust boundary to evade checks.
3. **Fail-Closed Escalation:** Unmapped changed paths (when `fail_closed_on_unmapped: true`), missing merge-bases, or edits to `.waypost.yaml`, `.waypost.lock`, `.github/workflows/**`, or `trust_paths` escalate automatically to full repository verification.
4. **Zero Local-Override Leakage in CI:** `.waypost.local.yaml` is gitignored and strictly ignored in `--mode ci` (`local_override_ignored: true` in the receipt).
5. **Honest 4-State Receipts & Redaction:** Every check reports strictly `PASS`, `FAIL`, `WARN`, or `SKIP`. Unavailable required binaries (`requires_bin`) fail closed as `FAIL`, never `PASS` or `SKIP`. Captured excerpts are bounded and scrubbed for common credential patterns before writing `receipt.v1.json`.

## Why Pure Go for Waypost (While Target Apps Stay Polyglot)

Waypost is written in **Pure Go (`CGO_ENABLED=0`)** because the harness itself must run identically on macOS, Linux CI runners, and Windows developer machines with zero Node/Python/Ruby runtime version friction, sub-50ms startup, deterministic cross-compilation, and strong AI-assisted maintainability.

Target applications remain in whatever language best fits their domain (TypeScript/React Native/Expo, Unreal C++, Rust, Python, Go). Waypost never forces an application's stack—it adapts to each repository through presets, static manifest inference, and external tool providers.

## Independent Versioning for Clean Rollback

`cli_version`, `schema_version`, and `resolver_version` are tracked independently in `internal/version`, `.waypost.lock`, and `receipt.v1.json`. Because upgrades only touch `.waypost.yaml` and `.waypost.lock`, `git revert` always restores the previous verified state cleanly.
