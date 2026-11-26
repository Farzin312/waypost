# waypost

**Agent-first repository orientation, inheritable policy, and deterministic verification — in one pure-Go binary.**

`waypost` replaces thousands of lines of vendored delivery scripts and bloated passive markdown rules with a clean, versioned, lockfile-pinned control plane that works with **every modern and future AI coding agent** (Claude Code, Codex, Gemini, OpenCode, Cursor, Pi, and plain shell agents).

---

## Why Waypost?

Traditional per-repo "AI delivery systems" break down as projects scale:

- **Copy-paste drift:** Vendoring 4,000+ lines of workflow scripts and markdown templates into every repo makes upgrades painful and inconsistent.
- **Bookkeeping churn:** 20–40% of git commits become pure task/status/markdown bookkeeping instead of product engineering.
- **Passive markdown failure:** Long `AGENTS.md` instructions decay under long context; only deterministic checks and CI policy floors actually hold.
- **Blind agents:** Agents waste tokens grepping repositories without knowing *"what builds on what"*, which cross-repo contracts are pinned, or which files sit inside trust boundaries.

`waypost` fixes all four with **5 focused commands**, **1 config file (`.waypost.yaml`)**, **1 frozen lockfile (`.waypost.lock`)**, and **1 provenance-bound verification receipt (`receipt.v1.json`)**.

---

## Architecture

```mermaid
flowchart LR
    Preset["Shared Preset (builtin: or org preset)"] -->|"single-parent extends"| Config[".waypost.yaml"]
    Config -->|"waypost upgrade --apply"| Lock[".waypost.lock (SHA-256 pinned)"]
    Config --> Context["waypost context --changed"]
    Manifests["Static Manifests (package.json, go.mod, Cargo.toml, pyproject.toml, *.uproject)"] -->|"inferred (zero code exec)"| Context
    Providers["Optional Providers (e.g. bounds JSON, authorized: true)"] -->|"tool-observed"| Context
    Context -->|"Components, Reverse Deps, Pins, Coverage Gaps"| Agent["Any AI Agent (AGENTS.md)"]
    Lock --> Verify["waypost verify --mode ci --frozen"]
    Base["git show base:.waypost.yaml (Policy Floor)"] --> Verify
    Verify --> Receipt["receipt.v1.json + PR Markdown"]
```

---

## 60-Second Quickstart

### Install

```bash
go install github.com/Farzin312/waypost/cmd/waypost@latest
```

Or build from source (pure Go, zero CGO):

```bash
git clone https://github.com/Farzin312/waypost.git
cd waypost
CGO_ENABLED=0 go build -o waypost ./cmd/waypost
```

### Initialize a repository

```bash
waypost init
```

`waypost init` safely inspects your manifests without executing repo code, selects a fitting preset (`base`, `app-ts`, or `polyglot-native`), writes `.waypost.yaml` and `.waypost.lock`, and inserts a compact pointer block into `AGENTS.md` (preserving your existing instructions).

### Orient any AI agent ("what builds on what")

```bash
waypost context --changed
waypost context --changed --format json
```

Reports:
- **Components** with explicit provenance (`declared | inferred | tool-observed`), `depends_on`, and reverse `depended_by` (*what builds on this component*)
- **Cross-repo pins** (`producer`, `artifact`, `consumer`, `compatibility_check`)
- **Rules** classified as `invariant` (permanent) vs `crutch` (model-era guidance eligible for pruning)
- **Honest gaps:** explicit `unmapped_paths` and `coverage_gaps`

### Verify deterministically (local or CI)

```bash
# Developer / agent pre-claim check
waypost verify

# Authoritative CI gate with base-branch policy floor & frozen lockfile
waypost verify --mode ci --frozen --base origin/main \
  --receipt .waypost/receipt.v1.json \
  --markdown .waypost/receipt.md
```

### Upgrade shared presets across all repositories

```bash
# Preview exact rule/check diffs & explicit permission-change warnings
waypost upgrade --target ../org-presets/v1.1.yaml --dry-run

# Apply atomically (git revert is always a clean rollback)
waypost upgrade --target ../org-presets/v1.1.yaml --apply
```

---

## Key Guarantees

- **Fail-Closed Policy Authority (`--mode ci`):** Enforces a **base-branch policy floor** (`git show <base>:.waypost.yaml`) so a PR cannot silently delete or weaken required checks. Evaluates **both sides of renames and deletions**, ignores `.waypost.local.yaml` in CI, and escalates unmapped paths or trust-boundary edits to the full repo gate.
- **Honest 4-State Verification:** Strict `PASS | FAIL | WARN | SKIP`. Unavailable required binaries (`requires_bin`) fail closed as `FAIL`, never `PASS` or `SKIP`. Output excerpts are bounded and scrubbed for common secrets before writing `receipt.v1.json`.
- **Inheritable & Composable Without Vendoring:** Single-parent `extends` rejects cycles and duplicate IDs. External tools (`AGENTS.md`, `agentskills.io`, `bounds`, `gitleaks`) are referenced via `.waypost.yaml` and pinned in `.waypost.lock` with an explicit `authorized: true` execution gate.
- **Built to Grow With Newer AI:** Rules and skills distinguish `kind: invariant` from `kind: crutch` so model-era scaffolding can be pruned cleanly across repositories as frontier models improve.
- **Pure Go Harness, Polyglot Target Apps:** `waypost` itself is 100% pure Go (`CGO_ENABLED=0`) for zero-runtime-friction distribution across macOS, Linux, and Windows, while supporting TypeScript, Go, Rust, Python, and Unreal C++/native repositories.

---

## GitHub Action

Use the included composite action in `.github/workflows/ci.yml`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: Farzin312/waypost/action@main
  with:
    frozen: "true"
```

---

## Documentation & Schemas

- [Architecture & Threat Model](docs/ARCHITECTURE.md)
- [Component Map & Real-World Examples](docs/COMPONENT_MAP.md)
- [Growing With Newer AI (`invariant` vs `crutch`)](docs/EVOLUTION.md)
- [Packaging External Tools & Skills](docs/PACKAGING.md)
- JSON Schemas: [waypost.v1](schemas/waypost.v1.schema.json) · [lock.v1](schemas/lock.v1.schema.json) · [receipt.v1](schemas/receipt.v1.schema.json)
- Worked Examples: [TypeScript Mobile App](examples/app-ts/.waypost.yaml) · [Unreal C++ / Python Polyglot](examples/polyglot-native/.waypost.yaml)

## License

MIT — see [LICENSE](LICENSE).
