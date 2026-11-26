# Composing External Agent Tools & Standards

Waypost does **not** reinvent linters, secret scanners, architecture boundary checkers, or skill registries—and it **never vendors thousands of lines of third-party scripts** into your target repositories.

Instead, Waypost composes actively maintained OSS standards and tools through `.waypost.yaml`, SHA-256-pinned remote presets, and `.waypost.lock`:

## Ecosystem Integration Map

| Capability | Standard / OSS Tool | How Waypost Composes It |
| --- | --- | --- |
| Agent Entrypoint | [AGENTS.md](https://agents.md) (AAIF) | `waypost init` manages a compact `<!-- waypost:begin -->` pointer block while preserving user instructions (optional `--claude-md` creates `@AGENTS.md` pointer) |
| Reusable Skills | [agentskills.io](https://agentskills.io) | Discovered read-only under `.agents/skills/*/SKILL.md` (with `.claude/skills/` duplicate warnings) and declared under `skills:` with `authorized: false` default |
| Module Boundary Graphs | `bounds` (or custom JSON graph tools) | Reads `.bounds/manifests/*.yaml` natively with zero code execution; active CLI providers (`providers:`) stay behind explicit `authorized: true` |
| Shared Org Presets | `github:<owner>/<repo>/<path>@<ref>` or `https://...` | Inherited via single-parent `extends`, SHA-256-pinned in `.waypost.lock`, cached content-addressed under `~/.cache/waypost/presets/`, and verifiable `--offline` |
| Secret Scanning | `gitleaks` | Declared as a required `check` with `requires_bin: gitleaks` (fails closed if missing in CI) |
| Spend / Budget Guards | `costlock` or repo wrapper scripts | Invoked as standard checks or CI steps alongside `waypost verify` |

## Explicit Execution Authorization Gate

Fetching or referencing an external preset, skill, or provider **never auto-executes scripts, prompts, or hooks**:

1. Every `skill` and `provider` defaults to `authorized: false`.
2. `waypost context` reports unauthorized providers transparently without running them.
3. Remote presets cannot extend local filesystem paths, reject HTTPS-to-HTTP redirect downgrades, and fail closed on SHA-256 mismatch or unpinned refs in `--mode ci`, `--frozen`, or `--offline`.
4. Enabling `authorized: true` (or changing a provider's command) is explicitly surfaced as a **WARNING — permission/authorization change** in `waypost upgrade --dry-run`, pinned in `.waypost.lock`, and rejected in `--mode ci --frozen` if unreviewed/unlocked.
