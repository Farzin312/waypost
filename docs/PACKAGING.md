# Composing External Agent Tools & Standards

Waypost does **not** reinvent linters, secret scanners, architecture boundary checkers, or skill registries—and it **never vendors thousands of lines of third-party scripts** into your target repositories.

Instead, Waypost composes actively maintained OSS standards and tools through `.waypost.yaml` and `.waypost.lock`:

## Ecosystem Integration Map

| Capability | Standard / OSS Tool | How Waypost Composes It |
| --- | --- | --- |
| Agent Entrypoint | [AGENTS.md](https://agents.md) (AAIF) | `waypost init` manages a compact 8-line `<!-- waypost:begin -->` pointer block while preserving user instructions |
| Reusable Skills | [agentskills.io](https://agentskills.io) | Declared under `skills:` with `id`, `source`, `version`, `kind`, and explicit `authorized: false` default |
| Module Boundary Graphs | `bounds` (or custom JSON graph tools) | Declared under `providers:` with `tool`, `command`, and explicit `authorized: false` default |
| Secret Scanning | `gitleaks` | Declared as a required `check` with `requires_bin: gitleaks` (fails closed if missing in CI) |
| Spend / Budget Guards | `costlock` or repo wrapper scripts | Invoked as standard checks or CI steps alongside `waypost verify` |

## Explicit Execution Authorization Gate

Fetching or referencing an external skill or provider **never auto-executes scripts, prompts, or hooks**:

1. Every `skill` and `provider` defaults to `authorized: false`.
2. `waypost context` reports unauthorized providers transparently without running them.
3. Enabling `authorized: true` (or changing a provider's command) is explicitly surfaced as a **WARNING — permission/authorization change** in `waypost upgrade --dry-run`, pinned in `.waypost.lock`, and rejected in `--mode ci --frozen` if unreviewed/unlocked.
