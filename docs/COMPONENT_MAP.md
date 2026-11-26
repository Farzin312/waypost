# Component Map ("What Builds on What")

Modern AI coding agents waste thousands of tokens running broad repository greps and still miss cross-component dependencies, cross-repo contracts, and trust boundaries. `waypost context` solves this with a bounded, provenance-tagged **Component Map**.

## Three Provenance Tiers

Every component and dependency edge is labeled explicitly so agents know what is authoritative versus heuristic:

| Provenance | Source | Trust / Limitations |
| --- | --- | --- |
| `declared` | `.waypost.yaml` (`components`, `pins`) | Authoritative; overrides inferred or tool-observed metadata for the same ID/root |
| `inferred` | Safe static manifest parsing (`package.json`, `go.mod` + local `replace`, `Cargo.toml` + local `path` deps, `pyproject.toml`, `tools/`/`scripts/*.py`, `*.uproject`) | Zero repo code execution; covers manifests only, never runtime or engine internals |
| `tool-observed` | Native read-only `.bounds/manifests/*.yaml` ingestion OR opt-in authorized external provider (`authorized: true` + locked in `.waypost.lock`) | `.bounds/manifests/*.yaml` runs zero code; external command providers remain opt-in only |

## Reverse Dependency Closure & Cycle Detection

When `waypost context --changed` or `waypost verify` runs:

1. Changed paths (including both sides of renames and deletions) map to **direct components** (specific subsystem globs win over root `**` catch-alls).
2. Waypost walks reverse `depends_on` edges (`depended_by`) to compute **transitive dependents**—explicitly answering *"what builds on what changed?"*.
3. A 3-color DFS detects any circular component dependencies and surfaces them transparently in `coverage_gaps`.
4. Any overlapping **cross-repo pins** (`{producer, artifact, consumer, compatibility_check}`) trigger their compatibility checks automatically.
5. Any changed path with **zero owning components** is reported in `unmapped_paths` and triggers fail-closed full-repo verification when `fail_closed_on_unmapped: true`.

## Ecosystem & Skill Awareness

`waypost context` also performs a zero-execution ecosystem inventory:

- Detects `AGENTS.md`, `CLAUDE.md`, `.bounds`, `.gitleaks.toml`, `.github/workflows`, and package manager lockfiles (`pnpm`, `bun`, `yarn`, `npm`).
- Discovers local AAIF skills under `.agents/skills/*/SKILL.md` (parsing YAML frontmatter `name` and `description`).
- Flags non-symlink duplicate skill directories in `.claude/skills/` so repositories avoid split-brain skill drift.

## Worked Examples

### 1. TypeScript Mobile/Web App + `.bounds` + Backend Contract Pin (e.g., `clear-answer-app`)

- Static inference reads `package.json` (`expo-router/entry`, `typescript`) without running `npm` or `metro`.
- Native `.bounds/manifests/*.yaml` ingestion reads all subsystem manifests (`api`, `api-hooks`, `auth`, `chat`, `contracts`, `routes`, etc.) and builds the complete reverse-dependency graph with zero code execution.
- `.waypost.yaml` pins the backend OpenAPI/contract artifact (`producer: clear-answer-backend`, `consumer: contracts`, `compatibility_check: contract-compat`) and binds deterministic verification checks.
- See `examples/app-ts/.waypost.yaml`.

### 2. Polyglot Engine / Native Repo (e.g., `dream_realm`)

- Static inference reads `game/*.uproject` (extracting Unreal engine version and runtime module entrypoints) and Python tooling under `tools/` (`tools-python`).
- Waypost **explicitly reports coverage gaps**: static inference does not parse Unreal `Build.cs` graphs, Blueprints, shaders, or binary `.wav`/`.uasset` files.
- `.waypost.yaml` declares deterministic `tools` Python validators, `data` schema checks, and `game` C++ trust paths, while listing unmapped binary art directories transparently so CI escalates safely rather than falsely claiming coverage.
- See `examples/polyglot-native/.waypost.yaml`.
