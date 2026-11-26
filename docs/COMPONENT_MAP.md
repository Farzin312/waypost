# Component Map ("What Builds on What")

Modern AI coding agents waste thousands of tokens running broad repository greps and still miss cross-component dependencies, cross-repo contracts, and trust boundaries. `waypost context` solves this with a bounded, provenance-tagged **Component Map**.

## Three Provenance Tiers

Every component and dependency edge is labeled explicitly so agents know what is authoritative versus heuristic:

| Provenance | Source | Trust / Limitations |
| --- | --- | --- |
| `declared` | `.waypost.yaml` (`components`, `pins`) | Authoritative; overrides inferred metadata for the same root |
| `inferred` | Safe static manifest parsing (`package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml`, `*.uproject`) | Zero repo code execution; covers manifests only, never runtime or engine internals |
| `tool-observed` | Authorized external provider (e.g., `bounds report --json`) | Opt-in only (`authorized: true` + locked in `.waypost.lock`) |

## Reverse Dependency Closure

When `waypost context --changed` or `waypost verify` runs:

1. Changed paths (including both sides of renames and deletions) map to **direct components**.
2. Waypost walks reverse `depends_on` edges (`depended_by`) to compute **transitive dependents**—explicitly answering *"what builds on what changed?"*.
3. Any overlapping **cross-repo pins** (`{producer, artifact, consumer, compatibility_check}`) trigger their compatibility checks automatically.
4. Any changed path with **zero owning components** is reported in `unmapped_paths` and triggers fail-closed full-repo verification when `fail_closed_on_unmapped: true`.

## Worked Examples

### 1. TypeScript Mobile/Web App + Backend Contract Pin (e.g., `clear-answer-app`)

- Static inference reads `package.json` (`expo-router/entry`, `typescript`) without running `npm` or `metro`.
- `.waypost.yaml` overlays feature/layer components (`api-client`, `ui-kit`, `app-screens`), declares `app-screens` depends on `api-client` and `ui-kit`, and pins the backend OpenAPI/contract artifact (`producer: org/clear-answer-backend`, `consumer: api-client`, `compatibility_check: contract-compat`).
- Optional `bounds` provider (`bounds report --json`) can be authorized to enrich intra-package dependency edges as `tool-observed`.
- See `examples/app-ts/.waypost.yaml`.

### 2. Polyglot Engine / Native Repo (e.g., `dream_realm`)

- Static inference reads `game/*.uproject` (extracting Unreal engine version and runtime module entrypoints) and `tools/pyproject.toml`.
- Waypost **explicitly reports coverage gaps**: static inference does not parse Unreal `Build.cs` graphs, Blueprints, shaders, or binary `.wav`/`.uasset` files.
- `.waypost.yaml` declares deterministic `tools` Python validators, `data` schema checks, and `game` C++ trust paths, while listing unmapped binary art directories transparently so CI escalates safely rather than falsely claiming coverage.
- See `examples/polyglot-native/.waypost.yaml`.
