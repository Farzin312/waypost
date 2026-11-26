# AGENTS.md

`waypost` is a pure-Go (`CGO_ENABLED=0`) CLI for agent-first repository orientation, inheritable delivery policy, and fail-closed verification.

## Core Design Invariants

- Keep `waypost` **100% pure Go (zero CGO)** so single binaries cross-compile cleanly for `darwin`, `linux`, and `windows`.
- Keep `init`, default `context`, `spec`, and `history` static.
- Reproduce bugs at the nearest behavioral seam, observe the failure where feasible, and retain the regression test. Add seam tests for behavior changes.
- Never report `SKIP` or `WARN` as `PASS`, and never let `.waypost.local.yaml` affect `--mode ci`.
- Preserve the v1 command surface (`init`, `context`, `verify`, `upgrade`, `version`) and versioned schemas under `schemas/`.

<!-- waypost:begin -->
## Waypost Contract

- Run `waypost context --changed` to orient and resume work.
- Use `waypost spec --component ID` and `waypost history` for contracts and their changes.
- Inspect architecture with `waypost graph` and reconcile policy with `waypost sync --apply`.
- Run `waypost verify` before reporting completion. Policy lives in `.waypost.yaml` and `.waypost.lock`.
<!-- waypost:end -->
