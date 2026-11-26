# AGENTS.md

`waypost` is a pure-Go (`CGO_ENABLED=0`) CLI for agent-first repository orientation, inheritable delivery policy, and fail-closed verification.

## Core Design Invariants

- Keep `waypost` **100% pure Go (zero CGO)** so single binaries cross-compile cleanly for `darwin`, `linux`, and `windows`.
- Never execute repository code during `waypost init` or `waypost context` static manifest inference.
- Never report `SKIP` or `WARN` as `PASS`, and never let `.waypost.local.yaml` affect `--mode ci`.
- Preserve the v1 command surface (`init`, `context`, `verify`, `upgrade`, `version`) and versioned schemas under `schemas/`.

<!-- waypost:begin -->
## Waypost Contract

This repository uses [waypost](https://github.com/Farzin312/waypost) for machine-readable architecture context and deterministic verification.

- Orient before broad searches: `waypost context --changed`
- Verify before claiming completion: `waypost verify`
- Policy & component map source of truth: `.waypost.yaml` (locked in `.waypost.lock`)
<!-- waypost:end -->
