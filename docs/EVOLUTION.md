# Growing With Newer AI Models & Agents

Agent harnesses rot when temporary model workarounds accumulate forever as permanent ceremony. Waypost is built to **shrink and evolve** as models improve.

## `invariant` vs `crutch` Rules

Every rule and skill in `.waypost.yaml` is tagged with `kind`:

- **`invariant`**: Permanent engineering truth that stays valuable regardless of model capability (e.g., *"never claim completion without a fresh receipt matching the current tree"*, *"edits to trust paths escalate to full verification"*).
- **`crutch`**: Guidance compensating for a current model limitation (e.g., *"run `waypost context --changed` before broad greps"*), paired with an optional `review_after` date.

## Evidence-Based Crutch Pruning

Waypost avoids brittle automated "benchmark probe farms." Instead, crutches are pruned through normal reviewed preset releases:

1. Pick 3–5 real representative tasks from the repository's history.
2. Run a small before/after trial with the crutch removed on current frontier agents.
3. If failure rate and token waste stay flat or improve, remove the crutch in the next preset release (`v1.x`) and roll it out cleanly via `waypost upgrade --dry-run` / `--apply`.

## Universal Agent Compatibility Matrix

Waypost targets open, durable discovery conventions rather than locking into a single IDE or model vendor:

| Agent / Client | Entrypoint | How It Uses Waypost |
| --- | --- | --- |
| Claude Code | `AGENTS.md` / `CLAUDE.md` pointer | Runs `waypost context --changed` & `waypost verify` via shell |
| OpenAI Codex | `AGENTS.md`, `.agents/skills/` | Reads bounded context & attaches `receipt.v1.json` |
| Gemini / Antigravity | `AGENTS.md`, skills | Consumes `--format json` context & receipt outputs |
| OpenCode / Cursor / Pi / Future Agents | `AGENTS.md` + standard CLI | Zero vendor plugins required; standard CLI + JSON schemas |

Because the contract is plain YAML, JSON Schema, and a static CLI binary, **future agents that do not exist yet** can immediately read `AGENTS.md`, run `waypost context --format json`, and verify via `waypost verify --format json`.
