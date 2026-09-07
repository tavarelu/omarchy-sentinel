# Contributing

Sentinel is a user-space watchdog for AI coding agents on Omarchy. It is small on purpose: Python
3.12+, standard library only, no runtime dependencies. Please keep it that way.

## Ground rules

- **No new dependencies.** The daemon must stay auditable in one sitting.
- **Metadata only.** Sentinel never reads file bodies, credentials or agent transcripts; paths,
  hashes, pids and argv (after redaction) are the whole evidence model. A change that opens a file
  classified `auth` is a bug, not a feature.
- **No network from the daemon.** The only outbound call in the tree is the opt-in Summarize
  helper; the daemon and rules never import a network module.
- **argv arrays, never shell strings.** Anything that spawns a process passes a list.
- **No silent kills.** Sentinel notifies and gives the user a kill target; it never terminates a
  process on its own.
- **Self-defense stays loud.** Sticky R-SELF alerts bypass pause and notification preferences.

The full list, with the reasoning, is in `AGENTS.md` ("Security invariants").

## Working on a change

```
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

Three suites run together: unit and integration tests, the black-box acceptance suite under
`tests/acceptance/` (written from the spec, not the code), and the adversarial harness under
`tests/joint/` (JSON cases; see `tests/joint/SCHEMA.md`). All three must stay green. Add a test with
every behaviour change; a test that documents a limitation is welcome too.

Larger work is organised as packets: a Goal, a Context section with numbered, checkable claims,
Changes, Tests and Acceptance commands. `docs/collab/PROTOCOL.md` describes the format and
`docs/collab/packets/` has the ones that shipped. You do not need a packet for a bug fix.

## Pull requests

- One topic per PR, with the acceptance commands you ran and their output.
- If you had to deviate from a spec or packet, say so in the PR; a recorded deviation is fine, a
  silent one is not.
- Never commit anything from `~/.config`, `~/.local` or a real `alerts.jsonl`.

Security issues: see `SECURITY.md`.
