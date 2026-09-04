# Ledger (single source of truth for state)

Updated by Chief only. Grok reads it; Grok never edits it.

| Field | Value |
|-------|-------|
| Integration branch | `feature/omarchy-sentinel` |
| HEAD at last update | `c015834` |
| Last reviewed range | `..4ebfb5d` (wave 1, R&D + Chief) |
| Unreviewed commits | `e0f2c86`, `30533f6`, `c015834` (wave 2, no R&D audit) |
| Tests | 116 passed on feature; 127 on claude/W3-01 |
| Live install | none; no units, hooks, shims, or menu rows installed |
| Canonical checkout | `~/Work/sentinel` at `1161091` (docs only, no venv); all code is on the feature branch in this worktree |

## Packets

| ID | Title | State | Branch | Report | Verdict |
|----|-------|-------|--------|--------|---------|
| W3-01 | Allowlist and Approve correctness | reported (Chief implemented) | claude/W3-01 | reports/W3-01-report.md | awaiting Grok review |
| W3-02 | One alert per process instance, safe kill, store hygiene | written | | | |
| W3-03 | Scout v2 | written | | | |
| W3-04 | Wire R-CHILD-SHELL | written, waits for W3-02 | | | |
| W3-05 | Vendor bypass table, install truth, click path | written | | | |
| W3-06 | Docs truth (Chief) | in progress | | | |

States: written, running, reported, returned, accepted, escalated.

## Open decisions for Owner

| ID | Question |
|----|----------|
| D-001 | Un-ignore `.superpowers/sdd` and commit the wave 1 and 2 review trail? It contains internal review diffs and briefs that would become public in an open-source repo. |
| D-002 | Public name (Sentinel collides with SentinelOne, Azure Sentinel, and others). |
| D-003 | License (recommend Apache-2.0 or MIT; Apache-2.0 carries an explicit patent grant). |

## Known limits carried into wave 3

- inotify gives no writer PID; the editor allowlist is unreachable in production until W6-04.
- Toast click and menu actions run headless until W3-05.
- Wrapper shims in `~/.local/bin` are shadowed by mise on this machine until W3-05.
