# Ledger (single source of truth for state)

Updated by Chief only. Grok reads it; Grok never edits it.

| Field | Value |
|-------|-------|
| Integration branch | `feature/omarchy-sentinel` |
| HEAD at last update | `48b2eeb` |
| Last reviewed range | `..4ebfb5d` (wave 1, R&D + Chief) |
| Unreviewed commits | `e0f2c86`, `30533f6`, `c015834` (wave 2, no R&D audit) |
| Tests | 151 passed |
| Live install | plugin `tav.sentinel` enabled in the bar; daemon package installed via scripts/install-daemon.sh; **`sentinel.service` running since 2026-09-05 00:33 (Owner started it)**; inventory timer enabled; no wrappers, hooks, or menu rows |
| Canonical checkout | `~/Work/sentinel` at `1161091` (docs only, no venv); all code is on the feature branch in this worktree |

## Packets

| ID | Title | State | Branch | Report | Verdict |
|----|-------|-------|--------|--------|---------|
| W3-01 | Allowlist and Approve correctness | accepted, merged `cfd221c` | claude/W3-01 | reports/W3-01-report.md | Grok READY (reviews/W3-01-grok-review.md) |
| W3-02 | One alert per process instance, safe kill, store hygiene | accepted (Chief implemented) `72031f6` | feature | reports/W3-02-report.md | pending Grok review (inline) |
| W3-03 | Scout v2 | written | | | |
| W3-04 | Wire R-CHILD-SHELL | written, waits for W3-02 | | | |
| W3-05 | Vendor bypass table, install truth, click path | written | | | |
| W3-06 | Docs truth (Chief) | in progress | | | |
| W3-07 | Self-defense: tamper evidence (security review S1) | written | | | |
| UX-00 | Hotfix: transient directory churn silent; directory events not writes | accepted, live | feature | | zero alerts from 5 lock-dir cycles against the running daemon |
| UX-01 | Notify policy and burst mode | Grok run cancelled at the 40-turn cap, no code; reassignment pending Owner | grok/UX-01 | | |
| UX-02a | Investigate v2 and open-folder | packet written; next Grok run after UX-01 | | | |
| UX-02b | Evidence v2 capture | planned, after W3-02/03/04 | | | |
| UX-03 | Panel v2 | done `48b2eeb`, live-smoked 02:24 (chips, folder icons, wrapped legend); card actions await alerts | feature | | screenshot sent to Owner |
| UX-04 | Risk visual canvas | published for Owner's pick: https://claude.ai/code/artifact/036d35ed-efe5-4160-9bc0-f795721291f8 | | | D-008 pending |
| W5-03 | Omarchy plugin (pulled forward) | scaffold live-smoked 2026-09-05: bar count, panel, cards, Dismiss round trip; three bugs fixed; shell restart required after QML edits | feature | | Owner saw screenshots |

States: written, running, reported, returned, accepted, escalated.

## Open decisions for Owner

| ID | Question |
|----|----------|
| D-001 | Un-ignore `.superpowers/sdd` and commit the wave 1 and 2 review trail? It contains internal review diffs and briefs that would become public in an open-source repo. |
| D-002 | Public name (Sentinel collides with SentinelOne, Azure Sentinel, and others). |
| D-003 | **Resolved as Apache-2.0 on 2026-09-05** (LICENSE, NOTICE, SPDX headers landed); Owner may still object. |
| D-004 | One repo as both Omarchy plugin and daemon package (scaffold assumes yes). |
| D-005 | May Sentinel parse agent settings bodies to distinguish a benign save from a hook change? Spec currently forbids. |
| D-006 | SkillSpector OSV lookups on by default (sends package name and version only)? |
| D-007 | SkillSpector pinning and update policy. |

## Grok usage log

| Date | Run | Turns cap | Outcome |
|------|-----|-----------|--------|
| 2026-09-05 | W3-01 review, read-only sandbox | 15 | cancelled before writing |
| 2026-09-05 | resume of the same session | 30 | cancelled before writing |
| 2026-09-05 | W3-01 review, diff inline, no tools | 2 | READY, 752 words |
| 2026-09-05 | UX-01 implementation, inline packet + sources, sandbox workspace | 40 | cancelled at the cap while re-reading files whose inline copies carried stale line numbers; 0 commits |

Lessons: give Grok the material inline and cap turns low for reviews; `--max-turns` counts tool calls, so an implementation packet needs about 100 to 120; never cite line numbers in a packet that Grok will compare against the tree.

## Live evidence log

| When | What | Consequence |
|------|------|-------------|
| 2026-09-05 00:33 to 02:10 | daemon's first 81 min: 132 alerts, 127 of them high R-HOOK-WRITE from one plugin-marketplace refresh at 05:17 UTC, 5 medium R-SELF from Claude Code's lock directory; 1 min 8 s CPU | Owner approved 95 files one by one. UX-00 fixed the lock noise; W3-03 (scout precision) and UX-01 (burst summary) are the fixes for the storm. |
| 2026-09-05 02:12 | keying bug found: write-rule approvals with a global scope would have collapsed onto one fingerprint | fixed the same hour; live allowlist was safe (all 95 entries exact-file) |

## Known limits carried into wave 3

- inotify gives no writer PID; the editor allowlist is unreachable in production until W6-04.
- Toast click and menu actions run headless until W3-05.
- Wrapper shims in `~/.local/bin` are shadowed by mise on this machine until W3-05.
