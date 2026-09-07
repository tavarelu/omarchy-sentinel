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
| W3-03 | Scout v2 | written; revised 2026-09-06 after the squad review (extends `vendors.py` from W3-05, runs after it) | | | |
| W3-04 | Wire R-CHILD-SHELL | written; revised 2026-09-06 (two-pass sampler; child argv redacted, URL-stripped and bounded); after W3-05 | | | |
| W3-05 | Vendor bypass table, install truth, click path | written; revised 2026-09-06 (PATH re-measured, install truth re-argued, owns `vendors.py` and `redact_argv`); first in the queue | | | |
| W3-06 | Docs truth (Chief) | in progress | | | |
| W3-07 | Self-defense: tamper evidence (security review S1) | written; revised 2026-09-06 (pause cap confirmed by the Owner 2026-09-06: an over-cap pause is not a pause; control socket hardened) | | | |
| UX-00 | Hotfix: transient directory churn silent; directory events not writes | accepted, live | feature | | zero alerts from 5 lock-dir cycles against the running daemon |
| UX-01 | Notify policy and burst mode | accepted (Chief implemented after the Grok cancellation) `af74d16`, live-proven 15:18 | feature | reports/UX-01-report.md | 5 toasts + 1 updating summary, all cleared at 30 s |
| UX-02a | Investigate v2 and open-folder | accepted (Grok wrote `964c461`, Chief fixed `743dee3`), merged `0e1fe2e`, deployed live 2026-09-06 01:20 | grok/UX-02a | reports/UX-02a-report.md | Chief READY; ASK-1 and ASK-2 open |
| UX-02b | Evidence v2 capture | written; runs after W3-03, W3-04 and W3-07 merge | | | |
| UX-03 | Panel v2 | done `48b2eeb`, live-smoked 02:24 (chips, folder icons, wrapped legend); card actions await alerts | feature | | screenshot sent to Owner |
| UX-04 | Risk visual canvas | published: https://claude.ai/code/artifact/036d35ed-efe5-4160-9bc0-f795721291f8 | | | D-008 DECIDED 2026-09-06: bar with SAFE / CAUTION / DO NOT INSTALL bands |
| W5-03 | Omarchy plugin (pulled forward) | scaffold live-smoked 2026-09-05: bar count, panel, cards, Dismiss round trip; three bugs fixed; shell restart required after QML edits | feature | | Owner saw screenshots |
| W6-01a | Scanner core | written; revised 2026-09-06 (sanitized report, streamed `tree_hash`, transient-service sandbox verified on this machine, protocol sections added) | | | |
| TEST-02 | Black-box acceptance suite (Grok, sole author) | accepted, merged `99a01c2` 2026-09-06: 19 tests salvaged from the cancelled grok/TEST-02 run | grok/TEST-02 | reports/TEST-02-report.md | Chief READY; 229 green on the merged branch |

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
| 2026-09-05 | UX-01 reassigned to Chief after that cancellation (Owner decision) | n/a | landed as af74d16, 183 tests green, 0 Grok turns spent |
| 2026-09-06 | UX-02a implementation, inline packet + sources, sandbox workspace | 120 | client ended the session on a text-only turn after 16 tool calls ($0.20); the implementation was complete and green but uncommitted |
| 2026-09-06 | two resumes of that session to write the report and commit | 25 each | both ended the same way on the first turn ($0.04 total, no work); the Chief committed Grok's tree and wrote the report |

Lessons: give Grok the material inline and cap turns low for reviews; `--max-turns` counts tool calls, so an implementation packet needs about 100 to 120; never cite line numbers in a packet that Grok will compare against the tree. The headless client (`grok 1.0.13`, `--output-format json`) treats a text-only assistant turn as the end of the prompt and reports `stopReason: cancelled`, so a run can stop mid-packet with its work uncommitted in the worktree: always check `git status` in `.worktrees/grok-<ID>` before concluding a cancelled run produced nothing, and prefer to finish the report and the commit on the Chief side rather than paying for resumes that narrate instead of acting.

## Live evidence log

| When | What | Consequence |
|------|------|-------------|
| 2026-09-05 00:33 to 02:10 | daemon's first 81 min: 132 alerts, 127 of them high R-HOOK-WRITE from one plugin-marketplace refresh at 05:17 UTC, 5 medium R-SELF from Claude Code's lock directory; 1 min 8 s CPU | Owner approved 95 files one by one. UX-00 fixed the lock noise; W3-03 (scout precision) and UX-01 (burst summary) are the fixes for the storm. |
| 2026-09-05 15:18 | UX-01 live proof on the Owner's screen: 7 synthetic high alerts from an isolated XDG dir produced 5 individual toasts, then one summary ("Sentinel: 7 alerts / 7 high — newest: ...") rewritten in place with `-r` for alerts 6 and 7; every toast was gone 34 s later | auto-dismiss and burst mode accepted; panel v2 chips, card, Logs button and wrapped hints verified in the same screenshots |
| 2026-09-06 01:20 | UX-02a deployed to the installed plugin (`omarchy plugin update tav.sentinel --yes`); the live CLI now offers `open`, and `render_sections` was run read-only over the real alerts.jsonl (133 rows) | the R-HOOK-WRITE row for `~/.claude/.credentials.json` renders all six sections with citations, the writer-unknown limit, and its own line number (131); no status was mutated |
| 2026-09-05 02:12 | keying bug found: write-rule approvals with a global scope would have collapsed onto one fingerprint | fixed the same hour; live allowlist was safe (all 95 entries exact-file) |

## Known limits carried into wave 3

- inotify gives no writer PID; the editor allowlist is unreachable in production until W6-04.
- Toast click and menu actions run headless until W3-05.
- Wrapper shims in `~/.local/bin` are shadowed by mise on this machine until W3-05.
