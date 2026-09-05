# W3-01 report
Branch: claude/W3-01   Commits: 79f7f2f   Tests: 127 passed / 0 failed (from `.venv/bin/pytest -q`)
Implemented by: Chief (Claude), because Grok was unreachable and its usage is metered. Grok's role for this packet is the read-only review (`scripts/collab/grok-review.sh W3-01`).

## Done
- `src/sentinel/keys.py` (new): `alert_location`, `alert_flag_set`, `repo_root`, `approval_prefix`, `candidate_prefixes`. One definition used by both sides.
- `src/sentinel/action.py`: `cmd_approve` keys on `approval_prefix(alert, scope)` and prints the effective prefix; private `_flag_set` removed.
- `src/sentinel/daemon.py`: `_allow_decision` tests the global prefix first, then the location and its parents, reading the allowlist files once; `emit` turns an expired 24h approval into one low `R-ALLOW-EXPIRE` and removes the entry; `run` clears session approvals at startup; `wall_clock` injectable; `allowlist-session.json` is operational.
- `src/sentinel/allowlist.py`: session approvals persisted to `allowlist-session.json` (deleted by `clear_session`); `load_all`, `decide`, `remove`; `_entry_expired`.
- Tests: `tests/test_keys.py` (5), `tests/test_action.py` (+2, one rewritten to a temp git repo), `tests/test_daemon_coalesce.py` (+4).

## Fact-check
| Claim | Verdict | Evidence |
|-------|---------|----------|
| 1 | CONFIRMED | `action.py` keyed `fingerprint(..., alert.cwd)`; cwd is `""` for write rules (`rules.py` evaluate_write sets `cwd=""`). |
| 2 | CONFIRMED | old `_is_alert_allowed` never tested prefix `""` when `paths` existed. |
| 3 | CONFIRMED | reproduced before the change: `False`; after: acceptance prints `True`. |
| 4 | CONFIRMED | reproduced before the change: deeper True, repo root False, other False. |
| 5 | CONFIRMED | `_entry_allows` only checked cwd for this-repo; the prefix lived in the fingerprint. |
| 6 | CONFIRMED | `grep -rn R-ALLOW-EXPIRE src/` was empty; now implemented in `daemon.expired_alert`. |
| 7 (new) | CONFIRMED | session scope was stored in a module dict of the `sentinel-action` process and never reached the daemon; now a file the daemon clears at start. |

## Deviations
- Migration note: `allowlist.json` keeps its shape (`{"entries": {...}}`) and existing entries keep working; the only new file is `allowlist-session.json` in the state dir, treated as operational and deleted by the daemon at startup. No Owner data migration.
- Added claim 7 and its fix (session scope did not survive the process boundary). Not in the packet; it made the `session` scope a no-op in production.
- `summarize._flag_list` left as is: it must keep evidence order for a stable payload; `keys.alert_flag_set` is a set for keying only.
- `is_allowed` kept as a thin wrapper over `decide` for existing tests.

## Not done
- Revoke command (packet non-goal).

## Asks
- none filed by the implementer; the reviewer may file.

## Self-review
- reviewer: Grok Build, READY (`docs/collab/reviews/W3-01-grok-review.md`); its five tasks were applied in the follow-up commit: two new assertions in test_keys, expired_scope assertion, this migration note, and tests/conftest.py isolating XDG for every test.
- auditor: Chief self-check: no file bodies read; daemon imports unchanged except `datetime`; no kill path touched; no secrets. One test initially wrote to the live state dir before the temp env was set; fixed and the stray file removed.

## Acceptance output
```
approved c87427b0-d8bf-4eb6-990b-009207a33706 scope=forever prefix=(any)
write-alert approved suppresses: True
approved d6bd8a8d-7abd-4b51-92b1-88ae1bd4edbf scope=forever prefix=(any)
forever global: True
```
