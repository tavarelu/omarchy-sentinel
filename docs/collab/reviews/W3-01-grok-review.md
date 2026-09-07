# W3-01 Grok review (read-only, diff inline, 2 turns)

**READY**

## Fact-check (Context 1–6)

| # | Verdict | Evidence |
|---|---------|----------|
| 1 | CONFIRMED | Old `cmd_approve`: `fp = fingerprint(alert.rule, alert.basename, _flag_set(alert), alert.cwd)` then `approve(fp, scope, alert.cwd)`. |
| 2 | CONFIRMED | Fix puts `""` first: `candidate_prefixes("/a/b/c")` → `["", "/a/b/c", "/a/b", "/a", "/"]` (`tests/test_keys.py` last test). Old path was location+parents only, so a `cwd=""` fingerprint could not match a write alert with paths. |
| 3 | CONFIRMED | Report: pre-change `_is_alert_allowed` was `False`. Acceptance: `write-alert approved suppresses: True`. |
| 4 | CONFIRMED | Report: pre-change deeper True, repo root False, `~/Work/scratch` False, `~/Other` False. After: `forever global: True` for `/a/b/c/d`, `/a/b`, `/x/y`. |
| 5 | CONFIRMED | `approval_prefix` is `""` for `session`/`24h`/`forever` (`tests/test_keys.py` `test_approval_prefix_by_scope`); this-repo still goes through `_cwd_matches_prefix`. Other scopes are keyed by the fingerprint prefix, not a cwd check. |
| 6 | CONFIRMED | Pre-change: no `R-ALLOW-EXPIRE` in `src/`. Now `test_24h_expiry_emits_allow_expire_once_then_normal` asserts rule `R-ALLOW-EXPIRE`, severity `low`, then the original `R-BYPASS` after delete. |

## Changes

| Item | Status | Where |
|------|--------|--------|
| `keys.alert_location` | DONE | `tests/test_keys.py` `test_alert_location_process_vs_write` (process cwd vs write `paths[0]` vs empty). |
| `keys.alert_flag_set` | DONE | `action.py` import + `cmd_approve`; `test_alert_flag_set_prefers_evidence_then_cmdline`. |
| `keys.repo_root` | DONE | `test_repo_root_finds_git_dir_from_dir_and_file` (`.git` dir, file path, no-git → self, `""` → `""`). |
| `keys.approval_prefix` | DONE | `action.py` `prefix = approval_prefix(alert, scope)`; four scopes on process; write `this-repo` = exact file path. |
| Delete private location/`_flag_set` copies | PARTIAL | `action.py` `_flag_set` deleted. `summarize._flag_list` kept (ordered payload). Daemon private copy not in the provided hunks; report says both sides use `keys`. |
| `approve(fp, scope, cwd_prefix)` signature | DONE | `cmd_approve` still calls `approve(fp, scope, prefix)`. |
| Daemon candidates `[""] + [location, *parents]`; load once | DONE | `candidate_prefixes`; `load_all()` in `allowlist.py`. Named `decide` / `_allow_decision`, not `is_allowed_in`. |
| `_entry_allows` this-repo prefix; 24h → `expired`; emit `R-ALLOW-EXPIRE`; delete | DONE | `_entry_expired` in `allowlist.py`; daemon test emits one low `R-ALLOW-EXPIRE` with `evidence["fingerprint"]`, entry gone, next event is `R-BYPASS`. |
| Print effective prefix | DONE | `action.py`: `prefix={prefix or '(any)'}`. |
| Distinct `""` vs `/` fingerprints | MISSING | Candidates include both strings; no `fingerprint(..., "") != fingerprint(..., "/")` assertion (packet fact-check). |

Deviation (in scope of Goal “session until daemon restart”, not in Changes list): session moved from a process-local dict to `allowlist-session.json`, cleared at daemon start. Existing `allowlist.json` shape unchanged (`{"entries": ...}`).

## Tests

| Item | Status | Where |
|------|--------|--------|
| `alert_location` / `repo_root` / `approval_prefix` | DONE | `tests/test_keys.py` (5 tests). Write `this-repo` covered; write `session`/`24h`/`forever` inferred (`""` by scope). **R-SELF** not in `approval_prefix` tests. |
| `test_approve_write_alert_suppresses_daemon` | DONE | Report `tests/test_action.py`; acceptance `write-alert approved suppresses: True`. |
| `test_forever_scope_is_global` | DONE | Report `tests/test_daemon_coalesce.py`; acceptance `forever global: True`. |
| `test_this_repo_scope_reaches_repo_root` | DONE | Report `tests/test_daemon_coalesce.py` (+4 there). |
| `test_24h_expiry_emits_allow_expire` | DONE | Relocated to `tests/test_daemon_coalesce.py` `test_24h_expiry_emits_allow_expire_once_then_normal` (not `test_allowlist.py`). Asserts `expired_scope` **not** shown — only `fingerprint` and `low`. |
| `test_summarize_redaction.py` after `_flag_list` removal | PARTIAL | `_flag_list` not removed; redaction suite expected still green. |

## Security invariants

| # | Status | Evidence |
|---|--------|----------|
| 1 | HOLDS | No kill-path edits; `action.py` still imports confirm-kill helpers only. |
| 2 | HOLDS | `R-ALLOW-EXPIRE` evidence is fingerprint (+ intended scope metadata), not file bodies. `repo_root` checks `.git` existence only. |
| 3 | HOLDS | No cloud SDK; report: daemon import delta is `datetime`. |
| 4 | HOLDS | Expiry emits a low alert and drops the entry; no kill. |
| 5 | HOLDS | No credentials/secrets added. |
| 6 | HOLDS | New state file is `state_dir()/allowlist-session.json` (XDG), not `~/.config` / `~/.local/bin`. Tests take `tmp_path`. Report: one test briefly wrote live state, then fixed and stray file removed. No `systemctl`/`omarchy`/`sudo`. |

## Tasks for the Chief

1. Add one assertion that `fingerprint(rule, basename, flags, "") != fingerprint(rule, basename, flags, "/")` (packet fact-check).
2. Assert `approval_prefix` for **R-SELF** `this-repo` is the exact `alert_location` path, not `repo_root` (packet write-rule exception).
3. In `test_24h_expiry_emits_allow_expire_once_then_normal`, assert `evidence["expired_scope"] == "24h"` to match the packet evidence shape.
4. Record the session-file change as the migration note the packet forbids omitting: `allowlist.json` unchanged; new `allowlist-session.json` is operational, deleted on daemon start; no Owner data migration.
5. Grep tests for `approve` / `clear_session` / `state_dir` before `XDG_STATE_HOME` is set, to confirm the live-state write cannot recur.
