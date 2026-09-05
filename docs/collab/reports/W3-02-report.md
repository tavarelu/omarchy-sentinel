# W3-02 report
Branch: feature/omarchy-sentinel (Chief implemented directly)   Commits: 72031f6   Tests: 151 passed in 0.89s

## Done
- `src/sentinel/procinfo.py` (new): `read_starttime`, `read_ppid`, `instance_key`.
- `src/sentinel/fsutil.py` (new): `ensure_private_dir` 0700, `open_private` 0600 append/truncate, `write_private_atomic` temp+fsync+rename.
- `src/sentinel/store.py` rewritten: `_locked()` flock on `alerts.lock`, `rotate_if_needed` (5000 rows or 5 MB → `alerts.jsonl.1`), `iter_alerts` skips torn lines, `update_alert_status` atomic under the lock.
- `src/sentinel/daemon.py`: `_seen` registry and `_prune_seen`; `handle_process(..., starttime)` records `evidence.starttime/instance/source`; `coalesce_key` uses the instance for process rules; `OPERATIONAL_NAMES` += pause_until, alerts.lock, alerts.jsonl.tmp, alerts.jsonl.1, notify-prefs.json, notify-burst.json; `_self_refresh` removed; private dirs.
- `src/sentinel/kill.py`: `plan_kill(expected_starttime=, get_starttime=, warn=)` drops recycled pids.
- `src/sentinel/action.py`: `expected_starttimes`, `alert_is_stale`, `--force-stale`, dismiss help text; pause written privately.
- `src/sentinel/wrap_record.py`: launch records carry `starttime`; `launch_to_alert` sets instance, source, launch_ts.
- `allowlist`, `scout`, `health`: private atomic writes. `notify.run`: 5 s timeout, returns stdout or None.

## Fact-check
| Claim | Verdict | Evidence |
|---|---|---|
| 1 | CONFIRMED | acceptance before: 5 alerts / 300 s; after: 1 |
| 2 | CONFIRMED | no rotation existed; now `rotate_if_needed` |
| 3 | CONFIRMED | `open("w")` without lock; test_update_status_survives_concurrent_append passes 200 interleaved appends |
| 4 | CONFIRMED | `plan_kill` checked uid only; now start time |
| 5 | CONFIRMED | dismiss flips one row; one alert per instance makes it final |
| 6 | CONFIRMED | W3-01 landed first; `load_all` reads once per decision |
| 7 | CONFIRMED | pause_until now operational (test_pause_until_write_is_operational) |
| 8 | CONFIRMED | `grep -c _self_refresh` = 0 |
| field 22 | CONFIRMED | /proc/self/stat starttime 6315339 ticks = uptime; stable across reads |

## Deviations
- Coalescer now keys process alerts on the instance (needed so a recycled pid alerts again); floods of distinct instances are UX-01's burst mode.
- `read_starttime` default proc root is /proc; tests pass a fake root.
- Registry prunes by pid presence, not by instance, which is sufficient because a recycled pid gets a new key.

## Not done
- Nothing from the packet. S6/S3/S7/S8 from the security review are included.

## Asks
- none.

## Self-review
- Security: no kill without confirm; nothing under a watched path is read; /proc reads are stat/cmdline/comm/exe/cwd only.
