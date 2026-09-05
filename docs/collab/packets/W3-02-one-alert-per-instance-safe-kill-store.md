# W3-02 One alert per process instance, safe kill, store hygiene
Depends on: none          Parallel-safe with: W3-01, W3-03, W3-05     Blocks: W3-04

## Goal
A long-lived bypass session produces exactly one alert and one toast, Dismiss actually ends the matter for that process, Kill can never signal a recycled PID, and `alerts.jsonl` cannot lose rows or grow without bound.

## Context
1. The sampler re-evaluates every process each tick (`src/sentinel/daemon.py:575-601`) and the only suppression is the 60 s coalescer (`daemon.py:448`). Measured on 2026-09-04 with a fake clock: one `claude --yolo` process over 300 s of ticks produced 5 alerts and 5 toasts, so 60 per hour.
2. Each repeat appends a row to `alerts.jsonl` (`src/sentinel/store.py:17-21`); nothing rotates it.
3. `update_alert_status` rewrites the whole file with `open("w")` and no lock or rename (`store.py:52-54`) while the daemon appends from another process; an append between read and write is lost.
4. `plan_kill` checks only uid (`src/sentinel/kill.py:131-138`). Alerts persist for hours in sticky toasts; a recycled PID owned by the user would be SIGTERMed.
5. `cmd_dismiss` only flips the status of one alert row (`src/sentinel/action.py:175-183`); it cannot stop the sampler from re-alerting the same process.
6. `_is_alert_allowed` re-reads and re-parses `allowlist.json` once per prefix; measured 9 reads for a cwd 7 levels deep (`daemon.py:271-276`, `allowlist.py:35-44`). W3-01 changes the loader; if W3-01 lands first, rebase onto it, otherwise leave the loader alone.
7. `pause_until` is written by `sentinel-action pause` into the state dir and is not in `OPERATIONAL_NAMES` (`daemon.py:39-47`), so pausing produces a high R-SELF alert. Verified with `evaluate_write` on 2026-09-04.
8. `Daemon._self_refresh` is assigned at `daemon.py:362,399,510,534` and never read.

## Changes
- **Process identity.** New `src/sentinel/procinfo.py`: `read_starttime(pid, proc_root="/proc") -> int | None` from field 22 of `/proc/<pid>/stat` (parse after the last `)`), and `instance_key(pid, starttime) -> str`. Every process alert (sampler, launches, and later child-shell) records `evidence["starttime"]` and `evidence["instance"]`.
- **Seen registry.** `Daemon` keeps `self._seen: dict[str, str]` mapping `f"{rule}|{instance}|{sorted flags}"` to the alert id. `emit` for process rules consults it: if seen, no alert, no toast, no row. Registry entries for dead instances are pruned every sampler tick using the current pid list. Write alerts keep using the coalescer only.
- **Dismiss and Kill semantics.** No plumbing needed: one alert per instance means Dismiss is final for that instance. Document this in the `dismiss` help string. Keep the coalescer for write rules.
- **Safe kill.** `plan_kill` takes `expected_starttime: Mapping[int, int] | None`; for each pid, if the alert recorded a starttime and the live starttime differs, treat the pid as already exited (skip, log `pid <n> recycled; skipping`). `cmd_kill` passes the starttimes from `alert.evidence`. Refuse to kill when the alert has pids but no starttime AND the alert is older than 10 minutes, with a clear message, unless `--force-stale` is given.
- **Store.** `update_alert_status` writes to `alerts.jsonl.tmp` and `os.replace`s it, under an `fcntl.flock` on `alerts.lock` that `append_alert` also takes. Add `rotate_if_needed(max_rows=5000, max_bytes=5_000_000)` called from `append_alert`: moves the file to `alerts.jsonl.1` (overwriting a previous `.1`). `iter_alerts` reads only the live file.
- **Allowlist loader.** If W3-01 is not yet merged, add an mtime-keyed cache in `allowlist._load_persisted` so repeated calls within one `_is_alert_allowed` hit the file once.
- **Operational names.** Add `pause_until`, `alerts.lock`, `alerts.jsonl.tmp`, `alerts.jsonl.1` to `OPERATIONAL_NAMES`. Remove `_self_refresh`.

## Tests
- `tests/test_procinfo.py`: parse a fake `/proc/<pid>/stat` with a comm containing spaces and parentheses; missing pid returns None.
- `tests/test_daemon_coalesce.py::test_same_instance_alerts_once`: fake `/proc` with one bypass process; 100 ticks over 300 s of fake clock; exactly 1 alert, 1 toast, 1 row.
- `tests/test_daemon_coalesce.py::test_new_instance_same_pid_alerts_again`: change the fake starttime for the same pid; second alert.
- `tests/test_daemon_coalesce.py::test_seen_registry_prunes_dead`: instance disappears from `/proc`; registry drops it.
- `tests/test_kill.py::test_plan_kill_skips_recycled_pid`: expected starttime differs from live; pid not in plan; message logged.
- `tests/test_kill.py::test_kill_refuses_stale_alert_without_starttime`.
- `tests/test_store.py::test_update_status_survives_concurrent_append`: use a thread that appends while `update_alert_status` runs 200 times; no row lost.
- `tests/test_store.py::test_rotation`.
- `tests/test_daemon_coalesce.py::test_pause_until_write_is_operational`.

## Acceptance
```
.venv/bin/pytest -q
.venv/bin/python - <<'PY'
import os,sys,tempfile; d=tempfile.mkdtemp(); os.environ["XDG_STATE_HOME"]=d; os.environ["XDG_CONFIG_HOME"]=d
sys.path.insert(0,"src")
from sentinel.daemon import Daemon
now=[1000.0]; seen=[]
dm=Daemon({"notify":lambda a: seen.append(a),"inotify":False,"clock":lambda: now[0],"sampler_interval":3.0})
for i in range(100):
    dm.handle_process(["claude","--yolo"],"/x/claude","/home/u/proj",pid=4242,starttime=777); now[0]+=3.0
print("alerts for one instance over 300s:", len(seen))
PY
# expected: 1
grep -c "_self_refresh" src/sentinel/daemon.py   # expected: 0
```

## Fact-check
- Claims 1 through 8. For claim 1 reproduce with the fake clock before changing code.
- Verify field 22 of `/proc/self/stat` is starttime on this kernel (`man 5 proc`), and that it is stable across the process lifetime.

## Non-goals
**Added by security review 2026-09-05 (S3, S7, S8):** create `state_dir()` and `config_dir()` with mode 0700 and write every state file with 0600 (`os.open` + `O_CREAT`, mode 0o600); `notify.run` gets `timeout=5` and swallows `TimeoutExpired` with a journal line; the alert-log rewrite uses a temp file plus `os.replace` under `fcntl.flock`, with rotation at 5 MB. Tests for each.


- R-CHILD-SHELL wiring (W3-04 uses this registry).
- Allowlist keying (W3-01).

## Forbidden
- Any code path that kills without the confirm in `kill.confirm_kill`.
- Reading `/proc/<pid>/environ` or any file under a watched path.

## Report
`docs/collab/reports/W3-02-report.md`
