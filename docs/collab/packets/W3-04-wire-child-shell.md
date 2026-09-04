# W3-04 Wire R-CHILD-SHELL into the sampler
Depends on: W3-02 (seen registry, starttime)          Parallel-safe with: W3-03, W3-05 after W3-02 merges

## Goal
The rule that already exists in `rules.py` fires in production: an agent that spawns an interactive shell, a curl-into-shell, or a bare network helper produces one alert per child instance, with the child as the default kill target, and the sampler stays cheap.

## Context
1. `evaluate_child_shell` is imported nowhere outside `src/sentinel/rules.py` (`grep -rn evaluate_child_shell src/`). The T13 report says so and the STATUS doc repeats it.
2. `sample_proc` (`src/sentinel/daemon.py:575-601`) skips every process whose names are disjoint from the known agent basenames and never reads ppid, so shells and curl children are never seen.
3. `evaluate_child_shell` needs the whole tree with `ppid` (`rules.py:346-403`).
4. Every kind is `severity="high"` (`rules.py:384`), including a bare `curl` (`rules.py:326-327`). Coding agents run `curl` constantly for ordinary API calls, so this is a false-positive generator once live.
5. Sampler cost today: 9.5 ms per tick for 263 processes on the Chief's machine.
6. Claude Code runs every Bash tool call as `bash -c "source ~/.claude/shell-snapshots/...; <cmd>"`; that is a `-c` shell and must not count as interactive.

## Changes
- `sample_proc` collects one `ProcSnapshot` per pid (pid, ppid from `/proc/<pid>/stat` field 4, cmdline, exe, comm, cwd, starttime) in a single pass. Read `stat` once and take both ppid and starttime from it. Keep the cheap early-exit for processes with an empty cmdline (kernel threads).
- After the pass: run `evaluate_process` on known-agent snapshots as today, then `evaluate_child_shell(snapshots, agent_basenames=self._known)`. Route every alert through the seen registry from W3-02 keyed on the child instance.
- Severity: `curl|bash` high; `interactive-shell` high; `net-helper` medium, and only when the helper's own cmdline is not covered by an allowlist in config `[rules] net_helper_ignore = ["localhost", "127.0.0.1"]` (substring match on cmdline tokens). Document that `net-helper` is a visibility alert, not a kill prompt, in the summary text.
- Parent info: the alert's `parent` block includes the agent's pid, exe, basename, and starttime; `evidence.child_pids` stays the kill target.
- Config: `[daemon] child_shell = true` default; when false the tree pass is skipped.

## Tests
- `tests/test_daemon_coalesce.py::test_sampler_fires_child_shell`: fake `/proc` with `claude` (pid 10) and its child `bash -i` (pid 11, ppid 10); one alert, rule R-CHILD-SHELL, kind interactive-shell, `evidence.child_pids == [11]`, `pids == [10, 11]`.
- `..::test_sampler_ignores_claude_snapshot_bash`: child `bash -c "source .../shell-snapshots/x.sh; ls"`; no alert.
- `..::test_net_helper_is_medium_and_once`: child `curl https://api.example`; one alert, severity medium, second tick nothing.
- `..::test_child_shell_disabled_by_config`.
- `tests/test_rules.py`: existing child-shell tests still green.
- Performance test marked `slow`: fake `/proc` with 400 processes, `sample_proc` under 40 ms median over 20 runs.

## Acceptance
```
.venv/bin/pytest -q
.venv/bin/python - <<'PY'
import os,sys,tempfile,time; d=tempfile.mkdtemp(); os.environ["XDG_STATE_HOME"]=d; os.environ["XDG_CONFIG_HOME"]=d
sys.path.insert(0,"src")
from sentinel.daemon import Daemon
dm=Daemon({"notify":lambda a: None,"inotify":False})
t=[]
for _ in range(10):
    t0=time.perf_counter(); dm.sample_proc(); t.append(time.perf_counter()-t0)
t.sort(); print("live sample_proc median ms:", round(t[5]*1000,1))
PY
# expected: under 30 ms on the Chief's machine (263 processes)
```

## Fact-check
- Claims 1 through 6. For 6, run one Bash tool call in Claude Code if available or inspect `~/.claude/shell-snapshots/` names; otherwise mark UNVERIFIED and keep the test.
- Verify `/proc/<pid>/stat` field positions for ppid (4) and starttime (22) from `man 5 proc`.

## Non-goals
- Loop-rate detection (W6-02).
- Network destination inspection.

## Forbidden
- Reading `/proc/<pid>/environ` or `/proc/<pid>/fd/*` targets.
- Any automatic kill.

## Report
`docs/collab/reports/W3-04-report.md`
