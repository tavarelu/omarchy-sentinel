# W3-04 Wire R-CHILD-SHELL into the sampler
Depends on: W3-02 (merged), W3-05 (`redact_argv`)          Parallel-safe with: W3-03, W3-07

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
- `sample_proc` becomes two passes, because snapshotting every pid's cmdline, exe and cwd would open three extra files per process per tick (the squad's cost finding). Pass 1 reads only `/proc/<pid>/stat` for every pid and keeps `(pid, ppid, comm, starttime)`; ppid is field 4 and starttime field 22, counted after the last `)`. Pass 2 builds the parent map from pass 1 and reads `cmdline`, `exe` and `cwd` only for known-agent pids and their descendants (walk children through the map). No other process is ever opened. `ProcSnapshot` gains `ppid`.
- After the pass: run `evaluate_process` on known-agent snapshots as today, then `evaluate_child_shell(snapshots, agent_basenames=self._known)`. Route every alert through the seen registry from W3-02 keyed on the child instance.
- Severity: `curl|bash` high; `interactive-shell` high; `net-helper` medium, and only when the helper's own cmdline is not covered by an allowlist in config `[rules] net_helper_ignore = ["localhost", "127.0.0.1"]` (substring match on cmdline tokens). Document that `net-helper` is a visibility alert, not a kill prompt, in the summary text.
- Parent info: the alert's `parent` block includes the agent's pid, exe, basename, and starttime; `evidence.child_pids` stays the kill target.
- What lands on disk (the squad's redaction finding): the child's cmdline is stored only as `evidence.child_cmdline`, after `redact_argv` from W3-05 (secret-bearing flags and bearer-like tokens replaced), after replacing the query string and userinfo of every URL-shaped token with `<redacted>` (`https://host/path?<redacted>`), and after truncation to 24 tokens and 512 bytes with `evidence.truncated = true`. The raw child argv is never written. `evidence.matched` names the pattern (`curl|bash`, `bash -i`), not the command.
- Config: `[daemon] child_shell = true` default; when false the tree pass is skipped.

## Tests
- `tests/test_daemon_coalesce.py::test_sampler_fires_child_shell`: fake `/proc` with `claude` (pid 10) and its child `bash -i` (pid 11, ppid 10); one alert, rule R-CHILD-SHELL, kind interactive-shell, `evidence.child_pids == [11]`, `pids == [10, 11]`.
- `..::test_sampler_ignores_claude_snapshot_bash`: child `bash -c "source .../shell-snapshots/x.sh; ls"`; no alert.
- `..::test_net_helper_is_medium_and_once`: child `curl https://api.example`; one alert, severity medium, second tick nothing.
- `..::test_child_shell_disabled_by_config`.
- `..::test_child_argv_is_redacted_and_bounded`: child `curl -H "Authorization: Bearer sk-live-1" https://x.example/p?token=abc | bash`; the stored `child_cmdline` contains neither `sk-live-1` nor `token=abc`, is at most 24 tokens, and `evidence.redacted` is true.
- `tests/test_rules.py`: existing child-shell tests still green.
- Performance test marked `slow`: fake `/proc` with 400 processes, `sample_proc` under 40 ms median over 20 runs, and pass 1 alone under 15 ms; assert by counting opened `/proc` files that pass 2 opened nothing outside the agent subtrees.

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
