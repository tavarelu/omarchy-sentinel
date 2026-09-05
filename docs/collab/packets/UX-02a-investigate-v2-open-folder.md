# UX-02a Investigate v2 with citations, and open-folder actions
Depends on: W3-02 (merged)          Parallel-safe with: UX-01, UX-03

## Goal
`sentinel-action <id> investigate` shows what fired, the evidence with the source of every fact, commands the user can run to verify it, the limits of what Sentinel could see, where the logs are, and the actions available; `sentinel-action <id> open [--logs]` reveals the alerted file or opens its directory, or the state directory. Old alert rows still render.

## Context (verified)
1. `investigate.format_detail` prints a flat field dump; `page_detail` prints it when not a tty and pipes it to `$PAGER` otherwise; `redact_mapping` drops token/auth/body keys (tests pin this).
2. `store.iter_alerts()` yields rows from the live `alerts.jsonl`; there is no line-number lookup. `store._locked()` exists (W3-02) and must wrap any new reader that must see a consistent file.
3. Alert fields: `id ts rule severity summary pids exe basename cmdline cwd evidence status parent paths writer_pid hashes`. W3-02 adds `evidence.starttime`, `evidence.instance`, `evidence.source` (`sampler`|`launches`), `evidence.launch_ts` for launches. Write alerts have `paths=[path]`, `evidence.path`, `cwd=""`. Watch-lost alerts have `evidence.event` (`IN_DELETE_SELF`|`IN_MOVE_SELF`) and `evidence.path`. Expiry alerts have `evidence.fingerprint`, `expired_scope`, `original_rule`. Child-shell alerts have `evidence.kind`, `child_pids`, `parent_pid` and `parent={pid, exe, basename}`.
4. `action.cmd_menu` prints the action cheat sheet; `cmd_investigate` calls `page_detail` then marks the alert investigated.
5. Opening a folder on this desktop: `uwsm-app -- nautilus --new-window <dir>`; revealing a file: `uwsm-app -- nautilus --select <file:// URI>`; detach with `subprocess.Popen(..., start_new_session=True)`.
6. The journal mirror (W3-07) is not merged yet; the logs section may still print the `journalctl` queries because they are harmless when empty.

## Changes
**`src/sentinel/investigate.py`**
- `@dataclass(frozen=True) class Section: title: str; lines: list[str]`; `SECTION_ORDER = ("What fired", "Evidence", "Verify it yourself", "Limits", "Where the logs are", "Actions")`.
- `RULE_TEXT: dict[str, str]` one line per rule from the spec: R-BYPASS "a known agent binary started with a permission-bypass switch"; R-HOOK-WRITE "a file under a watched agent hooks, settings, mcp or auth root was written, and Sentinel could not attribute the writer"; R-SELF "Sentinel's own config or state was changed, or a watched root vanished"; R-CHILD-SHELL "an agent spawned a surprise shell or network helper"; R-ALLOW-EXPIRE "a 24 h approval expired and the pattern recurred"; R-NEW-AGENT "a new skill, plugin or MCP root appeared (scan result attached when available)".
- `render_sections(alert, *, line_no=None, state_dir=None) -> list[Section]` with per-rule renderers in `_RENDERERS` for R-BYPASS, R-HOOK-WRITE, R-SELF, R-CHILD-SHELL, R-ALLOW-EXPIRE, R-NEW-AGENT and `_render_generic`. Each renderer returns `(what_fired_lines, facts, verify_cmds, limits)`; a fact is `_fact(label, value, source)` rendered as `  label: value    [source]`; `None` values are skipped. Every value passes through `redact_mapping`. Shell commands are built with `shlex.quote` on every alert-derived token.
- Facts and sources per rule:
  - R-BYPASS: matched flag(s) with argv index (`evidence.flags`; compute the index from `cmdline`), pid, exe, cwd, `starttime` and `instance`, `source` (`[/proc/<pid>/cmdline at detection]` or `[launches.jsonl record ts=…]`), `launch_ts`, parent when present.
  - R-HOOK-WRITE / R-SELF (write): path, `hashes[path]` when present, `writer_pid` or "unknown", `evidence.event` when present; source `[inotify event on the parent dir]`.
  - R-SELF (watch lost, expiry, tamper events from W3-07: `foreign-write`, `alert-log-truncated` with `size_before/size_after`): the event, the path, sizes.
  - R-CHILD-SHELL: kind, parent basename and pid, child pid(s) and cmdline, `[/proc tree at detection]`.
  - R-ALLOW-EXPIRE: fingerprint, original rule, expired scope, `[allowlist.json entry removed]`.
  - R-NEW-AGENT: `evidence.scan` fields `tool, version, risk_score, verdict, counts, top[] (title, file, line)`, `report` path; never file contents.
- Verify commands per rule, 2 to 3 each, using only alert data:
  - R-BYPASS: `ps -o pid,lstart,args -p <pid>`; `tr '\0' ' ' < /proc/<pid>/cmdline; echo`; `grep -n '"id":"<id>"' <alerts.jsonl>`; plus `grep -n '"pid":<pid>' <launches.jsonl>` for launches.
  - write rules: `stat -c '%s %y %a' <path>`; `sha256sum <path>` (with "compare with <hash>" when a hash exists); `grep -n -F '"path": "<path>"' <watchlist.json>`.
  - R-CHILD-SHELL: `ps -o pid,ppid,lstart,args -p <parent>,<child>`; `awk '{print $4}' /proc/<child>/stat`.
  - R-ALLOW-EXPIRE: `grep -c <fingerprint> <allowlist.json>` (expect 0); `sentinel-action list`.
  - R-NEW-AGENT: `sed -n 1,40p <report>`; `skillspector scan <root> --no-llm`.
- Limits lines: "writer unknown: inotify reports no PID (writer attribution is W6-04)" for write rules; "the sampler sees a process up to N s after start; kill re-checks the start time" for sampler bypass; "interactive-shell detection is argv-based" for child shell; "recorded before evidence v2; some facts were not captured" when `evidence.get("schema") != 2`; for R-NEW-AGENT "static scan only unless the LLM stage was requested".
- Where the logs are: state dir, `alerts.jsonl` with `(this alert: line N)` when known, `launches.jsonl`, `watchlist.json`, `journalctl --user -t sentinel SENTINEL_ID=<id> -o verbose`, `journalctl --user -u sentinel.service --since '<ts minus 60 s>'`.
- `action_lines(alert) -> list[str]`: approve (with scopes), dismiss, `open`, `open --logs`, `summarize`, plus `kill [--session]` only when the alert has pids. Used by both the Actions section and `cmd_menu`.
- `format_detail(alert, *, line_no=None)` = today's header block followed by the sections; `page_detail(alert, *, line_no=None)` unchanged contract.

**`src/sentinel/store.py`**: `find_alert(alert_id) -> tuple[int, Alert] | None` (1-based line number in the live file, read under `_locked()`); `action.get_alert` uses it and `cmd_investigate` passes `line_no`.

**`src/sentinel/action.py`**: subcommand `open` with `--logs`; `open_target(alert, *, logs=False) -> (mode, Path)` (`("select", file)` if `paths[0]` is an existing file, `("dir", parent)` if it is gone, `("dir", cwd)` otherwise, `("dir", state_dir())` for `--logs`; absolute paths only, else `ValueError`); `open_argv(mode, path)` -> `["uwsm-app","--","nautilus","--select", path.as_uri()]` or `[... "--new-window", str(path)]`; `launch_detached(argv, *, popen=subprocess.Popen)` with `start_new_session=True` and all stdio to `DEVNULL`; `cmd_open` prints `opening <path>` or, when `nautilus` is absent (`shutil.which`), prints the path and returns 1. `cmd_menu` prints `action_lines(alert)`. Add `"open"` to `COMMANDS`.

## Tests (names binding)
`tests/test_investigate.py` (keep existing tests; add fixtures `_bypass_sampler`, `_bypass_launch`, `_hook_write`, `_self_foreign`, `_child_shell`, `_allow_expire`, `_new_agent_scan`, `_legacy_v1`): test_sections_in_order, test_rbypass_sampler_cites_proc_and_flag_index, test_rbypass_launch_cites_launch_record, test_rhook_write_facts_verify_and_limits, test_rself_foreign_write_journal_query, test_rchild_shell_renders_chain_and_kill_target, test_rallow_expire_shows_fingerprint_and_original_rule, test_rnew_agent_scan_shows_score_verdict_report_no_bodies, test_legacy_alert_renders_with_limits_note, test_verify_commands_are_quoted (path `"/tmp/a b'c"`), test_where_logs_uses_xdg_state_home_and_line_number, test_actions_section_matches_menu.
`tests/test_store.py`: test_find_alert_returns_line_number_and_alert, test_find_alert_missing_returns_none.
`tests/test_action.py`: test_open_reveals_existing_file, test_open_falls_back_to_parent_when_file_missing, test_open_uses_cwd_for_process_alert, test_open_logs_opens_state_dir, test_open_refuses_relative_path_and_missing_location, test_open_unknown_alert_fails, test_menu_lists_open_and_logs.

## Acceptance
```
.venv/bin/pytest -q
XDG_STATE_HOME=$(mktemp -d) .venv/bin/python -c "import sys; sys.path.insert(0,'src'); from sentinel.investigate import format_detail; from sentinel.rules import evaluate_process; a=evaluate_process(['claude','--yolo'],'/x/claude','/tmp/a b'); a.pids=[4242]; a.evidence.update(starttime=7,instance='4242:7',source='sampler'); print(format_detail(a))" | grep -c -E "^(What fired|Evidence|Verify it yourself|Limits|Where the logs are|Actions)$"   # expected 6
```

## Fact-check
Claims 1 to 6 against the inline sources.

## Non-goals
Capturing new evidence in the daemon (UX-02b). The panel (UX-03). Notify (UX-01).

## Forbidden
Reading file bodies; printing anything from `~/.config` values; network; new dependencies; changing kill or allowlist semantics.

## Report
`docs/collab/reports/UX-02a-report.md` (PROTOCOL section 5, with the fact-check table).
