# UX-01 Notify policy and burst mode
Depends on: W3-02 (merged)          Parallel-safe with: UX-02a, UX-03

## Goal
High toasts auto-dismiss after 30 s, medium after 15 s, low never toasts unless enabled; self-tamper alerts stay sticky; after 5 toasts inside a window one summary toast takes over and updates in place, and clicking it opens the panel; a persisted per-severity on/off preference is shared by daemon and panel through `sentinel-action notify`.

## Context (verified on Omarchy 4.0.2)
1. `omarchy-notification-send` flags: `-u low|normal|critical`, `-t <ms>`, `-r <id>` (replace), `-p` (print the new id to stdout), `--app-name`, and `--exec <argv...>` which must be last.
2. The shell ignores `-t` for `critical` (stays until clicked). For `low`/`normal`, `-t` only raises the default (5000 / 8000 ms) and is capped at 30000 ms. Therefore a 30 s high toast is `-u normal -t 30000`; medium is `-u normal -t 15000`; only sticky exceptions use `-u critical`.
3. `-r <id>` rewrites the toast in place and restarts its countdown when summary or body change; an identical re-send is a no-op; a stale id yields a new toast and a new printed id.
4. `Daemon.emit` calls `self._notify(alert)` synchronously after `append_alert`; `cfg["notify"]` is the injection key for a callable; `Daemon` has `_wall_clock` (returns an aware `datetime`).
5. `notify.run(argv)` already returns stdout or `None` and has a 5 s timeout (W3-02).
6. `action.is_paused()` reads `state_dir()/pause_until`. `OPERATIONAL_NAMES` already lists `notify-prefs.json` and `notify-burst.json`.
7. There is no TOML writer in the stdlib; `tomllib` reads only. `fsutil.write_private_atomic` and `ensure_private_dir` exist for 0600/0700 writes.
8. `tests/test_notify.py` currently pins `-u critical` for high and the `--exec` tail; those tests change.

## Changes
Implement exactly the design below in `src/sentinel/notify.py`, `src/sentinel/action.py`, `src/sentinel/daemon.py`, `packaging/config.toml`.

**Policy**
```python
@dataclass(frozen=True) class SeverityPolicy: urgency: str; timeout_ms: int; enabled: bool
@dataclass(frozen=True) class BurstPolicy: threshold: int = 5; window_sec: float = 300.0; quiet_sec: float = 600.0
@dataclass(frozen=True) class NotifyPolicy:
    high = SeverityPolicy("normal", 30_000, True); medium = SeverityPolicy("normal", 15_000, True)
    low = SeverityPolicy("low", 5_000, False); burst = BurstPolicy(); plugin_id = "tav.sentinel"
    def for_severity(self, severity) -> SeverityPolicy   # unknown -> medium
STICKY_EVENTS = frozenset({"foreign-write", "alert-log-truncated"})   # code constant, not configurable
STICKY = SeverityPolicy("critical", 0, True)
def is_sticky(alert) -> bool: alert.rule == "R-SELF" and evidence.get("event") in STICKY_EVENTS
```
- `load_policy(config_path=None) -> NotifyPolicy`: defaults, then `[notify]` from config.toml (`toast_high/medium/low` booleans, `high_timeout/medium_timeout/low_timeout` seconds clamped to 1..30, `burst_threshold`, `burst_window`, `burst_quiet`, `plugin_id`). Urgency is not configurable.
- `load_prefs() -> dict[str,bool] | None` reads `state_dir()/notify-prefs.json` = `{"version":1,"severities":{"high":bool,"medium":bool,"low":bool},"updated":"<iso>"}`; malformed or missing -> None. `write_prefs(severities: dict[str,bool])` merges into the existing file and writes with `write_private_atomic`. `effective_policy(policy, prefs)` returns a policy with only `enabled` replaced.

**Runner and Notifier**
```python
class Notifier:
    def __init__(self, policy=None, *, runner=run, clock=time.time, state_path=None,
                 exec_prefix=("sentinel-action",), prefs_ok=lambda p: True, on_state_write=lambda p: None)
    def send(self, alert) -> None
```
`send` order: `is_sticky` -> critical toast, uncounted, ignores pause and prefs and burst. Then `is_paused()` -> return. Then `sp = effective.for_severity(alert.severity)`; disabled -> return. Then `mode = tracker.record(alert.severity)`; `"toast"` -> individual argv; `"summary"` -> summary argv with `-p` and `-r <summary_id>` when known; parse the printed id (last whitespace token of stdout, int) and store it; keep the old id on failure. Persist the tracker after every counted event. Prefs are re-read only when the file's mtime changes.

`send_alert(alert)` stays a module function over a lazily built module-level `Notifier`. `_exec_tail(alert_id) -> [*exec_prefix, alert_id, "menu"]` is the single place that builds the click argv.

**BurstTracker** (pure; `load(path)`/`save(path)` JSON `{"version":1,"active":bool,"events":[epoch...],"by_severity":{...},"summary_id":int|null,"last_event":epoch|null,"newest_id":str|null}`):
`record(severity)`: if `now - last_event >= quiet_sec` -> `reset()`; prune events older than `window_sec`; append now; count; if not active and `len(events) > threshold` -> active. Return `"summary"` if active else `"toast"`. Corrupt JSON -> start clean. Restart inside the quiet window restores state.

**Exact argv**
- high: `["omarchy","notification","send","-u","normal","-t","30000","--app-name","Sentinel","HIGH: <summary>","<basename> — <why> (<cwd basename>)","--exec","sentinel-action","<id>","menu"]`
- medium: same with `-t 15000`; low (only when enabled): `-u low -t 5000`.
- sticky: `["omarchy","notification","send","-u","critical","--app-name","Sentinel",...,"--exec","sentinel-action","<id>","menu"]` (no `-t`).
- summary: `["omarchy","notification","send","-u","normal","-t","30000","-p", ("-r","<summary_id>" when known), "--app-name","Sentinel","Sentinel: N alerts","<counts> — newest: <summary truncated to 80>. Click to open the panel.","--exec","omarchy-shell","shell","summon","<plugin_id>","{}"]` where `<counts>` joins non-zero parts like `4 high · 2 medium` with ` · `.
Keep today's title/body helpers (`_why`).

**Daemon**: in `Daemon.__init__`, when `cfg["notify"]` is absent build `Notifier(load_policy(), clock=lambda: self._wall_clock().timestamp()).send`.

**CLI** in `action.py`: subcommand `notify` with `--severity SEV=on|off` (repeatable), `--reset`, `--json`. Human output lists each severity with on/off, urgency, timeout, and the source (config or prefs), the sticky rule, the burst numbers, and the prefs path. Bad values exit 1. Add `"notify"` to `COMMANDS`.

**Config** `packaging/config.toml`: add the `[notify]` section with the defaults above and a comment that Omarchy caps non-critical toasts at 30 s.

## Tests (write these; names are binding)
`tests/test_notify.py` (rewrite): test_high_is_normal_with_30s_timeout (exact argv), test_medium_is_normal_with_15s_timeout, test_low_disabled_by_default_no_call, test_low_enabled_by_prefs_uses_low_urgency, test_sticky_self_tamper_is_critical_without_timeout, test_sticky_bypasses_pause_severity_flags_and_burst, test_exec_tail_is_last, test_load_policy_reads_config_section_and_clamps_to_30s, test_prefs_can_only_flip_enabled, test_prefs_corrupt_falls_back_to_config, test_prefs_reloaded_when_mtime_changes, test_unknown_severity_uses_medium_policy, keep test_notify_paused_does_not_call_runner and test_run_swallows_timeout_and_oserror.
`tests/test_notify_burst.py` (new; fake runner records argv and returns "42\n" when `-p` present, later "77\n" for the stale case; clock injected): test_first_five_alerts_toast_individually, test_sixth_alert_sends_summary_with_print_id_and_no_replace, test_seventh_alert_replaces_with_captured_id, test_summary_title_body_and_exec, test_zero_count_severities_omitted_from_body, test_burst_resets_after_quiet_period, test_window_prunes_old_events, test_state_persisted_and_restored_on_restart, test_state_corrupt_starts_clean, test_stale_id_is_replaced_by_new_printed_id, test_paused_and_disabled_alerts_do_not_count, test_runner_failure_keeps_previous_summary_id, test_daemon_emit_drives_notifier_with_wall_clock (six distinct cwds through `Daemon.emit` -> 5 individual + 1 summary).
`tests/test_action.py` (append): test_notify_prints_effective_policy_and_sources, test_notify_severity_writes_prefs_merged_0600, test_notify_rejects_bad_value, test_notify_reset_removes_file, test_notify_json_output.
`tests/test_config_template.py` (new): packaging/config.toml parses and `load_policy(path) == NotifyPolicy()`.

## Acceptance
```
.venv/bin/pytest -q            # all green, including every test named above
grep -n "critical" src/sentinel/notify.py   # only in STICKY and the urgency map
```

## Fact-check
Claims 1 to 8 against the files given inline. Report any REFUTED claim before coding.

## Non-goals
The panel (UX-03), investigate (UX-02a), any daemon rule change, any TOML writing.

## Forbidden
Network calls; reading file bodies; touching `~/.config` or `systemctl`; new dependencies; changing kill or allowlist code.

## Report
`docs/collab/reports/UX-01-report.md` in the format of PROTOCOL section 5, including the fact-check table.
