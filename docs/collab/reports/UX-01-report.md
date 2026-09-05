# UX-01 report
Branch: feature/omarchy-sentinel (Chief implemented directly, after the Grok run was cancelled at its turn cap)
Commit: af74d16   Tests: 183 passed in 1.09s

## Done
- `src/sentinel/notify.py` rewritten around a policy object:
  - `SeverityPolicy(urgency, timeout_ms, enabled)`, `BurstPolicy(threshold=5, window_sec=300, quiet_sec=600)`,
    `NotifyPolicy(high, medium, low, burst, plugin_id)` with `for_severity()`.
  - `STICKY_EVENTS = {"foreign-write", "alert-log-truncated"}` and `is_sticky(alert)`; sticky alerts are sent
    `-u critical` with no `-t`, are not counted by the burst tracker, and ignore both pause and the prefs file.
  - `load_policy(config_path)` reads `[notify]` with `tomllib` and clamps every timeout to 1..30 s (the
    notification server caps expiry at 30 s and ignores `-t` entirely for critical).
  - `load_prefs` / `write_prefs` / `effective_policy`: the prefs file may only flip `enabled` off, never widen
    the policy, never change urgency or timeout. Writes are 0600 temp+rename into a 0700 dir.
  - `run(argv)` captures output with a 5 s timeout and returns stdout or `None` (security review S7).
  - `BurstTracker` (events, counts, `summary_id`, `last_event`) persisted to `notify-burst.json`; `record()`
    returns `"toast"` or `"summary"`, prunes outside `window_sec`, resets after `quiet_sec` of silence.
  - `build_summary_argv` sends `-p` (and `-r <id>` once known) so one toast is rewritten in place, body is
    `"4 high · 2 medium — newest: <80 chars>. Click to open the panel."`, click runs
    `omarchy-shell shell summon tav.sentinel {}`.
  - `Notifier` resolves `run` and `is_paused` at call time (module-level lookup) so the daemon, the tests and
    W3-05's floating terminal can all swap them; `_exec_tail` is the single place W3-05 changes.
- `src/sentinel/daemon.py`: builds `Notifier(load_policy(), clock=wall_clock timestamp)` when no notify callable
  is injected, so burst windows follow the daemon's clock.
- `src/sentinel/action.py`: `sentinel-action notify [--severity SEV=on|off]... [--reset] [--json]` prints the
  effective policy and the source of each flag; this is what the panel chips call.
- `packaging/config.toml`: `[notify]` section with the eight keys, documented inline.

## Tests
`tests/test_notify.py` rewritten (exact argv per severity, sticky without `-t`, clamping, prefs precedence,
corrupt prefs fallback, run timeout), `tests/test_notify_burst.py` new (5 toasts then a summary with `-p`, the
7th replacing with `-r`, zero counts omitted, quiet reset, window pruning, restart restore, stale id, paused and
disabled not counted, `Daemon.emit` driving it through `wall_clock`), `tests/test_config_template.py` new
(template parses and matches the code defaults), plus notify-subcommand cases in `tests/test_action.py`.

## Deviations
- The packet listed `runner` and `paused` as constructor defaults; binding the functions at definition time made
  them unpatchable from the module, so both default to `None` and resolve the module attribute per call.
- The summary toast reuses the high timeout rather than a separate key, so there is one fewer config knob.

## Not done
- Nothing from the packet. The QML chips that call `notify --severity` shipped early with UX-03 and are wired to
  this CLI now.

## Asks
- Owner: confirm live that a high toast clears itself after 30 s and that the sixth alert in a burst collapses
  into one updating summary.
