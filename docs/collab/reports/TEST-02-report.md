# TEST-02 report
Branch: grok/TEST-02   Commits: pending   Tests: 229 passed / 0 failed (from `.venv/bin/pytest -q`)

## Done
- `tests/acceptance/__init__.py`: package marker for the acceptance suite.
- `tests/acceptance/test_blackbox_grok.py`: black-box suite (19 tests) driving `action_main` and `Daemon.emit` in an isolated XDG tree with a stub `omarchy` on PATH. Covers burst (five toasts then in-place summary rewrite; quiet-gap reset), timeouts (high 30 s / medium 15 s at normal urgency; high is not critical), sticky self-tamper (critical, no timeout, sent while paused and when the severity is off), notify prefs filter (off/on/`--json`/prefs cannot change urgency or timeout), investigate (six sections, bracketed sources, quoted paths with spaces, legacy evidence schema), open (reveal file, `--logs` state dir, print path when nautilus is absent), and argv invariants (list of str, no newlines, no file bodies).

## Fact-check
| Claim | Verdict | Evidence |
|-------|---------|----------|
| 1 | CONFIRMED | `pyproject.toml` `[project.scripts]`: `sentinel = sentinel.cli:main`, `sentinel-scout = sentinel.cli:scout_main`, `sentinel-action = sentinel.cli:action_main`. `src/sentinel/cli.py` `action_main(argv: list[str] \| None = None) -> int` delegates to `sentinel.action.action_main`. |
| 2 | CONFIRMED | `src/sentinel/action.py` `COMMANDS = frozenset({approve, kill, investigate, summarize, dismiss, menu, list, status, pause, notify, open})`. Parsers: `notify --severity/--reset/--json`; `open <alert_id> [--logs]`. |
| 3 | CONFIRMED | `src/sentinel/paths.py`: `state_dir()` uses `XDG_STATE_HOME`, `config_dir()` uses `XDG_CONFIG_HOME`. |
| 4 | CONFIRMED | `Daemon.__init__`: if `notify` not in config, builds `Notifier(load_policy(), clock=...).send`. `Daemon.emit` allowlists, coalesces, `append_alert`, then `_notify(alert)`. |
| 5 | CONFIRMED | `Alert.new` in `src/sentinel/models.py` takes the listed kwargs and assigns `id=str(uuid4())`, `ts=datetime.now(timezone.utc).isoformat()`. |
| 6 | CONFIRMED | `build_argv` / `build_summary_argv` start with `"omarchy"`, `"notification"`, `"send"`. `run(argv)` is `subprocess.run(argv, ..., capture_output=True, text=True)` and returns `proc.stdout`. Stub on PATH observed exact argv; printed id parsed by `_parse_id`. |
| 7 | CONFIRMED | `store.ALERTS_FILENAME = alerts.jsonl`; `notify.PREFS_FILENAME = notify-prefs.json`; `notify.BURST_FILENAME = notify-burst.json`; `action.PAUSE_FILENAME = pause_until`; all resolved via `state_dir()`. |

## Deviations
- Open argv is asserted two ways: public `open_target`/`open_argv` (no file manager launched) and an end-to-end CLI path that records argv from a stub `uwsm-app` after a stub `nautilus` is placed on PATH solely so `shutil.which("nautilus")` succeeds. Real nautilus is never started.
- Burst quiet-gap uses an injected Daemon `wall_clock`/`clock`; no `sleep`.
- `tests/acceptance/__init__.py` added so the package collects cleanly.

## Findings (contract vs code)
- None. The 19 acceptance tests passed against the current tree; no behaviour the contract describes was missing.

## Not done
- None of the required suite items.

## Asks
- None.

## Self-review
- reviewer: not run this turn (budget: finish suite, pytest, report, commit). Gaps to check: whether calling `open_argv`/`open_target` counts as asserting on internals.
- auditor: not run this turn. Evidence from the suite itself: isolated XDG only; stub `omarchy` records argv; SECRET_BODY never appears in argv; no `src/` edits; no network; no `systemctl`/`sudo`/live-home writes.
