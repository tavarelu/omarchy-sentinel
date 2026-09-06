# TEST-02 Black-box acceptance suite (Grok, sole author)

Depends on: UX-01 (merged), UX-02a (merged)   Parallel-safe with: nothing (run after UX-02a merges)

## Why this packet is different

This is the black-box half of the three-test plan. Claude wrote the unit suite; you write an independent
acceptance suite from the behaviour contract below, *without reading Claude's tests*. If your suite and
Claude's disagree, that disagreement is the finding — record it as an ask, do not edit the other suite.

**Do not open anything under `tests/`.** You may read `src/sentinel/` for public signatures. Everything the
contract depends on is stated below.

## Goal

`tests/acceptance/test_blackbox_grok.py` drives the real CLI and the real `Daemon.emit` inside a temporary
XDG tree, with a stub `omarchy` executable on `PATH` that records the argv it was called with and prints a
notification id. It proves the user-visible behaviour of the alert path end to end.

## Context (verified — fact-check each claim before relying on it)

1. Console scripts (`pyproject.toml` `[project.scripts]`): `sentinel` → `sentinel.cli:main`,
   `sentinel-scout` → `sentinel.cli:scout_main`, `sentinel-action` → `sentinel.cli:action_main`.
   `action_main(argv)` takes an argv list and returns an exit code, so the CLI can be driven in-process.
2. `sentinel-action` subcommands: `approve`, `kill`, `investigate`, `summarize`, `dismiss`, `menu`, `list`,
   `status`, `pause`, `notify`, `open`.
3. Paths come from the environment: `sentinel.paths.state_dir()` honours `XDG_STATE_HOME`, and the config
   path honours `XDG_CONFIG_HOME`. Setting both to a `tmp_path` gives a fully isolated tree.
4. `sentinel.daemon.Daemon(config)` builds its own `Notifier` from the config when no `notify` callable is
   injected; `Daemon.emit(alert)` is the single path an alert takes to the store and the notifier.
5. `sentinel.models.Alert.new(rule=..., severity=..., summary=..., pids=..., exe=..., basename=...,
   cmdline=..., cwd=..., evidence=...)` builds an alert with a fresh id and timestamp.
6. Toasts are sent by running `omarchy notification send …` as an argv array through `subprocess`. A stub
   `omarchy` script placed first on `PATH` therefore observes the exact argv, and what it prints on stdout is
   what the code reads back as the notification id.
7. State files live in `state_dir()`: `alerts.jsonl`, `notify-prefs.json`, `notify-burst.json`, `pause_until`.

## What the suite must prove

Each item is one or more test functions, named for the behaviour, with the assertion made on recorded argv or
on process output — never on internal function calls.

1. **Burst.** Five alerts of the same severity produce five individual toasts; from the sixth on, individual
   toasts stop and a single summary toast carries the totals and is rewritten in place (the replace flag
   carries the id the stub printed). A long enough quiet gap resets the tracker so toasting resumes.
2. **Timeouts.** A high toast asks for 30 s and a medium toast for 15 s, both at normal urgency — a high alert
   is *not* sent as `critical` (a critical toast can never be dismissed by a timer).
3. **Sticky.** A self-tamper alert is sent sticky (critical, no timeout) and is sent *even while paused* and
   even when its severity is switched off in the preferences.
4. **Filter.** `sentinel-action notify --severity high=off` silences high toasts on the next alert and is
   visible in `notify-prefs.json`; `--severity high=on` restores it; `--json` prints the effective policy.
   Preferences may only turn a severity on or off — a preferences file that tries to set an urgency or a
   timeout must not change either.
5. **Investigate.** `sentinel-action <id> investigate` prints the six sections in order (What fired, Evidence,
   Verify it yourself, Limits, Where the logs are, Actions); every evidence fact carries a bracketed source;
   the verify commands quote paths containing spaces; an alert row written before the current evidence schema
   still renders.
6. **Open.** `sentinel-action <id> open` builds an argv that reveals the alerted file, and `open --logs` one
   that opens the state directory; nothing is launched when the file manager is absent — the path is printed
   instead. Assert on the argv the code would run, not by launching a file manager.
7. **Free invariants for every recorded call.** Every argv is a list of `str`, no element contains a newline,
   and no element contains the body of any file.

## Shape

- `tests/acceptance/test_blackbox_grok.py`, plus `tests/acceptance/__init__.py` if the layout needs it.
- One `pytest` fixture builds the isolated tree: `tmp_path` for `XDG_STATE_HOME` and `XDG_CONFIG_HOME`, a
  `bin/omarchy` stub written from the test and made executable, `PATH` prefixed with it, and a helper that
  reads back the recorded argv lines.
- Time is controlled by injecting a clock where the code accepts one; do not `sleep`.
- The whole acceptance suite must run in under 60 s.

## Acceptance

```
.venv/bin/pytest -q                         # full suite green, count in the report
.venv/bin/pytest -q tests/acceptance        # green on its own, under 60 s
```

## Forbidden

Reading or editing anything under `tests/` other than `tests/acceptance/`; editing `src/`; network calls;
new dependencies; `systemctl`, `omarchy`, `sudo`, or any write outside the worktree; asserting on private
functions or monkeypatching internals to make a test pass.

## Report

`docs/collab/reports/TEST-02-report.md` from `docs/collab/reports/TEMPLATE.md`, with the fact-check table for
the Context claims above and, separately, a list of any behaviour that the contract describes but the code
does not do — those are findings, not failures to hide.
