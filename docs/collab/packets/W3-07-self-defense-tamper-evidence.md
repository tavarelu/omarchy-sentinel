# W3-07 Self-defense: tamper evidence for Sentinel's own state
Depends on: W3-02 (merged)          Parallel-safe with: W3-03, W3-05, UX-02b

## Goal
An agent running as the user cannot silently approve itself, erase alerts, or mute Sentinel. Every alert has an append-only copy in the journal; every change to Sentinel's state files that Sentinel itself did not make raises R-SELF; pauses are capped.

## Context
1. `OPERATIONAL_NAMES` (`src/sentinel/daemon.py:42-50`) makes the daemon ignore writes to `alerts.jsonl`, `allowlist.json`, `allowlist-session.json`, `pause_until` is not even listed but write alerts for it are self-inflicted noise, and `watchlist.json`.
2. `fingerprint()` (`src/sentinel/allowlist.py:20-28`) is sha256 over rule, basename, sorted flags, prefix: any process can compute the key for its own pattern and write it into `allowlist.json`.
3. `is_paused()` (`src/sentinel/action.py:91-99`) honours any future timestamp; a single write silences toasts indefinitely.
4. `consume_launches()` (`src/sentinel/daemon.py:552-553`) already detects truncation of `launches.jsonl` by size; nothing does this for `alerts.jsonl`.
5. journald is append-only for the user; `logger`/the journal socket accept structured fields.

## Changes
- `src/sentinel/journal.py`: `mirror_alert(alert)` writes one structured record to the journal (fields: `SENTINEL_RULE`, `SENTINEL_ID`, `SENTINEL_SEVERITY`, `SENTINEL_SUMMARY`, `SENTINEL_LOCATION`) via the native journal socket (`/run/systemd/journal/socket`, datagram, no dependency), falling back to `logger -t sentinel`. Called from `Daemon.emit` after `append_alert`.
- `src/sentinel/statewatch.py`: `StateLedger` records `(size, mtime_ns, sha256)` after each write Sentinel makes; `check(path)` returns `unchanged | ours | foreign`. The daemon updates the ledger on its own writes; `sentinel-action` announces its writes by sending `{"path":..., "sha256":...}` to a unix datagram socket `state_dir()/control.sock` (mode 0600) the daemon owns, before and after writing. If the socket is absent (daemon down) the CLI writes a nonce file `state_dir()/.cli-writes` the daemon consumes at startup.
- Daemon: writes to any operational file are no longer ignored; they are classified with the ledger. `foreign` → R-SELF high with `evidence={"event":"foreign-write","path":...}`. `alerts.jsonl` shrinking → R-SELF high `"event":"alert-log-truncated"`.
- Pause cap (Chief recommendation 2026-09-06, **confirmed by the Owner the same day**): a pause longer than `pause_max` (config `[notify] pause_max = "24h"`) is not a pause. `sentinel-action pause` refuses a longer duration with exit 2. `is_paused(now)` returns False when `pause_until - now > pause_max`, and the daemon raises R-SELF **high, sticky** once per distinct file content with `evidence={"event":"pause-over-cap","until":...}`, so a mute attempt is loud instead of silent. `Notifier` gains a `wall_clock` and calls `is_paused(now=wall_clock())` so tests and the joint harness can drive it. The committed joint case `harness-sticky-alert-ignores-pause` sets `pause_until` to 2099 and expects the ordinary alert muted; the Chief rewrites it (`tests/joint/` is Chief-owned) to a fixed harness clock with an in-cap pause and adds `harness-overcap-pause-does-not-mute` (pause 2099, one sticky and one ordinary alert, expect two toasts). The alternative, honouring an over-cap pause and merely flagging it, was rejected because one file write would then mute everything except sticky alerts.
- The control socket is an attack surface (squad security finding): any same-uid process, which is exactly the adversary in the threat model, can connect. Therefore the socket accepts only announcements of the form `{"path": <inside state_dir()>, "sha256": ...}` and nothing that changes daemon behaviour (no pause, dismiss, approve or reload); every datagram is received with `SO_PASSCRED` so the sender pid and uid are known; every announcement is mirrored to the journal as `SENTINEL_EVENT=cli-announce` with `SENTINEL_SENDER_PID`; an announcement whose sha256 does not match the file the daemon then observes is classified `foreign`, not `ours`; malformed datagrams are dropped and counted. State plainly in the README that a process which forges a correct announcement defeats the *ours* classification: this is tamper evidence (the journal keeps the sender pid), not prevention, which is a stated non-goal.
- `pause_until` becomes an operational name (removes the self-inflicted alert) but goes through the ledger like the others.

## Tests
- `tests/test_journal.py`: mirror writes to a fake socket path; fallback path used when absent.
- `tests/test_statewatch.py`: ours vs foreign classification; CLI announcement via socket; nonce fallback; a forged announcement with a wrong hash is foreign; a datagram carrying any key other than `path` and `sha256` is dropped; the sender pid reaches the journal record.
- `tests/test_action.py::test_pause_refuses_over_cap` and `tests/test_notify.py::test_is_paused_uses_injected_wall_clock`.
- `tests/test_daemon_coalesce.py`: foreign write to `allowlist.json` → one R-SELF high; truncated `alerts.jsonl` → R-SELF; CLI-announced write → no alert; pause 30d → not paused and one R-SELF medium.

## Acceptance
```
.venv/bin/pytest -q
XDG_STATE_HOME=$(mktemp -d) .venv/bin/python -c "..." # simulate foreign allowlist write while a Daemon instance runs handle_write; expect R-SELF
journalctl --user -t sentinel -n 1 --output=json | jq .SENTINEL_RULE   # after a real emit in a temp XDG (Owner-run)
```

## Fact-check
Claims 1 to 5. For 5, verify the journal socket accepts a datagram from an unprivileged process on this machine.

## Non-goals
- Preventing same-user tampering (impossible without containment; W6-05).
- Signing or encrypting state.

## Forbidden
- Any root helper, setuid, or `chattr +a` requirement.
- Reading alert bodies into the journal beyond the listed fields.

## Report
`docs/collab/reports/W3-07-report.md`
