# W3-07 Self-defense: tamper evidence for Sentinel's own state
Depends on: W3-02          Parallel-safe with: W3-03, W3-05

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
- Pause cap: `is_paused()` treats any `pause_until` more than `pause_max` (config, default 24h) in the future as invalid, returns False, and the daemon raises R-SELF medium once.
- `pause_until` becomes an operational name (removes the self-inflicted alert) but goes through the ledger like the others.

## Tests
- `tests/test_journal.py`: mirror writes to a fake socket path; fallback path used when absent.
- `tests/test_statewatch.py`: ours vs foreign classification; CLI announcement via socket; nonce fallback.
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
