# Omarchy Sentinel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Track A (Omarchy/T2 health hooks + sticky timer) and Track B (user-space Sentinel control plane: scout, wrappers, rules, notify, Approve/Kill/Investigate) on this MacBook Pro 2019 T2 running Omarchy — without local LLMs, without silent auto-kill, and without reading agent transcript/credential bodies.

**Architecture:** One Python package under `~/Work/sentinel/` with `track-a/` shell hooks and `src/sentinel/` daemon/tools. systemd `--user` runs the daemon and timers. Omarchy hooks call thin scripts. Notifications use `omarchy notification send`; the menu uses `~/.config/omarchy/extensions/omarchy-menu.jsonc`. Cloud Summarize is a separate oneshot in a later task.

**Tech Stack:** Python 3.12+ (stdlib + `inotify_simple` or `watchdog` only if stdlib is insufficient — prefer stdlib `os`/`select` where possible), pytest, systemd user units, Omarchy hooks/menu/notifications, bash wrappers.

**Spec:** `docs/superpowers/specs/2026-09-03-omarchy-sentinel-design.md`

## Global Constraints

- Sentinel runs as **the user**, never root in v1; Kill only user-owned PIDs.
- **No local LLMs**; cloud only on explicit Investigate → Summarize (Task 14).
- Alerts and cloud payloads are **metadata only** — never transcripts, `auth.json` bodies, MCP env/API keys, or settings file bodies.
- Daemon MemoryMax ≈ **256M**; inventory oneshot ≈ **512M**.
- **No battery-low throttle** hook.
- Fingerprint setup is **non-blocking**; Track B ships even if fingerprint fails.
- Prefer `omarchy hook install` and `omarchy notification send` over hand-rolled notify-send.
- TDD: failing test → implement → pass → commit per task.
- Init git in this repo on Task 0 (Work root currently has no git).

---

## File map (create / own)

| Path | Responsibility |
|------|----------------|
| `pyproject.toml` | Package metadata, pytest entry |
| `src/sentinel/__init__.py` | Package version |
| `src/sentinel/paths.py` | XDG config/state paths |
| `src/sentinel/models.py` | Alert, AllowlistEntry dataclasses + JSON ser/de |
| `src/sentinel/store.py` | Append/read `alerts.jsonl`, allowlist, watchlist |
| `src/sentinel/scout.py` | Metadata inventory → `watchlist.json` |
| `src/sentinel/rules.py` | Rule evaluation (R-BYPASS, R-HOOK-WRITE, R-SELF, …) |
| `src/sentinel/allowlist.py` | Keying + scope expiry |
| `src/sentinel/kill.py` | Narrow kill policy |
| `src/sentinel/notify.py` | Wrap `omarchy notification send` |
| `src/sentinel/wrap_record.py` | Helper used by launcher wrappers |
| `src/sentinel/daemon.py` | inotify + sampler loop |
| `src/sentinel/cli.py` | `sentinel` / `sentinel-action` / `sentinel-scout` entrypoints |
| `src/sentinel/investigate.py` | Local detail; later Summarize |
| `wrappers/` | Thin shell wrappers installed onto PATH ahead of real binaries |
| `track-a/hooks/post-boot.d/sentinel-health` | Boot health script |
| `track-a/hooks/post-update.d/sentinel-recheck` | Post-update recheck |
| `track-a/systemd/sentinel-health.{service,timer}` | Health timer units |
| `track-b/systemd/sentinel.{service}` | Daemon unit |
| `track-b/systemd/sentinel-inventory.{service,timer}` | Inventory timer |
| `packaging/omarchy-menu-sentinel.jsonc` | Menu extension snippet to merge |
| `tests/` | pytest suite mirroring modules |
| `~/.config/sentinel/config.toml` | Runtime config (created by install helper, not committed secrets) |
| `~/.local/state/sentinel/` | Runtime state (gitignored locally) |

---

### Task 0: Repo bootstrap

**Files:**
- Create: `pyproject.toml`, `README.md`, `.gitignore`, `src/sentinel/__init__.py`, `src/sentinel/paths.py`, `tests/test_paths.py`
- Create: git repo at `~/Work/sentinel`

**Interfaces:**
- Produces: `sentinel.paths.state_dir() -> Path`, `config_dir() -> Path`, `default_config_path() -> Path`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_paths.py
from pathlib import Path
from sentinel.paths import state_dir, config_dir

def test_state_dir_under_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert state_dir() == tmp_path / "state" / "sentinel"
    assert config_dir() == tmp_path / "config" / "sentinel"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Work/sentinel && python -m pytest tests/test_paths.py -v`  
Expected: FAIL (package / function missing)

- [ ] **Step 3: Minimal implementation + packaging**

```toml
# pyproject.toml
[project]
name = "omarchy-sentinel"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
sentinel = "sentinel.cli:main"
sentinel-scout = "sentinel.cli:scout_main"
sentinel-action = "sentinel.cli:action_main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]
```

```python
# src/sentinel/paths.py
from pathlib import Path
import os

def config_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "sentinel"

def state_dir() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "sentinel"

def default_config_path() -> Path:
    return config_dir() / "config.toml"
```

`.gitignore` must include: `__pycache__/`, `.venv/`, `*.egg-info/`, `.pytest_cache/`, and never commit `~/.config/sentinel` secrets.

- [ ] **Step 4: Install editable + pass tests**

Run:
```bash
cd ~/Work/sentinel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/test_paths.py -v
```
Expected: PASS

- [ ] **Step 5: Init git and commit**

```bash
cd ~/Work/sentinel
git init
git add pyproject.toml README.md .gitignore src/sentinel tests/test_paths.py
git commit -m "chore: bootstrap omarchy-sentinel package and XDG paths"
```

---

### Task 1: Alert model + JSONL store

**Files:**
- Create: `src/sentinel/models.py`, `src/sentinel/store.py`, `tests/test_store.py`

**Interfaces:**
- Produces: `Alert` dataclass; `append_alert(alert: Alert) -> None`; `iter_alerts() -> Iterator[Alert]`; `update_alert_status(id: str, status: str) -> None`
- Status enum strings exactly: `open|approved|killed|investigated|dismissed`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_store.py
from sentinel.models import Alert
from sentinel.store import append_alert, iter_alerts, update_alert_status

def test_append_and_read_alert(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    a = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with bypassPermissions",
        pids=[1234],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd="~/Work/scratch",
        evidence={"flag": "bypassPermissions"},
    )
    append_alert(a)
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-BYPASS"
    assert rows[0].status == "open"
    update_alert_status(a.id, "approved")
    assert list(iter_alerts())[0].status == "approved"
```

- [ ] **Step 2: Run to verify fail** — `pytest tests/test_store.py -v`

- [ ] **Step 3: Implement `Alert` + store**

`Alert.new(...)` must generate `uuid4` and ISO-8601 `ts`.  
`append_alert` writes one JSON object per line to `state_dir()/alerts.jsonl`.  
`update_alert_status` rewrites the file (v1: small files OK) matching by `id`.  
Do **not** include fields for file bodies or tokens.

- [ ] **Step 4: Pass tests** — `pytest tests/test_store.py -v`

- [ ] **Step 5: Commit** — `git commit -m "feat: alert model and jsonl store"`

---

### Task 2: Allowlist keying and scopes

**Files:**
- Create: `src/sentinel/allowlist.py`, `tests/test_allowlist.py`

**Interfaces:**
- Produces: `fingerprint(rule, basename, flag_set, cwd_prefix) -> str`
- Produces: `is_allowed(fp, cwd: str, now=None) -> bool`
- Produces: `approve(fp, scope: Literal["session","24h","this-repo","forever"], cwd_prefix: str) -> None`
- Consumes: `state_dir()` for `allowlist.json`

- [ ] **Step 1: Failing tests**

```python
def test_this_repo_scope_matches_prefix_only(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    from sentinel.allowlist import fingerprint, approve, is_allowed
    fp = fingerprint("R-BYPASS", "claude", frozenset(["--dangerously-skip-permissions"]), "~/Work/scratch")
    approve(fp, "this-repo", "~/Work/scratch")
    assert is_allowed(fp, "~/Work/scratch/pkg") is True
    assert is_allowed(fp, "~/Work/prod") is False
```

Also test `24h` expiry (freeze time with a `now=` argument) and `session` cleared by `clear_session()`.

- [ ] **Step 2–4:** Implement → pass → commit `feat: allowlist scopes session/24h/this-repo/forever`

---

### Task 3: Scout → generated watch list

**Files:**
- Create: `src/sentinel/scout.py`, `tests/test_scout.py`, fixtures under `tests/fixtures/fake_home/`

**Interfaces:**
- Produces: `scout(home: Path, seeds: list[str] | None = None) -> dict` writing kinds `settings|hooks|mcp|auth|other`
- Produces: `write_watchlist(result) -> Path`
- Must **not** read file bodies — only path, size, mtime, kind heuristics from filename/dirname

- [ ] **Step 1: Failing test with temp home**

Create dirs: `fake_home/.claude/settings.json` (empty file), `fake_home/.claude/hooks/x.sh`, `fake_home/.codex/auth.json`.  
Assert scout classifies `settings`, `hooks`, `auth` and never opens content (monkeypatch `Path.read_text` to raise if called).

- [ ] **Step 2–4:** Implement classification heuristics:
  - name contains `hook` → `hooks`
  - name in `{settings.json,settings.local.json}` → `settings`
  - name contains `auth` or `credentials` → `auth` (metadata only)
  - name contains `mcp` → `mcp`
  - else → `other`  
  Missing seeds skip quietly.  
  Commit: `feat: sentinel-scout metadata watchlist`

- [ ] **Step 5: Wire CLI** `sentinel-scout --refresh` in `cli.py` calling scout + write under `state_dir()/watchlist.json`. Smoke: `sentinel-scout --refresh` against real home should exit 0 and print path count.

---

### Task 4: Rule engine (MVP: R-BYPASS, R-HOOK-WRITE, R-SELF)

**Files:**
- Create: `src/sentinel/rules.py`, `tests/test_rules.py`

**Interfaces:**
- Produces: `evaluate_process(cmdline: list[str], exe: str, cwd: str) -> Alert | None`
- Produces: `evaluate_write(path: Path, writer_pid: int | None, writer_exe: str | None) -> Alert | None`
- Bypass flag set (normalize): `--dangerously-skip-permissions`, `bypassPermissions`, `--yolo`, `trust-all`, `--trust-all`, and config-driven extras

- [ ] **Step 1: Failing tests**

```python
def test_rbypass_detects_skip_permissions():
    from sentinel.rules import evaluate_process
    alert = evaluate_process(
        ["claude", "--dangerously-skip-permissions"],
        "/usr/bin/claude",
        "/tmp/scratch",
    )
    assert alert is not None
    assert alert.rule == "R-BYPASS"

def test_rself_on_sentinel_config(tmp_path):
    from sentinel.rules import evaluate_write
    p = tmp_path / "config.toml"
    p.write_text("x=1\n")
    alert = evaluate_write(p, writer_pid=9, writer_exe="/usr/bin/nano", self_paths=[tmp_path])
    assert alert is not None and alert.rule == "R-SELF"
```

- [ ] **Step 2–4:** Implement; ignore writes when `writer_exe` basename is in an editor allowlist only for **non-self** paths (self paths always alert). Commit `feat: MVP rules R-BYPASS R-HOOK-WRITE R-SELF`

---

### Task 5: Launcher wrappers (primary R-BYPASS path)

**Files:**
- Create: `wrappers/sentinel-wrap`, `src/sentinel/wrap_record.py`, `tests/test_wrap_record.py`
- Create: install helper `scripts/install-wrappers.sh`

**Interfaces:**
- Produces: wrapper records argv to `state_dir()/launches.jsonl` then `exec`s real binary from `SENTINEL_REAL_<NAME>` or next PATH hit outside wrappers dir
- Produces: daemon/reader can convert a launch record into `evaluate_process`

- [ ] **Step 1: Test wrap_record parses flags without executing**

```python
def test_extract_flags():
    from sentinel.wrap_record import extract_bypass_flags
    flags = extract_bypass_flags(["claude", "--dangerously-skip-permissions", "do stuff"])
    assert "--dangerously-skip-permissions" in flags
```

- [ ] **Step 2–4:** Implement shell wrapper:

```bash
#!/usr/bin/env bash
# wrappers/sentinel-wrap — usage: sentinel-wrap <basename> -- "$@"
set -euo pipefail
BASE="$1"; shift
# record via python -m sentinel.wrap_record "$BASE" -- "$@"
# then exec real binary
```

Install by putting `~/.local/bin/claude` → wrapper only when user opts in via `scripts/install-wrappers.sh claude`. Never overwrite without backup.

Commit: `feat: launcher wrappers record bypass flags`

---

### Task 6: Daemon loop — inotify + sampler backup

**Files:**
- Create: `src/sentinel/daemon.py`, `tests/test_daemon_coalesce.py`
- Modify: `src/sentinel/cli.py` (`sentinel daemon` / `sentinel run`)

**Interfaces:**
- Consumes: watchlist paths, rules, allowlist, store, notify (stub OK until Task 7)
- Produces: `run_forever(config)` loop; coalesce duplicate alerts 60s; sampler interval 2–5s from config

- [ ] **Step 1: Unit-test coalesce keying**

```python
def test_coalesce_suppresses_duplicate_within_window():
    from sentinel.daemon import Coalescer
    c = Coalescer(window_sec=60)
    assert c.should_emit("R-BYPASS|claude|/tmp") is True
    assert c.should_emit("R-BYPASS|claude|/tmp") is False
```

- [ ] **Step 2–4:** Implement:
  - Load watchlist; watch parent dirs with `inotify` (use stdlib if feasible; otherwise add `inotify_simple` to dependencies with pin).
  - On write events under watch/self paths → `evaluate_write` → allowlist check → append + notify hook.
  - Sampler: scan `/proc` for known basenames + bypass flags every N seconds (backup).
  - Handle inotify overflow by emitting one warning alert + calling scout refresh.
  - Respect `MemoryMax` via systemd later; keep code lean.

Commit: `feat: sentinel daemon inotify and process sampler`

---

### Task 7: Notify via Omarchy

**Files:**
- Create: `src/sentinel/notify.py`, `tests/test_notify.py`

**Interfaces:**
- Produces: `send_alert(alert: Alert) -> None` calling:

```bash
omarchy notification send -u critical|normal|low --app-name Sentinel \
  "<SEVERITY>: <summary>" "<basename> — <why> (<cwd_basename>)" \
  --exec sentinel-action <id> menu
```

- [ ] **Step 1: Test builds argv without executing** (inject runner)

```python
def test_notify_builds_critical_for_high(monkeypatch):
    calls = []
    monkeypatch.setattr("sentinel.notify.run", lambda argv: calls.append(argv))
    # ... create high alert, send_alert(alert)
    assert calls[0][0:3] == ["omarchy", "notification", "send"]
    assert "-u" in calls[0] and "critical" in calls[0]
```

- [ ] **Step 2–4:** Implement + wire daemon enqueue path. Commit `feat: omarchy notification send for alerts`

---

### Task 8: `sentinel-action` — Approve / Kill / Investigate / Dismiss / Pause

**Files:**
- Create: `src/sentinel/action.py`, `src/sentinel/kill.py`, `tests/test_kill.py`, `tests/test_action.py`
- Modify: `cli.py`

**Interfaces:**
- `action_main`: subcommands `approve|kill|investigate|dismiss|menu|list|status|pause`
- Kill policy (narrow): see spec §11 — default child PIDs; optional `--session`; refuse non-owned; precious worktree double-confirm via interactive tty prompt (non-interactive tests pass `--yes` only for child kill)

- [ ] **Step 1: Kill policy unit tests**

```python
def test_kill_refuses_foreign_uid(monkeypatch):
    from sentinel.kill import plan_kill
    # fake proc entries owned by other uid → plan_kill raises PermissionError

def test_default_targets_child_not_supervisor():
    plan = plan_kill(alert_pids=[100, 101], child_pids=[101], mode="child")
    assert plan == [101]
```

- [ ] **Step 2–4:** Implement `plan_kill` + `execute_kill` (SIGTERM, wait 3s, SIGKILL survivors). Approve writes allowlist. Dismiss updates status. Pause writes `state_dir()/pause_until` ISO timestamp; notify path checks it.

Commit: `feat: sentinel-action approve kill investigate dismiss pause`

---

### Task 9: Omarchy menu extension

**Files:**
- Create: `packaging/omarchy-menu-sentinel.jsonc`
- Create: `scripts/install-menu.sh` that merges keys into `~/.config/omarchy/extensions/omarchy-menu.jsonc` (backup first)

**Interfaces:**
- Menu ids: `sentinel`, `sentinel.alerts`, `sentinel.status`, `sentinel.inventory`, `sentinel.pause` per spec

- [ ] **Step 1:** Write JSONC snippet exactly as spec (icons may use Nerd Font glyphs from spec).
- [ ] **Step 2:** Install script copies/merges; dry-run mode prints diff.
- [ ] **Step 3:** Manual verify: `omarchy menu summon sentinel` (or open menu) shows rows. Document in README.
- [ ] **Step 4:** Commit `feat: omarchy menu extension for Sentinel`

---

### Task 10: Track A — health hooks + sticky timer

**Files:**
- Create: `track-a/hooks/post-boot.d/sentinel-health`, `track-a/hooks/post-update.d/sentinel-recheck`
- Create: `track-a/systemd/sentinel-health.service`, `track-a/systemd/sentinel-health.timer`
- Create: `src/sentinel/health.py`, `tests/test_health.py`
- Create: `scripts/install-track-a.sh`

**Interfaces:**
- `check_health() -> HealthReport` with fields: `t2fanrd_active`, `wifi_up`, `disk_ok`, `daemon_active`, `sticky_fail_count`
- Notify only when sticky fail count ≥ 3 (config)

- [ ] **Step 1: Failing tests for sticky logic**

```python
def test_sticky_requires_three_failures():
    from sentinel.health import StickyCounter
    s = StickyCounter(threshold=3)
    assert s.record(False) is False
    assert s.record(False) is False
    assert s.record(False) is True  # notify now
```

- [ ] **Step 2–4:** Implement health checks:
  - `systemctl is-active t2fanrd`
  - default route / `ip -br link` wifi iface up
  - disk free on `/` > 10%
  - `systemctl --user is-active sentinel.service` (may be inactive until Task 11 — treat as warn only after daemon packaged)
- Install hooks via `omarchy hook install post-boot track-a/hooks/post-boot.d/sentinel-health` (and post-update).
- **Do not** install battery-low hook.
- Commit: `feat: track-a sticky health hooks and timer`

---

### Task 11: systemd user units + install

**Files:**
- Create: `track-b/systemd/sentinel.service`, `track-b/systemd/sentinel-inventory.service`, `track-b/systemd/sentinel-inventory.timer`
- Create: `scripts/install-systemd.sh`

**Unit requirements (verbatim intent from spec):**

```ini
# sentinel.service (user)
[Service]
ExecStart=%h/Work/sentinel/.venv/bin/sentinel daemon
Restart=on-failure
RestartSec=5
MemoryMax=256M
```

Inventory timer: daily off-peak (`OnCalendar=*-*-* 03:30:00`, `Persistent=true`), `MemoryMax=512M`.

- [ ] **Step 1:** Write unit files with `%h`-based paths; document override if repo moves.
- [ ] **Step 2:** `install-systemd.sh` copies to `~/.config/systemd/user/`, `daemon-reload`, `enable --now` timers; enable daemon only after Phase 2 acceptance smoke.
- [ ] **Step 3:** Commit `feat: systemd user units for sentinel and inventory`

---

### Task 12: Local Investigate view

**Files:**
- Create: `src/sentinel/investigate.py`, `tests/test_investigate.py`

**Interfaces:**
- `format_detail(alert: Alert) -> str` for pager
- `sentinel-action <id> investigate` opens `$PAGER` or `less`

- [ ] **Step 1:** Test that formatted output includes rule, cmdline, cwd, paths, hashes, and **excludes** any key named like token/auth body.
- [ ] **Step 2–4:** Implement + commit `feat: local investigate detail view`

---

### Task 13: Phase 3 — R-CHILD-SHELL + precious worktrees

**Files:**
- Modify: `rules.py`, `kill.py`, `tests/test_rules.py`, `tests/test_kill.py`
- Config: `precious_worktrees = []` in default `config.toml` template

- [ ] **Step 1:** Tests for agent-parent → `bash -c 'curl|bash'` detection via synthetic proc tree fixtures.
- [ ] **Step 2:** Default kill targets child; `--session` requires second confirm when cwd matches precious prefix.
- [ ] **Step 3:** Commit `feat: R-CHILD-SHELL and precious worktree kill confirm`

---

### Task 14: Phase 4 — Cloud Summarize (opt-in)

**Files:**
- Create: `src/sentinel/summarize.py`, `tests/test_summarize_redaction.py`

**Interfaces:**
- `build_redacted_bundle(alert) -> dict` — only rule, severity, basename, flags, cwd, parent basename, path names, hashes, writer_pid
- `summarize(alert)` subprocess/oneshot; API key from `SENTINEL_API_KEY` or `config_dir()/api_key` mode `0600`
- Daemon must not import the cloud SDK

- [ ] **Step 1:** Redaction tests — assert forbidden keys absent.
- [ ] **Step 2:** Stub HTTP client injectable; failure returns None and CLI prints local detail only.
- [ ] **Step 3:** Wire Investigate menu “Summarize” → `sentinel-action <id> summarize`.
- [ ] **Step 4:** Commit `feat: opt-in redacted cloud summarize`

---

### Task 15: End-to-end acceptance script + README

**Files:**
- Create: `scripts/acceptance-smoke.sh`, update `README.md`

- [ ] **Step 1:** Script runs: scout → synthetic wrap launch with fake bypass flag → assert alert line appears → approve this-repo → second launch no new notify → kill test child process → R-SELF by touching config with `touch` from a subshell recorded as writer.
- [ ] **Step 2:** Document fingerprint optional steps (`omarchy setup security fingerprint`) and FIDO2 deferred.
- [ ] **Step 3:** Commit `docs: acceptance smoke and README`

---

## Parallelism note

After Task 0–1, **Task 10 (Track A)** can proceed in parallel with Tasks 2–9 (Track B) on a second agent/worktree. Tasks 11–12 need daemon + notify. Tasks 13–14 are sequential after MVP.

---

## Spec coverage self-check

| Spec section | Tasks |
|--------------|-------|
| Mission / response mode | 7, 8, 12, 14 |
| Track A hooks / sticky health / no battery | 10 |
| Fingerprint non-blocking | 15 (docs) + manual |
| Scout / watchlist | 3 |
| Rules MVP + R-CHILD-SHELL | 4, 13 |
| R-SELF | 4, 15 |
| Alert schema / redaction | 1, 14 |
| Allowlist scopes | 2, 8 |
| Kill policy narrow | 8, 13 |
| Wrappers + sampler | 5, 6 |
| Omarchy notify + menu | 7, 9 |
| systemd timers/units | 10, 11 |
| Investigate / Summarize | 12, 14 |
| Resource budgets | 11 (MemoryMax), 6 lean loop |
| Acceptance checklist | 15 |

## Placeholder scan

No TBD/TODO left in task steps. Provider choice for Summarize is intentionally config-time (spec: not a v1 blocker for Phases 0–3).

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-03-omarchy-sentinel.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration (`subagent-driven-development`).
2. **Inline Execution** — execute tasks in this session with checkpoints (`executing-plans`).

Which approach?
