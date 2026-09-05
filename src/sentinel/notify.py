# SPDX-License-Identifier: Apache-2.0
"""Desktop notifications with a policy the Owner can live with.

Omarchy facts this module is built on (Service.qml, 4.0.2): critical urgency
ignores any expire timeout and stays until clicked; low and normal honour
``-t`` only as a floor raised above their 5 s / 8 s defaults, capped at 30 s;
``-r <id>`` rewrites a toast in place and restarts its countdown when the text
changes; ``-p`` prints the id of the toast that was created.

Policy: high toasts expire after 30 s, medium after 15 s, low never toasts
unless enabled; self-tamper alerts stay sticky and ignore pause, prefs and
burst; after ``threshold`` toasts inside ``window_sec`` one summary toast takes
over and updates in place; a quiet ``quiet_sec`` resets the burst.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from sentinel.action import is_paused
from sentinel.fsutil import write_private_atomic
from sentinel.models import Alert
from sentinel.paths import default_config_path, state_dir

PREFS_FILENAME = "notify-prefs.json"
BURST_FILENAME = "notify-burst.json"
MAX_TIMEOUT_MS = 30_000  # the shell's cap for non-critical toasts
SUMMARY_MAX_CHARS = 80

# Tamper alerts must never be mutable by anything that runs as the user, so
# this set is code, not config.
STICKY_EVENTS = frozenset({"foreign-write", "alert-log-truncated"})


@dataclass(frozen=True)
class SeverityPolicy:
    urgency: str  # low | normal | critical
    timeout_ms: int  # 0 = omit -t
    enabled: bool


@dataclass(frozen=True)
class BurstPolicy:
    threshold: int = 5
    window_sec: float = 300.0
    quiet_sec: float = 600.0


@dataclass(frozen=True)
class NotifyPolicy:
    high: SeverityPolicy = SeverityPolicy("normal", 30_000, True)
    medium: SeverityPolicy = SeverityPolicy("normal", 15_000, True)
    low: SeverityPolicy = SeverityPolicy("low", 5_000, False)
    burst: BurstPolicy = BurstPolicy()
    plugin_id: str = "tav.sentinel"

    def for_severity(self, severity: str) -> SeverityPolicy:
        sev = str(severity or "").lower()
        if sev == "high":
            return self.high
        if sev == "low":
            return self.low
        return self.medium


STICKY = SeverityPolicy("critical", 0, True)
SEVERITIES = ("high", "medium", "low")


def is_sticky(alert: Alert) -> bool:
    event = str((alert.evidence or {}).get("event", ""))
    return alert.rule == "R-SELF" and event in STICKY_EVENTS


# ---------------------------------------------------------------- policy files


def _clamp_timeout(seconds: Any, fallback_ms: int) -> int:
    try:
        sec = float(seconds)
    except (TypeError, ValueError):
        return fallback_ms
    sec = max(1.0, min(sec, MAX_TIMEOUT_MS / 1000))
    return int(round(sec * 1000))


def load_policy(config_path: Path | None = None) -> NotifyPolicy:
    """Built-in defaults, then the [notify] section of config.toml."""
    policy = NotifyPolicy()
    path = config_path if config_path is not None else default_config_path()
    try:
        with Path(path).open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return policy
    section = data.get("notify")
    if not isinstance(section, dict):
        return policy

    def sev(current: SeverityPolicy, name: str) -> SeverityPolicy:
        enabled = section.get(f"toast_{name}", current.enabled)
        timeout = _clamp_timeout(section.get(f"{name}_timeout", current.timeout_ms / 1000), current.timeout_ms)
        return SeverityPolicy(current.urgency, timeout, bool(enabled))

    burst = policy.burst
    try:
        burst = BurstPolicy(
            threshold=max(1, int(section.get("burst_threshold", burst.threshold))),
            window_sec=max(1.0, float(section.get("burst_window", burst.window_sec))),
            quiet_sec=max(1.0, float(section.get("burst_quiet", burst.quiet_sec))),
        )
    except (TypeError, ValueError):
        pass
    plugin_id = str(section.get("plugin_id", policy.plugin_id) or policy.plugin_id)
    return NotifyPolicy(
        high=sev(policy.high, "high"),
        medium=sev(policy.medium, "medium"),
        low=sev(policy.low, "low"),
        burst=burst,
        plugin_id=plugin_id,
    )


def prefs_path() -> Path:
    return state_dir() / PREFS_FILENAME


def load_prefs(path: Path | None = None) -> dict[str, bool] | None:
    """Per-severity on/off written by `sentinel-action notify`; None if absent or bad."""
    p = path if path is not None else prefs_path()
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    sev = data.get("severities") if isinstance(data, dict) else None
    if not isinstance(sev, dict):
        return None
    out: dict[str, bool] = {}
    for name in SEVERITIES:
        if isinstance(sev.get(name), bool):
            out[name] = sev[name]
    return out


def write_prefs(severities: Mapping[str, bool], path: Path | None = None) -> dict[str, bool]:
    """Merge the given flags into the prefs file (0600) and return the result."""
    p = path if path is not None else prefs_path()
    current = load_prefs(p) or {}
    for name, value in severities.items():
        if name in SEVERITIES:
            current[name] = bool(value)
    from datetime import datetime, timezone

    payload = {
        "version": 1,
        "severities": {k: current[k] for k in SEVERITIES if k in current},
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    write_private_atomic(p, json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return current


def effective_policy(policy: NotifyPolicy, prefs: Mapping[str, bool] | None) -> NotifyPolicy:
    """Prefs may only flip `enabled`; urgency and timeouts stay the policy's."""
    if not prefs:
        return policy
    return replace(
        policy,
        high=replace(policy.high, enabled=prefs.get("high", policy.high.enabled)),
        medium=replace(policy.medium, enabled=prefs.get("medium", policy.medium.enabled)),
        low=replace(policy.low, enabled=prefs.get("low", policy.low.enabled)),
    )


# ------------------------------------------------------------------- runner


def run(argv: list[str]) -> str | None:
    """Fire a notification; never block the daemon for more than 5 s (S7)."""
    try:
        proc = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _why(alert: Alert) -> str:
    evidence = alert.evidence or {}
    flag = evidence.get("flag")
    if flag:
        return str(flag)
    flags = evidence.get("flags")
    if isinstance(flags, list) and flags:
        return str(flags[0])
    path = evidence.get("path")
    if path:
        return Path(str(path)).name
    event = evidence.get("event")
    if event:
        return str(event)
    return alert.rule


def _title_body(alert: Alert) -> tuple[str, str]:
    title = f"{alert.severity.upper()}: {alert.summary}"
    cwd_base = Path(alert.cwd).name if alert.cwd else ""
    body = f"{alert.basename} — {_why(alert)} ({cwd_base})"
    return title, body


def _exec_tail(alert_id: str, exec_prefix: Sequence[str] = ("sentinel-action",)) -> list[str]:
    return ["--exec", *exec_prefix, alert_id, "menu"]


def build_argv(
    alert: Alert,
    policy: SeverityPolicy | None = None,
    *,
    exec_prefix: Sequence[str] = ("sentinel-action",),
) -> list[str]:
    sp = policy if policy is not None else (STICKY if is_sticky(alert) else NotifyPolicy().for_severity(alert.severity))
    title, body = _title_body(alert)
    argv = ["omarchy", "notification", "send", "-u", sp.urgency]
    if sp.urgency != "critical" and sp.timeout_ms > 0:
        argv += ["-t", str(int(sp.timeout_ms))]
    argv += ["--app-name", "Sentinel", title, body, *_exec_tail(alert.id, exec_prefix)]
    return argv


def _counts_text(by_severity: Mapping[str, int]) -> str:
    parts = [f"{by_severity[s]} {s}" for s in SEVERITIES if by_severity.get(s, 0) > 0]
    return " · ".join(parts)


def build_summary_argv(
    total: int,
    by_severity: Mapping[str, int],
    newest: Alert,
    *,
    summary_id: int | None,
    plugin_id: str,
    timeout_ms: int = MAX_TIMEOUT_MS,
) -> list[str]:
    newest_text = newest.summary
    if len(newest_text) > SUMMARY_MAX_CHARS:
        newest_text = newest_text[: SUMMARY_MAX_CHARS - 1] + "…"
    argv = ["omarchy", "notification", "send", "-u", "normal", "-t", str(int(timeout_ms)), "-p"]
    if summary_id is not None:
        argv += ["-r", str(int(summary_id))]
    argv += [
        "--app-name",
        "Sentinel",
        f"Sentinel: {total} alert{'' if total == 1 else 's'}",
        f"{_counts_text(by_severity)} — newest: {newest_text}. Click to open the panel.",
        "--exec",
        "omarchy-shell",
        "shell",
        "summon",
        plugin_id,
        "{}",
    ]
    return argv


def _parse_id(out: str | None) -> int | None:
    if not out:
        return None
    tokens = out.split()
    if not tokens:
        return None
    try:
        return int(tokens[-1])
    except ValueError:
        return None


# ---------------------------------------------------------------- burst


class BurstTracker:
    """Counts toasts in a sliding window; from the (threshold+1)th on, summary mode."""

    def __init__(self, policy: BurstPolicy, *, clock: Callable[[], float] = time.time) -> None:
        self.policy = policy
        self._clock = clock
        self.reset()

    def reset(self) -> None:
        self.active = False
        self.events: list[float] = []
        self.by_severity: dict[str, int] = {}
        self.summary_id: int | None = None
        self.last_event: float | None = None
        self.newest_id: str | None = None

    def record(self, severity: str, alert_id: str | None = None) -> str:
        now = self._clock()
        if self.last_event is not None and now - self.last_event >= self.policy.quiet_sec:
            self.reset()
        self.events = [t for t in self.events if now - t < self.policy.window_sec] + [now]
        sev = str(severity or "").lower()
        self.by_severity[sev] = self.by_severity.get(sev, 0) + 1
        self.last_event = now
        self.newest_id = alert_id
        if not self.active and len(self.events) > self.policy.threshold:
            self.active = True
        return "summary" if self.active else "toast"

    def totals(self) -> tuple[int, dict[str, int]]:
        return sum(self.by_severity.values()), dict(self.by_severity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "active": self.active,
            "events": list(self.events),
            "by_severity": dict(self.by_severity),
            "summary_id": self.summary_id,
            "last_event": self.last_event,
            "newest_id": self.newest_id,
        }

    def save(self, path: Path) -> None:
        write_private_atomic(path, json.dumps(self.to_dict(), separators=(",", ":")) + "\n")

    @classmethod
    def load(cls, path: Path, policy: BurstPolicy, *, clock: Callable[[], float] = time.time) -> "BurstTracker":
        tracker = cls(policy, clock=clock)
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return tracker
        if not isinstance(data, dict):
            return tracker
        try:
            last = data.get("last_event")
            if last is None or clock() - float(last) >= policy.quiet_sec:
                return tracker  # too old to matter; start clean
            tracker.active = bool(data.get("active", False))
            tracker.events = [float(t) for t in data.get("events", [])]
            tracker.by_severity = {str(k): int(v) for k, v in (data.get("by_severity") or {}).items()}
            sid = data.get("summary_id")
            tracker.summary_id = int(sid) if sid is not None else None
            tracker.last_event = float(last)
            nid = data.get("newest_id")
            tracker.newest_id = str(nid) if nid else None
        except (TypeError, ValueError):
            return cls(policy, clock=clock)
        return tracker


# ---------------------------------------------------------------- notifier


class Notifier:
    def __init__(
        self,
        policy: NotifyPolicy | None = None,
        *,
        runner: Callable[[list[str]], str | None] | None = None,
        clock: Callable[[], float] = time.time,
        state_path: Path | None = None,
        prefs_file: Path | None = None,
        exec_prefix: Sequence[str] = ("sentinel-action",),
        prefs_ok: Callable[[Path], bool] = lambda p: True,
        on_state_write: Callable[[Path], None] = lambda p: None,
        paused: Callable[[], bool] | None = None,
    ) -> None:
        self.policy = policy if policy is not None else NotifyPolicy()
        # Resolved at call time so tests (and W3-05) can swap the module hooks.
        self._runner = runner
        self._clock = clock
        self._state_path = state_path
        self._prefs_file = prefs_file
        self._exec_prefix = tuple(exec_prefix)
        self._prefs_ok = prefs_ok
        self._on_state_write = on_state_write
        self._paused = paused
        self._prefs_cache: tuple[int, dict[str, bool] | None] | None = None
        self._tracker: BurstTracker | None = None

    # State paths resolve lazily so XDG overrides in tests are honoured.
    def _state(self) -> Path:
        return self._state_path if self._state_path is not None else state_dir() / BURST_FILENAME

    def _prefs(self) -> Path:
        return self._prefs_file if self._prefs_file is not None else prefs_path()

    def _run(self, argv: list[str]) -> str | None:
        return run(argv) if self._runner is None else self._runner(argv)

    def _is_paused(self) -> bool:
        return is_paused() if self._paused is None else self._paused()

    def _tracker_(self) -> BurstTracker:
        if self._tracker is None:
            self._tracker = BurstTracker.load(self._state(), self.policy.burst, clock=self._clock)
        return self._tracker

    def effective(self) -> NotifyPolicy:
        path = self._prefs()
        try:
            mtime = os.stat(path).st_mtime_ns
        except OSError:
            self._prefs_cache = None
            return self.policy
        if self._prefs_cache is None or self._prefs_cache[0] != mtime:
            prefs = load_prefs(path) if self._prefs_ok(path) else None
            self._prefs_cache = (mtime, prefs)
        return effective_policy(self.policy, self._prefs_cache[1])

    def send(self, alert: Alert) -> None:
        if is_sticky(alert):
            self._run(build_argv(alert, STICKY, exec_prefix=self._exec_prefix))
            return
        if self._is_paused():
            return
        policy = self.effective()
        sp = policy.for_severity(alert.severity)
        if not sp.enabled:
            return
        tracker = self._tracker_()
        mode = tracker.record(alert.severity, alert.id)
        if mode == "toast":
            self._run(build_argv(alert, sp, exec_prefix=self._exec_prefix))
        else:
            total, by_sev = tracker.totals()
            out = self._run(
                build_summary_argv(
                    total,
                    by_sev,
                    alert,
                    summary_id=tracker.summary_id,
                    plugin_id=policy.plugin_id,
                    timeout_ms=self.policy.high.timeout_ms or MAX_TIMEOUT_MS,
                )
            )
            new_id = _parse_id(out)
            if new_id is not None:
                tracker.summary_id = new_id
        state = self._state()
        try:
            tracker.save(state)
        except OSError:
            return
        self._on_state_write(state)


_default: Notifier | None = None


def _default_notifier() -> Notifier:
    global _default
    if _default is None:
        _default = Notifier(load_policy())
    return _default


def send_alert(alert: Alert) -> None:
    """Module-level entry point used by the daemon when nothing is injected."""
    _default_notifier().send(alert)
