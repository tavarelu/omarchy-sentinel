# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.action import is_paused
from sentinel.models import Alert

_URGENCY = {
    "high": "critical",
    "medium": "normal",
    "low": "low",
}


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


def build_argv(alert: Alert) -> list[str]:
    urgency = _URGENCY.get(alert.severity.lower(), "normal")
    title = f"{alert.severity.upper()}: {alert.summary}"
    cwd_base = Path(alert.cwd).name if alert.cwd else ""
    body = f"{alert.basename} — {_why(alert)} ({cwd_base})"
    return [
        "omarchy",
        "notification",
        "send",
        "-u",
        urgency,
        "--app-name",
        "Sentinel",
        title,
        body,
        "--exec",
        "sentinel-action",
        alert.id,
        "menu",
    ]


def send_alert(alert: Alert) -> None:
    if is_paused():
        return
    run(build_argv(alert))
