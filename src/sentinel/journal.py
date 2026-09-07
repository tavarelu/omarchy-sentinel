# SPDX-License-Identifier: Apache-2.0
"""Append-only tamper evidence: mirror every stored alert into the user journal.

journald is append-only for an unprivileged user (a same-uid attacker can add
entries but not delete or edit existing ones), so a copy here survives even a
full rewrite of alerts.jsonl. Metadata only: mirror_alert sends exactly the
five listed SENTINEL_* fields by explicit key lookup, never alert bodies,
cmdlines, or evidence beyond that (W3-07 Forbidden list, security review).
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from sentinel.keys import alert_location
from sentinel.models import Alert

# AF_UNIX/SOCK_DGRAM native journal endpoint; every field is a KEY=VALUE line
# (systemd's native protocol -- see sd_journal_sendv(3)). No dependency.
JOURNAL_SOCKET_PATH = Path("/run/systemd/journal/socket")
_SEND_TIMEOUT = 1.0
_LOGGER_TIMEOUT = 5.0


def _send_native(payload: bytes) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SEND_TIMEOUT)
            sock.sendto(payload, str(JOURNAL_SOCKET_PATH))
        return True
    except OSError:
        return False


def _send_logger(message: str) -> None:
    argv = ["logger", "-t", "sentinel", message]
    try:
        subprocess.run(argv, check=False, capture_output=True, timeout=_LOGGER_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return


def mirror_event(fields: dict[str, str]) -> None:
    """Send one structured record: KEY=VALUE lines to the native journal socket,
    falling back to `logger -t sentinel <MESSAGE>` when the socket write fails
    or the socket is absent. Never raises."""
    payload = "\n".join(f"{k}={v}" for k, v in fields.items()).encode(
        "utf-8", "surrogateescape"
    )
    try:
        if _send_native(payload):
            return
    except Exception:
        pass
    message = fields.get("MESSAGE", fields.get("SENTINEL_SUMMARY", "sentinel event"))
    try:
        _send_logger(message)
    except Exception:
        return


def mirror_alert(alert: Alert) -> None:
    """Called from Daemon.emit after append_alert -- only for alerts actually
    stored. Fields: SENTINEL_RULE, SENTINEL_ID, SENTINEL_SEVERITY,
    SENTINEL_SUMMARY, SENTINEL_LOCATION, plus SYSLOG_IDENTIFIER and MESSAGE so
    `journalctl -t sentinel` finds and displays the record. Never raises."""
    fields = {
        "SYSLOG_IDENTIFIER": "sentinel",
        "SENTINEL_RULE": str(alert.rule),
        "SENTINEL_ID": str(alert.id),
        "SENTINEL_SEVERITY": str(alert.severity),
        "SENTINEL_SUMMARY": str(alert.summary),
        "SENTINEL_LOCATION": str(alert_location(alert)),
        "MESSAGE": f"[{alert.severity}] {alert.rule} {alert.id}: {alert.summary}",
    }
    try:
        mirror_event(fields)
    except Exception:
        return
