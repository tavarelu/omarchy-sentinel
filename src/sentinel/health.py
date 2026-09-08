# SPDX-License-Identifier: Apache-2.0
"""Track A health checks with sticky failure notifications."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.fsutil import ensure_private_dir, write_private_atomic
from sentinel.paths import state_dir
from sentinel.statewatch import announce_write

HEALTH_FILENAME = "health.json"
DEFAULT_STICKY_THRESHOLD = 3
DEFAULT_MIN_DISK_FREE_PCT = 10.0


@dataclass
class HealthReport:
    t2fanrd_active: bool
    wifi_up: bool
    disk_ok: bool
    daemon_active: bool
    sticky_fail_count: int

    @property
    def critical_ok(self) -> bool:
        return self.t2fanrd_active and self.wifi_up and self.disk_ok

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["critical_ok"] = self.critical_ok
        return data


class StickyCounter:
    """Count consecutive failures; notify once count reaches threshold."""

    def __init__(self, threshold: int = DEFAULT_STICKY_THRESHOLD, count: int = 0) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.threshold = threshold
        self.count = count

    def record(self, ok: bool) -> bool:
        """Record a check result.

        ``ok=False`` increments the failure streak. Returns True when the
        caller should notify (failures >= threshold). Success resets the streak.
        """
        if ok:
            self.count = 0
            return False
        self.count += 1
        return self.count >= self.threshold


def health_path() -> Path:
    return state_dir() / HEALTH_FILENAME


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def _systemctl_is_active(unit: str, *, user: bool = False) -> bool:
    cmd = ["systemctl"]
    if user:
        cmd.append("--user")
    cmd.extend(["is-active", "--quiet", unit])
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, timeout=5.0)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _t2fanrd_active() -> bool:
    return _systemctl_is_active("t2fanrd", user=False)


def _daemon_active() -> bool:
    return _systemctl_is_active("sentinel.service", user=True)


def _wifi_up() -> bool:
    """True when a wifi iface (wl*) is UP, or a default route exists via wl*."""
    link_out = _run(["ip", "-br", "link"])
    for line in link_out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, state = parts[0], parts[1]
        if name.startswith("wl") and state == "UP":
            return True
    route_out = _run(["ip", "route", "show", "default"])
    for line in route_out.splitlines():
        if " dev wl" in f" {line} " or " dev wl" in line:
            return True
        tokens = line.split()
        if "dev" in tokens:
            dev = tokens[tokens.index("dev") + 1] if tokens.index("dev") + 1 < len(tokens) else ""
            if dev.startswith("wl"):
                return True
    return False


def _disk_ok(path: str = "/", min_free_pct: float = DEFAULT_MIN_DISK_FREE_PCT) -> bool:
    try:
        st = os.statvfs(path)
    except OSError:
        return False
    if st.f_blocks <= 0:
        return False
    free_pct = (st.f_bfree / st.f_blocks) * 100.0
    return free_pct > min_free_pct


def _load_health_state() -> dict[str, Any]:
    path = health_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_sticky_count() -> int:
    raw = _load_health_state().get("sticky_fail_count", 0)
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def write_health_report(report: HealthReport, *, source: str | None = None) -> Path:
    path = health_path()
    ensure_private_dir(path.parent)
    payload = report.to_dict()
    payload["ts"] = datetime.now(timezone.utc).isoformat()
    if source:
        payload["source"] = source
    if not report.daemon_active:
        payload["warnings"] = ["sentinel.service inactive (warn only)"]
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    try:
        announce_write(path, digest)
    except Exception:
        pass
    write_private_atomic(path, content)
    try:
        announce_write(path, digest)
    except Exception:
        pass
    return path


def send_notification(
    headline: str,
    body: str = "",
    *,
    urgency: str = "normal",
) -> None:
    """Best-effort desktop notify via omarchy, with notify-send fallback."""
    omarchy = shutil.which("omarchy")
    if omarchy:
        cmd = [omarchy, "notification", "send", "-u", urgency, headline]
        if body:
            cmd.append(body)
        try:
            subprocess.run(cmd, check=False, capture_output=True, timeout=10.0)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    notify_send = shutil.which("notify-send")
    if notify_send:
        try:
            subprocess.run(
                [notify_send, "-u", urgency, headline, body],
                check=False,
                capture_output=True,
                timeout=10.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


def check_health(
    *,
    notify: bool = True,
    warn_daemon: bool = False,
    threshold: int = DEFAULT_STICKY_THRESHOLD,
    source: str | None = None,
) -> HealthReport:
    """Probe fan/wifi/disk/daemon, update sticky count, optionally notify."""
    t2 = _t2fanrd_active()
    wifi = _wifi_up()
    disk = _disk_ok()
    daemon = _daemon_active()

    prev = _load_health_state()
    sticky = StickyCounter(threshold=threshold, count=_load_sticky_count())
    critical_ok = t2 and wifi and disk
    should_notify = sticky.record(critical_ok)

    report = HealthReport(
        t2fanrd_active=t2,
        wifi_up=wifi,
        disk_ok=disk,
        daemon_active=daemon,
        sticky_fail_count=sticky.count,
    )
    write_health_report(report, source=source)

    if notify and should_notify:
        parts = []
        if not t2:
            parts.append("t2fanrd inactive")
        if not wifi:
            parts.append("wifi down")
        if not disk:
            parts.append(f"disk free ≤{DEFAULT_MIN_DISK_FREE_PCT:g}%")
        body = "; ".join(parts) or "health check failed"
        body += f" (sticky {sticky.count}/{threshold})"
        if not daemon:
            body += "; sentinel.service inactive"
        send_notification("Sentinel health", body, urgency="critical")

    # Daemon missing is warn-only and edge-triggered (no sticky / no spam).
    prev_daemon = prev.get("daemon_active")
    daemon_became_inactive = not daemon and prev_daemon is not False
    if notify and warn_daemon and daemon_became_inactive and critical_ok:
        send_notification(
            "Sentinel inactive",
            "sentinel.service is not active (warn only)",
            urgency="low",
        )

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-health")
    parser.add_argument(
        "--source",
        default="manual",
        help="Caller tag written into health.json (post-boot, timer, …)",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Skip desktop notifications",
    )
    parser.add_argument(
        "--warn-daemon",
        action="store_true",
        help="Emit a low-urgency warn when sentinel.service is inactive",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_STICKY_THRESHOLD,
        help="Consecutive critical failures before notify (default: 3)",
    )
    args = parser.parse_args(argv)
    report = check_health(
        notify=not args.no_notify,
        warn_daemon=args.warn_daemon,
        threshold=args.threshold,
        source=args.source,
    )
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.critical_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
