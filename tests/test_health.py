from __future__ import annotations

import json

from sentinel.health import (
    HealthReport,
    StickyCounter,
    check_health,
    write_health_report,
)


def test_sticky_requires_three_failures():
    from sentinel.health import StickyCounter

    s = StickyCounter(threshold=3)
    assert s.record(False) is False
    assert s.record(False) is False
    assert s.record(False) is True  # notify now


def test_sticky_resets_on_success():
    s = StickyCounter(threshold=3)
    assert s.record(False) is False
    assert s.record(False) is False
    assert s.record(True) is False
    assert s.count == 0
    assert s.record(False) is False
    assert s.count == 1


def test_sticky_stays_true_while_failing_past_threshold():
    s = StickyCounter(threshold=3)
    s.record(False)
    s.record(False)
    assert s.record(False) is True
    assert s.record(False) is True
    assert s.count == 4


def test_check_health_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    monkeypatch.setattr("sentinel.health._t2fanrd_active", lambda: True)
    monkeypatch.setattr("sentinel.health._wifi_up", lambda: True)
    monkeypatch.setattr("sentinel.health._disk_ok", lambda: True)
    monkeypatch.setattr("sentinel.health._daemon_active", lambda: False)

    report = check_health(notify=False)
    assert isinstance(report, HealthReport)
    assert report.t2fanrd_active is True
    assert report.wifi_up is True
    assert report.disk_ok is True
    assert report.daemon_active is False
    assert report.sticky_fail_count == 0


def test_check_health_sticky_and_notify(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    notifies: list[tuple[str, str]] = []

    def fake_notify(headline: str, body: str = "", *, urgency: str = "normal") -> None:
        notifies.append((headline, body, urgency))

    monkeypatch.setattr("sentinel.health._t2fanrd_active", lambda: False)
    monkeypatch.setattr("sentinel.health._wifi_up", lambda: True)
    monkeypatch.setattr("sentinel.health._disk_ok", lambda: True)
    monkeypatch.setattr("sentinel.health._daemon_active", lambda: True)
    monkeypatch.setattr("sentinel.health.send_notification", fake_notify)

    r1 = check_health(notify=True)
    r2 = check_health(notify=True)
    r3 = check_health(notify=True)
    assert r1.sticky_fail_count == 1
    assert r2.sticky_fail_count == 2
    assert r3.sticky_fail_count == 3
    assert len(notifies) == 1
    assert "health" in notifies[0][0].lower() or "sentinel" in notifies[0][0].lower()


def test_daemon_inactive_is_warn_only(monkeypatch, tmp_path):
    """Missing sentinel.service must not advance the sticky counter."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    notifies: list = []

    monkeypatch.setattr("sentinel.health._t2fanrd_active", lambda: True)
    monkeypatch.setattr("sentinel.health._wifi_up", lambda: True)
    monkeypatch.setattr("sentinel.health._disk_ok", lambda: True)
    monkeypatch.setattr("sentinel.health._daemon_active", lambda: False)
    monkeypatch.setattr(
        "sentinel.health.send_notification",
        lambda *a, **k: notifies.append((a, k)),
    )

    for _ in range(5):
        report = check_health(notify=True, warn_daemon=True)
        assert report.sticky_fail_count == 0
        assert report.daemon_active is False
    # warn-only: at most one low-urgency daemon notice, never sticky critical
    critical = [n for n in notifies if n[1].get("urgency") == "critical"]
    assert critical == []


def test_write_health_report(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    report = HealthReport(
        t2fanrd_active=True,
        wifi_up=True,
        disk_ok=True,
        daemon_active=False,
        sticky_fail_count=0,
    )
    path = write_health_report(report)
    assert path == tmp_path / "state" / "sentinel" / "health.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["t2fanrd_active"] is True
    assert data["daemon_active"] is False
    assert data["sticky_fail_count"] == 0


def test_disk_ok_threshold(monkeypatch):
    from sentinel import health as health_mod

    class FakeUsage:
        f_blocks = 100
        f_bfree = 5  # 5% free
        f_frsize = 1

    monkeypatch.setattr(health_mod.os, "statvfs", lambda _path: FakeUsage())
    assert health_mod._disk_ok(min_free_pct=10.0) is False

    class OkUsage:
        f_blocks = 100
        f_bfree = 20
        f_frsize = 1

    monkeypatch.setattr(health_mod.os, "statvfs", lambda _path: OkUsage())
    assert health_mod._disk_ok(min_free_pct=10.0) is True


def test_wifi_up_from_ip_output(monkeypatch):
    from sentinel import health as health_mod

    monkeypatch.setattr(
        health_mod,
        "_run",
        lambda cmd: (
            "lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\n"
            "wlp1s0f0         UP             aa:bb:cc:dd:ee:ff <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
        ),
    )
    assert health_mod._wifi_up() is True

    monkeypatch.setattr(
        health_mod,
        "_run",
        lambda cmd: "lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\n",
    )
    assert health_mod._wifi_up() is False
