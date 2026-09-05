from __future__ import annotations

from datetime import timedelta

import pytest

from sentinel.models import Alert
from sentinel.notify import send_alert


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def _alert(**overrides) -> Alert:
    data = dict(
        rule="R-BYPASS",
        severity="high",
        summary="bypass flags",
        pids=[1234],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd="/home/tav/Work/scratch",
        evidence={"flag": "--dangerously-skip-permissions"},
    )
    data.update(overrides)
    return Alert.new(**data)


def test_notify_builds_critical_for_high(monkeypatch):
    calls = []
    monkeypatch.setattr("sentinel.notify.run", lambda argv: calls.append(argv))
    alert = _alert(severity="high")
    send_alert(alert)
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0:3] == ["omarchy", "notification", "send"]
    assert "-u" in argv and argv[argv.index("-u") + 1] == "critical"
    assert "--app-name" in argv and argv[argv.index("--app-name") + 1] == "Sentinel"
    assert f"HIGH: {alert.summary}" in argv
    assert "claude — --dangerously-skip-permissions (scratch)" in argv
    exec_i = argv.index("--exec")
    assert argv[exec_i:] == ["--exec", "sentinel-action", alert.id, "menu"]
    assert exec_i == len(argv) - 4


def test_notify_urgency_medium_and_low(monkeypatch):
    calls = []
    monkeypatch.setattr("sentinel.notify.run", lambda argv: calls.append(argv))

    send_alert(_alert(severity="medium", summary="watched write", basename="nano",
                      evidence={"path": "/tmp/hooks/pre.sh"}, cwd="/tmp/hooks"))
    assert calls[0][calls[0].index("-u") + 1] == "normal"
    assert "MEDIUM: watched write" in calls[0]
    assert "nano — pre.sh (hooks)" in calls[0]

    send_alert(_alert(severity="low", summary="noise", basename="inotify",
                      evidence={"event": "IN_Q_OVERFLOW"}, cwd=""))
    assert calls[1][calls[1].index("-u") + 1] == "low"
    assert "LOW: noise" in calls[1]
    assert "inotify — IN_Q_OVERFLOW ()" in calls[1]


def test_notify_unknown_severity_defaults_normal(monkeypatch):
    calls = []
    monkeypatch.setattr("sentinel.notify.run", lambda argv: calls.append(argv))
    send_alert(_alert(severity="weird", summary="x", evidence={}))
    assert calls[0][calls[0].index("-u") + 1] == "normal"
    # why falls back to rule when evidence has no flag/path/event
    assert "claude — R-BYPASS (scratch)" in calls[0]


def test_notify_paused_does_not_call_runner(monkeypatch):
    from sentinel.action import write_pause

    write_pause(timedelta(hours=1))
    calls = []
    monkeypatch.setattr("sentinel.notify.run", lambda argv: calls.append(argv))
    send_alert(_alert())
    assert calls == []


def test_run_swallows_timeout_and_oserror(monkeypatch):
    import subprocess

    from sentinel import notify

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="omarchy", timeout=5)

    monkeypatch.setattr(subprocess, "run", boom)
    assert notify.run(["omarchy"]) is None
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
    assert notify.run(["omarchy"]) is None
