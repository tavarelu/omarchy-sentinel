from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel import notify
from sentinel.action import write_pause
from sentinel.models import Alert
from sentinel.notify import (
    MAX_TIMEOUT_MS,
    Notifier,
    NotifyPolicy,
    SeverityPolicy,
    build_argv,
    effective_policy,
    load_policy,
    load_prefs,
    write_prefs,
)


def _alert(severity="high", rule="R-BYPASS", summary="claude started with --yolo", evidence=None, cwd="/home/tav/Work/scratch"):
    return Alert.new(
        rule=rule,
        severity=severity,
        summary=summary,
        pids=[1234],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd=cwd,
        evidence=evidence if evidence is not None else {"flag": "--yolo", "flags": ["--yolo"]},
    )


def _notifier(tmp_path, **kw):
    calls: list[list[str]] = []
    kw.setdefault("runner", lambda argv: calls.append(argv) or "42\n")
    kw.setdefault("state_path", tmp_path / "burst.json")
    kw.setdefault("prefs_file", tmp_path / "prefs.json")
    kw.setdefault("paused", lambda: False)
    return Notifier(**kw), calls


def test_high_is_normal_with_30s_timeout(tmp_path):
    n, calls = _notifier(tmp_path)
    a = _alert()
    n.send(a)
    assert calls == [[
        "omarchy", "notification", "send", "-u", "normal", "-t", "30000", "--app-name", "Sentinel",
        "HIGH: claude started with --yolo", "claude — --yolo (scratch)",
        "--exec", "sentinel-action", a.id, "menu",
    ]]


def test_medium_is_normal_with_15s_timeout(tmp_path):
    n, calls = _notifier(tmp_path)
    n.send(_alert(severity="medium"))
    assert calls[0][3:7] == ["-u", "normal", "-t", "15000"]


def test_low_disabled_by_default_no_call(tmp_path):
    n, calls = _notifier(tmp_path)
    n.send(_alert(severity="low"))
    assert calls == []


def test_low_enabled_by_prefs_uses_low_urgency(tmp_path):
    n, calls = _notifier(tmp_path)
    write_prefs({"low": True}, tmp_path / "prefs.json")
    n.send(_alert(severity="low"))
    assert calls[0][3:7] == ["-u", "low", "-t", "5000"]


def test_sticky_self_tamper_is_critical_without_timeout(tmp_path):
    n, calls = _notifier(tmp_path)
    for event in ("foreign-write", "alert-log-truncated"):
        a = _alert(rule="R-SELF", summary="x", evidence={"event": event, "path": "/p"})
        n.send(a)
    for argv in calls:
        assert argv[3:5] == ["-u", "critical"]
        assert "-t" not in argv


def test_sticky_bypasses_pause_severity_flags_and_burst(tmp_path):
    n, calls = _notifier(tmp_path, paused=lambda: True)
    write_prefs({"high": False, "medium": False, "low": False}, tmp_path / "prefs.json")
    for _ in range(8):
        n.send(_alert(rule="R-SELF", summary="x", evidence={"event": "foreign-write", "path": "/p"}))
    assert len(calls) == 8
    assert all(argv[3:5] == ["-u", "critical"] for argv in calls)
    assert not (tmp_path / "burst.json").exists()


def test_exec_tail_is_last(tmp_path):
    n, calls = _notifier(tmp_path)
    a = _alert()
    n.send(a)
    assert calls[0][-4:] == ["--exec", "sentinel-action", a.id, "menu"]


def test_load_policy_reads_config_section_and_clamps_to_30s(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[notify]\nhigh_timeout = 90\nmedium_timeout = 7\ntoast_low = true\nburst_threshold = 3\nplugin_id = "acme.guard"\n')
    p = load_policy(cfg)
    assert p.high.timeout_ms == MAX_TIMEOUT_MS
    assert p.medium.timeout_ms == 7000
    assert p.low.enabled is True
    assert p.burst.threshold == 3
    assert p.plugin_id == "acme.guard"
    assert p.high.urgency == "normal"  # urgency is not configurable


def test_prefs_can_only_flip_enabled(tmp_path):
    pf = tmp_path / "prefs.json"
    pf.write_text(json.dumps({"version": 1, "severities": {"high": False, "urgency": "critical", "timeout": 1}, "extra": 5}))
    prefs = load_prefs(pf)
    assert prefs == {"high": False}
    eff = effective_policy(NotifyPolicy(), prefs)
    assert eff.high.enabled is False
    assert eff.high.urgency == "normal" and eff.high.timeout_ms == 30000


def test_prefs_corrupt_falls_back_to_config(tmp_path):
    pf = tmp_path / "prefs.json"
    pf.write_text("{not json")
    assert load_prefs(pf) is None
    n, calls = _notifier(tmp_path)
    n.send(_alert())
    assert len(calls) == 1


def test_prefs_reloaded_when_mtime_changes(tmp_path):
    n, calls = _notifier(tmp_path)
    pf = tmp_path / "prefs.json"
    write_prefs({"high": False}, pf)
    n.send(_alert())
    assert calls == []
    write_prefs({"high": True}, pf)
    os.utime(pf, ns=(os.stat(pf).st_atime_ns, os.stat(pf).st_mtime_ns + 1_000_000))
    n.send(_alert(cwd="/other"))
    assert len(calls) == 1


def test_run_swallows_timeout_and_oserror(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="omarchy", timeout=5)

    monkeypatch.setattr(subprocess, "run", boom)
    assert notify.run(["omarchy"]) is None
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
    assert notify.run(["omarchy"]) is None


def test_unknown_severity_uses_medium_policy(tmp_path):
    n, calls = _notifier(tmp_path)
    n.send(_alert(severity="weird"))
    assert calls[0][3:7] == ["-u", "normal", "-t", "15000"]


def test_notify_paused_does_not_call_runner(tmp_path):
    n, calls = _notifier(tmp_path, paused=lambda: True)
    n.send(_alert())
    assert calls == []


def test_real_pause_file_is_honoured(tmp_path, monkeypatch):
    write_pause(timedelta(hours=1))
    calls: list = []
    n = Notifier(runner=lambda argv: calls.append(argv), state_path=tmp_path / "b.json", prefs_file=tmp_path / "p.json")
    n.send(_alert())
    assert calls == []


def test_build_argv_default_policy_matches_severity():
    a = _alert(severity="medium")
    assert build_argv(a)[3:7] == ["-u", "normal", "-t", "15000"]
    sticky = _alert(rule="R-SELF", evidence={"event": "foreign-write"})
    assert build_argv(sticky)[3:5] == ["-u", "critical"]


def test_send_alert_module_entry_point(monkeypatch, tmp_path):
    calls: list = []
    monkeypatch.setattr(notify, "run", lambda argv: calls.append(argv) or "1\n")
    monkeypatch.setattr(notify, "_default", None)
    monkeypatch.setattr("sentinel.notify.is_paused", lambda: False)
    notify.send_alert(_alert())
    assert len(calls) == 1 and calls[0][0:3] == ["omarchy", "notification", "send"]
