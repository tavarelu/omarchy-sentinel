# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import statewatch
from sentinel.action import cmd_approve, cmd_dismiss, cmd_notify
from sentinel.daemon import Daemon
from sentinel.models import Alert
from sentinel.paths import state_dir
from sentinel.store import append_alert, iter_alerts


def _setup_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    state_dir().mkdir(parents=True, exist_ok=True)


def _collect_fs_events(daemon: Daemon, path: Path):
    """Simulate what inotify sends to the daemon when path or state_dir is modified."""
    daemon._on_fs_event(path, 0x00000008)  # IN_CLOSE_WRITE


def test_approve_action_produces_no_self_alerts(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)
    d = Daemon({"inotify": False, "notify": lambda a: None})
    d._seed_ledger()

    # Create an initial alert
    initial_alert = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude launched with --dangerously-skip-permissions",
        pids=[1234],
        exe="/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd=str(tmp_path),
        evidence={"flags": ["--dangerously-skip-permissions"]},
    )
    append_alert(initial_alert)
    d._ledger.record(state_dir() / "alerts.jsonl")

    # Approve the alert
    res = cmd_approve(initial_alert.id, "this-repo")
    assert res == 0

    # The action wrote allowlist.json (and .tmp), allowlist-session.json, and alerts.jsonl
    # Simulate the inotify events reaching the daemon
    for name in (
        "allowlist.json.tmp",
        "allowlist.json",
        "allowlist-session.json.tmp",
        "allowlist-session.json",
        "alerts.lock",
        "alerts.jsonl.tmp",
        "alerts.jsonl",
    ):
        p = state_dir() / name
        if p.exists() or name.endswith(".tmp"):
            _collect_fs_events(d, p)

    # Verify: initial alert is approved, and NO R-SELF alerts were created
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].id == initial_alert.id
    assert rows[0].status == "approved"
    assert rows[0].rule == "R-BYPASS"


def test_dismiss_action_produces_no_self_alerts(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)
    d = Daemon({"inotify": False, "notify": lambda a: None})
    d._seed_ledger()

    # Create an initial alert
    initial_alert = Alert.new(
        rule="R-BYPASS",
        severity="medium",
        summary="codex bypass",
        pids=[2345],
        exe="/bin/codex",
        basename="codex",
        cmdline=["codex", "--yolo"],
        cwd=str(tmp_path),
        evidence={"flags": ["--yolo"]},
    )
    append_alert(initial_alert)
    d._ledger.record(state_dir() / "alerts.jsonl")

    # Dismiss the alert
    res = cmd_dismiss(initial_alert.id)
    assert res == 0

    # Simulate inotify events
    for name in ("alerts.lock", "alerts.jsonl.tmp", "alerts.jsonl"):
        p = state_dir() / name
        if p.exists() or name.endswith(".tmp"):
            _collect_fs_events(d, p)

    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].id == initial_alert.id
    assert rows[0].status == "dismissed"
    assert rows[0].rule == "R-BYPASS"


def test_notify_prefs_action_produces_no_self_alerts(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)
    d = Daemon({"inotify": False, "notify": lambda a: None})
    d._seed_ledger()

    # Change notify preferences
    res = cmd_notify(["low=on"])
    assert res == 0

    # Simulate inotify events
    for name in ("notify-prefs.json.tmp", "notify-prefs.json"):
        p = state_dir() / name
        if p.exists() or name.endswith(".tmp"):
            _collect_fs_events(d, p)

    rows = list(iter_alerts())
    assert len(rows) == 0  # No alerts created at all
