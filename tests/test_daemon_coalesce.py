from __future__ import annotations

from pathlib import Path

from sentinel.allowlist import approve, fingerprint
from sentinel.models import Alert
from sentinel.store import iter_alerts
from sentinel.wrap_record import record_launch


def test_coalesce_suppresses_duplicate_within_window():
    from sentinel.daemon import Coalescer

    c = Coalescer(window_sec=60)
    assert c.should_emit("R-BYPASS|claude|/tmp") is True
    assert c.should_emit("R-BYPASS|claude|/tmp") is False


def test_coalesce_emits_after_window_and_other_keys():
    from sentinel.daemon import Coalescer

    now = [0.0]
    c = Coalescer(window_sec=60, clock=lambda: now[0])
    assert c.should_emit("a") is True
    assert c.should_emit("b") is True
    now[0] = 59.9
    assert c.should_emit("a") is False
    now[0] = 60.0
    assert c.should_emit("a") is True


def _daemon(tmp_path, monkeypatch, **cfg):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from sentinel.daemon import Daemon

    config = {
        "inotify": False,
        "sampler_interval": 2.0,
        "notify": lambda alert: None,
        **cfg,
    }
    return Daemon(config)


def test_handle_write_appends_hook_alert(tmp_path, monkeypatch):
    watch = tmp_path / "hooks"
    watch.mkdir()
    target = watch / "pre.sh"
    target.write_text("#!/bin/sh\n")
    d = _daemon(tmp_path, monkeypatch, watch_paths=[watch], self_paths=[tmp_path / "sentinel"])
    d.handle_write(target, writer_pid=42, writer_exe="/usr/bin/python3")
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-HOOK-WRITE"
    assert rows[0].writer_pid == 42


def test_handle_write_self_path_is_rself(tmp_path, monkeypatch):
    cfg = tmp_path / "config" / "sentinel"
    cfg.mkdir(parents=True)
    target = cfg / "config.toml"
    target.write_text("x=1\n")
    d = _daemon(tmp_path, monkeypatch, watch_paths=[], self_paths=[cfg])
    d.handle_write(target, writer_pid=9, writer_exe="/usr/bin/nano")
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-SELF"


def test_handle_write_skips_operational_state_files(tmp_path, monkeypatch):
    state = tmp_path / "state" / "sentinel"
    state.mkdir(parents=True)
    alerts = state / "alerts.jsonl"
    alerts.write_text("")
    d = _daemon(tmp_path, monkeypatch, self_paths=[state], watch_paths=[])
    d.handle_write(alerts, writer_pid=1, writer_exe="/usr/bin/python3")
    assert list(iter_alerts()) == []


def test_emit_respects_allowlist_and_coalesce(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch)
    alert = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[1],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd="/tmp/scratch",
        evidence={"flag": "--yolo", "flags": ["--yolo"]},
    )
    d.emit(alert)
    assert len(list(iter_alerts())) == 1
    d.emit(alert)
    assert len(list(iter_alerts())) == 1

    fp = fingerprint("R-BYPASS", "claude", frozenset(["--yolo"]), "/tmp/scratch")
    approve(fp, "this-repo", "/tmp/scratch")
    other = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[2],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd="/tmp/other",
        evidence={"flag": "--yolo", "flags": ["--yolo"]},
    )
    # force outside coalesce window via new coalescer key (other cwd)
    d.emit(other)
    assert len(list(iter_alerts())) == 2

    allowed = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[3],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd="/tmp/scratch/pkg",
        evidence={"flag": "--yolo", "flags": ["--yolo"]},
    )
    d.emit(allowed)
    assert len(list(iter_alerts())) == 2


def test_overflow_emits_warning_and_refreshes(tmp_path, monkeypatch):
    called: list[str] = []
    d = _daemon(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "sentinel.daemon.refresh_watchlist",
        lambda home=None: called.append("refresh") or tmp_path / "watchlist.json",
    )
    d.handle_overflow()
    d.handle_overflow()
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert "overflow" in rows[0].summary.lower()
    assert rows[0].severity in {"low", "medium", "high"}
    assert called == ["refresh", "refresh"]


def _fake_proc(root: Path, pid: int, exe_name: str, cmdline: list[str], cwd: Path) -> None:
    p = root / str(pid)
    p.mkdir(parents=True)
    cwd.mkdir(parents=True, exist_ok=True)
    (p / "cmdline").write_bytes(b"\0".join(s.encode() for s in cmdline) + b"\0")
    (p / "comm").write_text(exe_name + "\n")
    (p / "exe").symlink_to(f"/usr/bin/{exe_name}")
    (p / "cwd").symlink_to(cwd)


def test_sampler_detects_known_basename_bypass(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    cwd = tmp_path / "proj"
    _fake_proc(proc, 4242, "claude", ["claude", "--dangerously-skip-permissions"], cwd)
    _fake_proc(proc, 7, "bash", ["bash", "-c", "echo hi"], cwd)
    d = _daemon(
        tmp_path,
        monkeypatch,
        proc_root=proc,
        known_basenames=["claude"],
    )
    d.sample_proc()
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-BYPASS"
    assert rows[0].pids == [4242]
    assert rows[0].basename == "claude"
    d.sample_proc()
    assert len(list(iter_alerts())) == 1


def test_sampler_interval_clamped_2_to_5():
    from sentinel.daemon import load_config

    low = load_config(defaults={"sampler_interval": 0.5})
    high = load_config(defaults={"sampler_interval": 30})
    assert low["sampler_interval"] == 2.0
    assert high["sampler_interval"] == 5.0


def test_consume_launches_emits_rbypass(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch)
    record_launch(
        "claude",
        ["--yolo"],
        exe="/usr/bin/claude",
        cwd=str(tmp_path / "scratch"),
        pid=99,
    )
    d.consume_launches()
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-BYPASS"
    assert rows[0].pids == [99]
    d.consume_launches()
    assert len(list(iter_alerts())) == 1


def test_notify_hook_called(tmp_path, monkeypatch):
    seen: list[str] = []
    d = _daemon(tmp_path, monkeypatch, notify=lambda a: seen.append(a.rule))
    d.handle_process(
        ["claude", "--yolo"],
        "/usr/bin/claude",
        str(tmp_path),
        pid=5,
    )
    assert seen == ["R-BYPASS"]


def test_run_forever_stops_when_event_set(tmp_path, monkeypatch):
    import threading

    from sentinel.daemon import run_forever

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    stop = threading.Event()
    stop.set()
    run_forever({"stop": stop, "inotify": False, "sampler_interval": 2.0})


def test_cli_daemon_invokes_run_forever(monkeypatch):
    from sentinel.cli import main

    called: dict[str, object] = {}

    def fake_run(config):
        called["config"] = config

    monkeypatch.setattr("sentinel.daemon.run_forever", fake_run)
    assert main(["daemon"]) == 0
    assert "config" in called
    called.clear()
    assert main(["run"]) == 0
    assert "config" in called


def test_inotify_reports_close_write(tmp_path):
    from sentinel.daemon import IN_CLOSE_WRITE, Inotify

    watcher = Inotify()
    try:
        watcher.add_watch(tmp_path)
        (tmp_path / "hook.sh").write_text("echo\n")
        events = watcher.read_events()
        names = {e.name for e in events}
        assert "hook.sh" in names
        assert any(e.mask & IN_CLOSE_WRITE for e in events)
    finally:
        watcher.close()


def test_load_watchlist_parents_and_kinds(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    from sentinel.daemon import watch_roots_from_entries
    from sentinel.paths import state_dir

    state_dir().mkdir(parents=True)
    entries = [
        {"path": str(tmp_path / ".claude" / "settings.json"), "kind": "settings"},
        {"path": str(tmp_path / ".claude" / "hooks" / "x.sh"), "kind": "hooks"},
        {"path": str(tmp_path / ".claude" / "transcript.txt"), "kind": "other"},
    ]
    roots = watch_roots_from_entries(entries)
    assert tmp_path / ".claude" / "settings.json" in roots
    assert tmp_path / ".claude" / "hooks" / "x.sh" in roots
    assert tmp_path / ".claude" / "hooks" in roots
    assert tmp_path / ".claude" / "transcript.txt" not in roots
