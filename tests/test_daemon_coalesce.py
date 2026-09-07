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


def test_handle_write_operational_recorded_is_silent(tmp_path, monkeypatch):
    """A write the daemon itself recorded (its own ledger baseline) never
    alerts, even though OPERATIONAL_NAMES writes are no longer skipped
    outright (W3-07 R9)."""
    state = tmp_path / "state" / "sentinel"
    state.mkdir(parents=True)
    d = _daemon(tmp_path, monkeypatch, self_paths=[state], watch_paths=[])
    for name in ("alerts.jsonl", "launches.jsonl", "allowlist.json", "watchlist.json"):
        path = state / name
        path.write_text("")
        d._ledger.record(path)  # simulates the daemon's own write
        d.handle_write(path, writer_pid=1, writer_exe="/usr/bin/python3")
    assert list(iter_alerts()) == []


def test_handle_write_operational_unrecorded_raises_foreign(tmp_path, monkeypatch):
    """The same writes, without a prior ledger record/announce, are now
    classified foreign and each raise one R-SELF (W3-07 supersedes the old
    blanket OPERATIONAL_NAMES skip)."""
    state = tmp_path / "state" / "sentinel"
    state.mkdir(parents=True)
    d = _daemon(tmp_path, monkeypatch, self_paths=[state], watch_paths=[])
    names = ("alerts.jsonl", "launches.jsonl", "allowlist.json", "watchlist.json")
    for name in names:
        path = state / name
        path.write_text("x\n")  # newline-terminated so a later append_alert lands cleanly
        d.handle_write(path, writer_pid=1, writer_exe="/usr/bin/python3")
    rows = list(iter_alerts())
    assert len(rows) == len(names)
    assert all(r.rule == "R-SELF" and r.severity == "high" for r in rows)
    assert all(r.evidence.get("event") == "foreign-write" for r in rows)


def test_emit_appends_when_paused_without_calling_runner(tmp_path, monkeypatch):
    from datetime import timedelta

    from sentinel.action import write_pause
    from sentinel.notify import send_alert

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    write_pause(timedelta(hours=1))
    calls = []
    monkeypatch.setattr("sentinel.notify.run", lambda argv: calls.append(argv))
    d = _daemon(tmp_path, monkeypatch, notify=send_alert)
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
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].id == alert.id
    assert calls == []


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


def _fake_proc(
    root: Path,
    pid: int,
    exe_name: str,
    cmdline: list[str],
    cwd: Path,
    *,
    comm: str | None = None,
    exe_target: str | None = None,
    starttime: int | None = None,
) -> None:
    p = root / str(pid)
    p.mkdir(parents=True, exist_ok=True)
    cwd.mkdir(parents=True, exist_ok=True)
    if starttime is not None:
        (p / "stat").write_text(
            f"{pid} ({exe_name}) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {starttime} 0 0 0\n"
        )
    (p / "cmdline").write_bytes(b"\0".join(s.encode() for s in cmdline) + b"\0")
    (p / "comm").write_text((comm if comm is not None else exe_name) + "\n")
    (p / "exe").symlink_to(exe_target or f"/usr/bin/{exe_name}")
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


def test_maybe_sample_skips_until_interval(tmp_path, monkeypatch):
    now = [0.0]
    d = _daemon(
        tmp_path,
        monkeypatch,
        clock=lambda: now[0],
        sampler_interval=2.0,
    )
    calls = {"n": 0}
    d.sample_proc = lambda: calls.__setitem__("n", calls["n"] + 1)
    assert d.maybe_sample() is True
    assert calls["n"] == 1
    now[0] = 1.9
    assert d.maybe_sample() is False
    assert calls["n"] == 1
    now[0] = 2.0
    assert d.maybe_sample() is True
    assert calls["n"] == 2


def test_sampler_matches_comm_deleted_exe_and_node_wrapper(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    cwd = tmp_path / "proj"
    _fake_proc(
        proc,
        11,
        "node",
        ["node", "/usr/lib/node_modules/.bin/claude", "--yolo"],
        cwd,
        comm="node",
        exe_target="/usr/bin/node",
    )
    _fake_proc(
        proc,
        12,
        "python3",
        ["python3", "--yolo"],
        cwd,
        comm="claude",
        exe_target="/usr/bin/python3",
    )
    _fake_proc(
        proc,
        13,
        "claude",
        ["claude", "--trust-all"],
        cwd,
        comm="claude",
        exe_target="/usr/bin/claude (deleted)",
    )
    _fake_proc(
        proc,
        14,
        "node",
        ["node", "server.js"],
        cwd,
        comm="node",
        exe_target="/usr/bin/node",
    )
    d = _daemon(
        tmp_path,
        monkeypatch,
        proc_root=proc,
        known_basenames=["claude"],
    )
    d.sample_proc()
    rows = list(iter_alerts())
    pids = {p for row in rows for p in row.pids}
    assert pids == {11, 12, 13}
    assert all(row.rule == "R-BYPASS" for row in rows)


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


def test_watch_mask_includes_moved_from():
    from sentinel.daemon import IN_DELETE_SELF, IN_MOVED_FROM, IN_MOVE_SELF, WATCH_MASK

    assert WATCH_MASK & IN_MOVED_FROM
    assert WATCH_MASK & IN_MOVE_SELF
    assert WATCH_MASK & IN_DELETE_SELF


def test_move_self_triggers_watch_lost(tmp_path, monkeypatch):
    from sentinel.daemon import IN_MOVE_SELF, InotifyEvent

    d = _daemon(tmp_path, monkeypatch)
    called: list[str] = []
    d.handle_watch_lost = lambda path=None, mask=0: called.append("lost")

    class FakeIno:
        wd_to_path = {1: tmp_path / "hooks"}

        def read_events(self):
            return [InotifyEvent(wd=1, mask=IN_MOVE_SELF, cookie=0, name="")]

    d._inotify = FakeIno()
    d._drain_inotify()
    assert called == ["lost"]


def test_transient_subdir_loss_is_silent(tmp_path, monkeypatch):
    """A directory that appears under a watched dir and vanishes again (a lock
    dir) must not raise an alert or trigger a watchlist refresh."""
    from sentinel.daemon import IN_CREATE, IN_DELETE_SELF, IN_ISDIR, InotifyEvent

    d = _daemon(tmp_path, monkeypatch)
    lost: list[str] = []
    d.handle_watch_lost = lambda path=None, mask=0: lost.append(str(path))
    refreshed: list[str] = []
    monkeypatch.setattr("sentinel.daemon.refresh_watchlist", lambda home=None: refreshed.append("r"))

    class FakeIno:
        wd_to_path = {1: tmp_path / ".claude"}
        added: list = []

        def add_watch(self, path, mask=0):
            self.added.append(path)
            self.wd_to_path[2] = path
            return 2

        def read_events(self):
            return [
                InotifyEvent(wd=1, mask=IN_CREATE | IN_ISDIR, cookie=0, name="history.jsonl.lock"),
                InotifyEvent(wd=2, mask=IN_DELETE_SELF, cookie=0, name=""),
            ]

    d._inotify = FakeIno()
    d._drain_inotify()
    assert lost == []
    assert refreshed == []
    assert list(iter_alerts()) == []
    assert 2 not in d._auto_wds


def test_real_inotify_lock_dir_churn_is_silent(tmp_path, monkeypatch):
    import os

    watched = tmp_path / "claude"
    watched.mkdir()
    refreshed: list[str] = []
    monkeypatch.setattr("sentinel.daemon.refresh_watchlist", lambda home=None: refreshed.append("r"))
    d = _daemon(tmp_path, monkeypatch, inotify=True, watch_paths=[str(watched)], self_paths=[str(tmp_path / "self")])
    d._rebuild_watches()
    assert d._inotify is not None
    for _ in range(20):
        lock = watched / "history.jsonl.lock"
        lock.mkdir()
        d._drain_inotify()
        lock.rmdir()
        d._drain_inotify()
    d._drain_inotify()
    d._close_inotify()
    assert refreshed == []
    assert list(iter_alerts()) == []


def test_root_loss_still_alerts_with_real_event_name(tmp_path, monkeypatch):
    from sentinel.daemon import IN_DELETE_SELF

    d = _daemon(tmp_path, monkeypatch)
    monkeypatch.setattr("sentinel.daemon.refresh_watchlist", lambda home=None: tmp_path / "watchlist.json")
    d.handle_watch_lost(tmp_path / "hooks", IN_DELETE_SELF)
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].evidence["event"] == "IN_DELETE_SELF"
    assert "deleted" in rows[0].summary


def test_handle_watch_lost_refreshes(tmp_path, monkeypatch):
    called: list[str] = []
    d = _daemon(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "sentinel.daemon.refresh_watchlist",
        lambda home=None: called.append("refresh") or tmp_path / "watchlist.json",
    )
    d.handle_watch_lost()
    d.handle_watch_lost()
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert "moved" in rows[0].summary.lower() or "deleted" in rows[0].summary.lower()
    assert called == ["refresh", "refresh"]


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


def _bypass(cwd="/tmp/scratch", pid=1):
    return Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[pid],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd=cwd,
        evidence={"flag": "--yolo", "flags": ["--yolo"]},
    )


def test_forever_scope_is_global(tmp_path, monkeypatch):
    from sentinel.allowlist import approve, clear_session, fingerprint

    d = _daemon(tmp_path, monkeypatch)
    clear_session()
    approve(fingerprint("R-BYPASS", "claude", frozenset(["--yolo"]), ""), "forever", "")
    for cwd in ("/a/b/c/d", "/a/b", "/x/y"):
        d.emit(_bypass(cwd=cwd))
    assert list(iter_alerts()) == []


def test_this_repo_scope_reaches_repo_root(tmp_path, monkeypatch):
    from sentinel.allowlist import approve, clear_session, fingerprint

    d = _daemon(tmp_path, monkeypatch)
    clear_session()
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    approve(fingerprint("R-BYPASS", "claude", frozenset(["--yolo"]), str(root)), "this-repo", str(root))
    d.emit(_bypass(cwd=str(root)))
    d.emit(_bypass(cwd=str(root / "other")))
    assert list(iter_alerts()) == []
    d.emit(_bypass(cwd=str(tmp_path / "sibling")))
    assert len(list(iter_alerts())) == 1


def test_session_scope_crosses_process_boundary_until_restart(tmp_path, monkeypatch):
    from sentinel.allowlist import approve, clear_session, fingerprint

    d = _daemon(tmp_path, monkeypatch)  # sets XDG_STATE_HOME before any allowlist write
    clear_session()
    # sentinel-action runs in another process; only the file can carry the approval.
    approve(fingerprint("R-BYPASS", "claude", frozenset(["--yolo"]), ""), "session", "")
    d.emit(_bypass())
    assert list(iter_alerts()) == []
    clear_session()  # what the daemon does at startup
    d2 = _daemon(tmp_path, monkeypatch)
    d2.emit(_bypass(cwd="/tmp/other"))
    assert len(list(iter_alerts())) == 1


def test_24h_expiry_emits_allow_expire_once_then_normal(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sentinel.allowlist import _load_persisted, approve, clear_session, fingerprint

    later = datetime.now(timezone.utc) + timedelta(hours=25)
    d = _daemon(tmp_path, monkeypatch, wall_clock=lambda: later)
    clear_session()
    fp = fingerprint("R-BYPASS", "claude", frozenset(["--yolo"]), "")
    approve(fp, "24h", "")
    d.emit(_bypass())
    rows = list(iter_alerts())
    assert [r.rule for r in rows] == ["R-ALLOW-EXPIRE"]
    assert rows[0].severity == "low"
    assert rows[0].evidence["fingerprint"] == fp
    assert rows[0].evidence["expired_scope"] == "24h"
    assert rows[0].evidence["original_rule"] == "R-BYPASS"
    assert fp not in _load_persisted()
    d.emit(_bypass(pid=2))
    assert [r.rule for r in list(iter_alerts())] == ["R-ALLOW-EXPIRE", "R-BYPASS"]


def _bypass_proc(root, pid, cwd, starttime):
    _fake_proc(root, pid, "claude", ["claude", "--yolo"], cwd, starttime=starttime)


def test_same_instance_alerts_once(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    cwd = tmp_path / "proj"
    _bypass_proc(proc, 4242, cwd, 777)
    now = [1000.0]
    toasts: list = []
    d = _daemon(tmp_path, monkeypatch, proc_root=proc, known_basenames=["claude"], clock=lambda: now[0], sampler_interval=3.0, notify=lambda a: toasts.append(a))
    for _ in range(100):
        d.maybe_sample()
        now[0] += 3.0
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert len(toasts) == 1
    assert rows[0].evidence["starttime"] == 777
    assert rows[0].evidence["instance"] == "4242:777"
    assert rows[0].evidence["source"] == "sampler"


def test_new_instance_same_pid_alerts_again(tmp_path, monkeypatch):
    import shutil

    proc = tmp_path / "proc"
    cwd = tmp_path / "proj"
    _bypass_proc(proc, 4242, cwd, 777)
    d = _daemon(tmp_path, monkeypatch, proc_root=proc, known_basenames=["claude"])
    d.sample_proc()
    d.sample_proc()
    assert len(list(iter_alerts())) == 1
    shutil.rmtree(proc / "4242")
    _bypass_proc(proc, 4242, cwd, 999)  # pid recycled by a new claude
    d.sample_proc()
    rows = list(iter_alerts())
    assert len(rows) == 2
    assert rows[1].evidence["instance"] == "4242:999"


def test_seen_registry_prunes_dead(tmp_path, monkeypatch):
    import shutil

    proc = tmp_path / "proc"
    cwd = tmp_path / "proj"
    _bypass_proc(proc, 4242, cwd, 777)
    d = _daemon(tmp_path, monkeypatch, proc_root=proc, known_basenames=["claude"])
    d.sample_proc()
    assert len(d._seen) == 1
    shutil.rmtree(proc / "4242")
    d.sample_proc()
    assert d._seen == {}


def test_launch_record_carries_instance(tmp_path, monkeypatch):
    from sentinel.wrap_record import launch_to_alert

    a = launch_to_alert({"ts": "2026-09-05T00:00:00+00:00", "basename": "claude", "cmdline": ["claude", "--yolo"], "cwd": "/p", "pid": 12, "starttime": 55})
    assert a is not None
    assert a.evidence["instance"] == "12:55"
    assert a.evidence["source"] == "launches"
    assert a.evidence["launch_ts"].startswith("2026-09-05")


def test_pause_until_write_is_operational_when_recorded(tmp_path, monkeypatch):
    """pause_until stays an operational name and, when the daemon has recorded
    the write as its own (an in-cap value written via sentinel-action), stays
    silent -- it just goes through the ledger like the others now (W3-07)."""
    from sentinel.paths import state_dir

    d = _daemon(tmp_path, monkeypatch, self_paths=[str(state_dir())], watch_paths=[])
    state_dir().mkdir(parents=True, exist_ok=True)
    for name in ("pause_until", "alerts.lock", "alerts.jsonl.tmp", "alerts.jsonl.1", "notify-prefs.json"):
        p = state_dir() / name
        p.write_text("2020-01-01T00:00:00+00:00\n" if name == "pause_until" else "x")
        d._ledger.record(p)
        d.handle_write(p)
    assert list(iter_alerts()) == []


def test_pause_until_write_unrecorded_raises_foreign(tmp_path, monkeypatch):
    """The same files, unrecorded, now raise R-SELF instead of being skipped
    outright -- the old blanket OPERATIONAL_NAMES skip is gone (W3-07 R9)."""
    from sentinel.paths import state_dir

    d = _daemon(tmp_path, monkeypatch, self_paths=[str(state_dir())], watch_paths=[])
    state_dir().mkdir(parents=True, exist_ok=True)
    names = ("pause_until", "alerts.lock", "alerts.jsonl.tmp", "alerts.jsonl.1", "notify-prefs.json")
    for name in names:
        p = state_dir() / name
        p.write_text("2020-01-01T00:00:00+00:00\n" if name == "pause_until" else "x")
        d.handle_write(p)
    rows = list(iter_alerts())
    assert len(rows) == len(names)
    assert all(r.rule == "R-SELF" and r.evidence.get("event") == "foreign-write" for r in rows)


# --------------------------------------------------------- W3-07 self-defense


def test_emit_mirrors_alert_to_journal_after_append_alert(tmp_path, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr("sentinel.daemon.append_alert", lambda alert: order.append("append"))
    monkeypatch.setattr("sentinel.daemon.mirror_alert", lambda alert: order.append("mirror"))
    d = _daemon(tmp_path, monkeypatch)
    d.emit(_bypass())
    assert order == ["append", "mirror"]


def test_emit_survives_journal_mirror_raising(tmp_path, monkeypatch):
    def boom(alert):
        raise OSError("journal down")

    monkeypatch.setattr("sentinel.daemon.mirror_alert", boom)
    notified: list = []
    d = _daemon(tmp_path, monkeypatch, notify=lambda a: notified.append(a))
    alert = _bypass()
    d.emit(alert)
    rows = list(iter_alerts())
    assert len(rows) == 1 and rows[0].id == alert.id
    assert len(notified) == 1


def test_foreign_write_to_allowlist_raises_one_rself_high(tmp_path, monkeypatch):
    from sentinel.paths import state_dir

    d = _daemon(tmp_path, monkeypatch, self_paths=[state_dir()], watch_paths=[])
    state_dir().mkdir(parents=True, exist_ok=True)
    path = state_dir() / "allowlist.json"
    path.write_text('{"entries":{}}')  # written directly, no d._ledger.record/announce
    d.handle_write(path)
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-SELF" and rows[0].severity == "high"
    assert rows[0].evidence == {"event": "foreign-write", "path": str(path)}
    # An identical repeat write is already recorded by the alert above; no 2nd alert.
    d.handle_write(path)
    assert len(list(iter_alerts())) == 1


def test_truncated_alerts_jsonl_raises_rself(tmp_path, monkeypatch):
    from sentinel.paths import state_dir
    from sentinel.store import append_alert as real_append

    d = _daemon(tmp_path, monkeypatch, self_paths=[state_dir()], watch_paths=[])
    real_append(_bypass())
    real_append(_bypass(pid=2))
    path = state_dir() / "alerts.jsonl"
    d._ledger.record(path)  # the daemon's own append path has recorded it as ours
    path.write_text("")  # truncated directly, bypassing store.append_alert
    d.handle_write(path)
    rows = [a for a in iter_alerts() if a.rule == "R-SELF"]
    assert len(rows) == 1
    assert rows[0].severity == "high"
    assert rows[0].evidence.get("event") == "alert-log-truncated"
    assert rows[0].evidence.get("path") == str(path)


def test_cli_announced_write_produces_no_alert(tmp_path, monkeypatch):
    from sentinel import statewatch
    from sentinel.paths import state_dir

    d = _daemon(tmp_path, monkeypatch, self_paths=[state_dir()], watch_paths=[])
    path = state_dir() / "allowlist.json"
    content = '{"entries":{"x":1}}'
    digest = statewatch.sha256_bytes(content.encode())
    statewatch.announce_write(path, digest)  # what sentinel-action does, pre-write
    path.write_text(content)
    statewatch.announce_write(path, digest)  # ...and post-write
    d._drain_control_socket()
    d.handle_write(path)
    assert list(iter_alerts()) == []


def test_pause_30d_is_not_paused_and_raises_one_self_alert(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sentinel import action
    from sentinel.paths import state_dir

    d = _daemon(tmp_path, monkeypatch, self_paths=[state_dir()], watch_paths=[])
    state_dir().mkdir(parents=True, exist_ok=True)
    path = state_dir() / "pause_until"
    over = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    path.write_text(over + "\n")
    d.handle_write(path)
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-SELF" and rows[0].severity == "high"
    assert rows[0].evidence.get("event") == "pause-over-cap"
    assert rows[0].evidence.get("until") == over
    # An identical repeat write does not raise a second alert.
    d.handle_write(path)
    assert len(list(iter_alerts())) == 1
    assert action.is_paused(now=datetime.now(timezone.utc)) is False


def test_scan_report_write_is_ours_when_announced_else_foreign(tmp_path, monkeypatch):
    """state_dir()/scans/<digest>.json is written by sentinel-scan, not the daemon.
    Announced content classifies as ours (no alert); the same path written
    without an announcement is a foreign write to Sentinel's own state."""
    from sentinel.statewatch import sha256_bytes

    state = tmp_path / "state" / "sentinel"
    scans = state / "scans"
    scans.mkdir(parents=True)
    d = _daemon(tmp_path, monkeypatch, self_paths=[state], watch_paths=[])
    path = scans / "abc123.json"
    content = "{}\n"
    d._ledger.announce(path, sha256_bytes(content.encode("utf-8")))
    path.write_text(content)
    d.handle_write(path, writer_pid=1, writer_exe="/usr/bin/python3")
    assert list(iter_alerts()) == []
    path.write_text("{\"tampered\": true}\n")
    d.handle_write(path, writer_pid=1, writer_exe="/usr/bin/python3")
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-SELF"
    assert rows[0].evidence == {"event": "foreign-write", "path": str(path)}
