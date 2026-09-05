from sentinel.models import Alert
from sentinel.store import append_alert, iter_alerts, update_alert_status

def test_append_and_read_alert(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    a = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with bypassPermissions",
        pids=[1234],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd="/home/tav/Work/scratch",
        evidence={"flag": "bypassPermissions"},
    )
    append_alert(a)
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-BYPASS"
    assert rows[0].status == "open"
    update_alert_status(a.id, "approved")
    assert list(iter_alerts())[0].status == "approved"


def test_update_status_survives_concurrent_append(monkeypatch, tmp_path):
    import threading

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    first = Alert.new(rule="R-BYPASS", severity="high", summary="x", pids=[1], exe="", basename="claude", cmdline=["claude"], cwd="/p", evidence={})
    append_alert(first)

    def appender():
        for i in range(200):
            append_alert(Alert.new(rule="R-SELF", severity="low", summary=str(i), pids=[], exe="", basename="", cmdline=[], cwd="", evidence={}))

    t = threading.Thread(target=appender)
    t.start()
    for _ in range(200):
        update_alert_status(first.id, "approved")
    t.join()
    rows = list(iter_alerts())
    assert len(rows) == 201
    assert next(r for r in rows if r.id == first.id).status == "approved"


def test_rotation(monkeypatch, tmp_path):
    from sentinel import store

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(store, "MAX_BYTES", 2000)
    for i in range(30):
        append_alert(Alert.new(rule="R-SELF", severity="low", summary="s" * 100, pids=[], exe="", basename="", cmdline=[], cwd="", evidence={}))
    live = tmp_path / "sentinel" / "alerts.jsonl"
    rotated = tmp_path / "sentinel" / "alerts.jsonl.1"
    assert rotated.exists()
    assert live.stat().st_size < 2000 + 600  # rotation runs before an append; one row may overshoot
    assert len(list(iter_alerts())) < 30


def test_state_files_are_private(monkeypatch, tmp_path):
    import os
    import stat

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    a = Alert.new(rule="R-BYPASS", severity="high", summary="x", pids=[1], exe="", basename="claude", cmdline=["claude"], cwd="/p", evidence={})
    append_alert(a)
    update_alert_status(a.id, "dismissed")
    from sentinel.allowlist import approve
    from sentinel.action import write_pause
    from datetime import timedelta

    approve("fp", "forever", "")
    write_pause(timedelta(hours=1))
    d = tmp_path / "sentinel"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    for name in ("alerts.jsonl", "allowlist.json", "pause_until"):
        assert stat.S_IMODE((d / name).stat().st_mode) == 0o600, name


def test_iter_skips_torn_line(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    a = Alert.new(rule="R-BYPASS", severity="high", summary="x", pids=[1], exe="", basename="claude", cmdline=["claude"], cwd="/p", evidence={})
    append_alert(a)
    with (tmp_path / "sentinel" / "alerts.jsonl").open("a") as f:
        f.write('{"id": "torn", "rule": "R-')
    assert [r.id for r in iter_alerts()] == [a.id]
