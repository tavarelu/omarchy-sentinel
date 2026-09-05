from __future__ import annotations

import json
from pathlib import Path

from sentinel.models import Alert
from sentinel.notify import BurstPolicy, BurstTracker, Notifier, NotifyPolicy


def _alert(i, severity="high"):
    return Alert.new(
        rule="R-BYPASS",
        severity=severity,
        summary=f"claude started with --yolo #{i}",
        pids=[100 + i],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd=f"/w/{i}",
        evidence={"flag": "--yolo", "flags": ["--yolo"]},
    )


class Runner:
    def __init__(self):
        self.calls: list[list[str]] = []
        self.next_id = 42
        self.fail = False

    def __call__(self, argv):
        self.calls.append(argv)
        if self.fail:
            return None
        return f"{self.next_id}\n" if "-p" in argv else ""


def _setup(tmp_path, **policy):
    now = [1000.0]
    runner = Runner()
    n = Notifier(
        NotifyPolicy(burst=BurstPolicy(**policy)) if policy else NotifyPolicy(),
        runner=runner,
        clock=lambda: now[0],
        state_path=tmp_path / "burst.json",
        prefs_file=tmp_path / "prefs.json",
        paused=lambda: False,
    )
    return n, runner, now


def test_first_five_alerts_toast_individually(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(5):
        n.send(_alert(i))
        now[0] += 1
    assert len(r.calls) == 5
    assert all("-p" not in c for c in r.calls)


def test_sixth_alert_sends_summary_with_print_id_and_no_replace(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 1
    summary = r.calls[5]
    assert "-p" in summary and "-r" not in summary
    assert summary[summary.index("--app-name") + 2] == "Sentinel: 6 alerts"


def test_seventh_alert_replaces_with_captured_id(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(7):
        n.send(_alert(i))
        now[0] += 1
    seventh = r.calls[6]
    assert seventh[seventh.index("-r") + 1] == "42"
    assert "-p" in seventh


def test_summary_title_body_and_exec(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(5):
        n.send(_alert(i))
        now[0] += 1
    n.send(_alert(5, "medium"))
    n.send(_alert(6, "medium"))
    argv = r.calls[-1]
    i = argv.index("--app-name")
    assert argv[i + 2] == "Sentinel: 7 alerts"
    assert argv[i + 3] == "5 high · 2 medium — newest: claude started with --yolo #6. Click to open the panel."
    assert argv[-6:] == ["--exec", "omarchy-shell", "shell", "summon", "tav.sentinel", "{}"]
    assert argv[3:7] == ["-u", "normal", "-t", "30000"]


def test_zero_count_severities_omitted_from_body(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 1
    body = r.calls[-1][r.calls[-1].index("--app-name") + 3]
    assert body.startswith("6 high — newest:")
    assert "medium" not in body and "low" not in body


def test_burst_resets_after_quiet_period(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 1
    now[0] += 600
    n.send(_alert(9))
    assert "-p" not in r.calls[-1]  # an individual toast again
    state = json.loads((tmp_path / "burst.json").read_text())
    assert state["active"] is False and state["by_severity"] == {"high": 1}


def test_window_prunes_old_events(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 70  # never more than 5 inside any 300 s window
    assert all("-p" not in c for c in r.calls)


def test_state_persisted_and_restored_on_restart(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 1
    n2 = Notifier(NotifyPolicy(), runner=r, clock=lambda: now[0], state_path=tmp_path / "burst.json", prefs_file=tmp_path / "p.json", paused=lambda: False)
    n2.send(_alert(7))
    argv = r.calls[-1]
    assert argv[argv.index("-r") + 1] == "42"
    assert argv[argv.index("--app-name") + 2] == "Sentinel: 7 alerts"


def test_state_corrupt_starts_clean(tmp_path):
    (tmp_path / "burst.json").write_text("{corrupt")
    n, r, now = _setup(tmp_path)
    n.send(_alert(1))
    assert "-p" not in r.calls[0]


def test_stale_id_is_replaced_by_new_printed_id(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 1
    r.next_id = 77  # the user closed the toast; the server allocates a new id
    n.send(_alert(6))
    n.send(_alert(7))
    assert r.calls[-1][r.calls[-1].index("-r") + 1] == "77"


def test_paused_and_disabled_alerts_do_not_count(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(10):
        n.send(_alert(i, "low"))  # disabled by default
    assert r.calls == []
    assert not (tmp_path / "burst.json").exists()


def test_runner_failure_keeps_previous_summary_id(tmp_path):
    n, r, now = _setup(tmp_path)
    for i in range(6):
        n.send(_alert(i))
        now[0] += 1
    r.fail = True
    n.send(_alert(6))
    r.fail = False
    n.send(_alert(7))
    assert r.calls[-1][r.calls[-1].index("-r") + 1] == "42"


def test_daemon_emit_drives_notifier_with_wall_clock(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sentinel import notify
    from sentinel.daemon import Daemon

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    r = Runner()
    monkeypatch.setattr(notify, "run", r)
    monkeypatch.setattr("sentinel.notify.is_paused", lambda: False)
    t = [datetime(2026, 9, 5, tzinfo=timezone.utc)]
    d = Daemon({"inotify": False, "wall_clock": lambda: t[0]})
    for i in range(6):
        d.handle_process(["claude", "--yolo"], "/x/claude", f"/w/{i}", pid=100 + i, starttime=5)
        t[0] += timedelta(seconds=1)
    assert len(r.calls) == 6
    assert sum(1 for c in r.calls if "-p" in c) == 1


def test_tracker_totals_and_dict_roundtrip(tmp_path):
    now = [0.0]
    tr = BurstTracker(BurstPolicy(threshold=2, window_sec=100, quiet_sec=50), clock=lambda: now[0])
    assert tr.record("high") == "toast"
    assert tr.record("medium") == "toast"
    assert tr.record("high") == "summary"
    assert tr.totals() == (3, {"high": 2, "medium": 1})
    tr.summary_id = 9
    tr.save(tmp_path / "b.json")
    back = BurstTracker.load(tmp_path / "b.json", tr.policy, clock=lambda: now[0])
    assert back.active and back.summary_id == 9 and back.totals() == (3, {"high": 2, "medium": 1})
