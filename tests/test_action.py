from datetime import datetime, timedelta, timezone

import pytest

from sentinel.action import open_argv, open_target
from sentinel.allowlist import clear_session, fingerprint, is_allowed
from sentinel.cli import action_main
from sentinel.models import Alert
from sentinel.paths import state_dir
from sentinel.store import append_alert, iter_alerts


def _alert(**overrides) -> Alert:
    data = dict(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with bypassPermissions",
        pids=[100, 101],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd="/home/tav/Work/scratch",
        evidence={
            "flag": "--dangerously-skip-permissions",
            "flags": ["--dangerously-skip-permissions"],
            "child_pids": [101],
        },
    )
    data.update(overrides)
    return Alert.new(**data)


def test_approve_writes_allowlist_and_status(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    clear_session()
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    sub = root / "sub"
    sub.mkdir()
    alert = _alert(cwd=str(sub))
    append_alert(alert)
    assert action_main([alert.id, "approve", "--scope", "this-repo"]) == 0
    assert list(iter_alerts())[0].status == "approved"
    # this-repo is keyed on the repository root, not the subdirectory the agent ran in.
    fp = fingerprint(
        alert.rule,
        alert.basename,
        frozenset(["--dangerously-skip-permissions"]),
        str(root),
    )
    assert is_allowed(fp, str(root)) is True
    assert is_allowed(fp, str(root / "other")) is True
    assert is_allowed(fp, str(tmp_path / "elsewhere")) is False


def test_approve_write_alert_suppresses_daemon(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    clear_session()
    from sentinel.daemon import _is_alert_allowed
    from sentinel.rules import evaluate_write

    target = tmp_path / "settings.json"
    target.write_text("{}")
    first = evaluate_write(target, None, None, self_paths=[], watch_paths=[target])
    assert first is not None and first.rule == "R-HOOK-WRITE"
    append_alert(first)
    assert action_main([first.id, "approve", "--scope", "forever"]) == 0
    again = evaluate_write(target, None, None, self_paths=[], watch_paths=[target])
    assert _is_alert_allowed(again) is True


def test_approve_forever_is_global(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    clear_session()
    from sentinel.daemon import _is_alert_allowed

    alert = _alert(cwd="/a/b/c")
    append_alert(alert)
    assert action_main([alert.id, "approve", "--scope", "forever"]) == 0
    for cwd in ("/a/b/c/d", "/a/b", "/x/y"):
        assert _is_alert_allowed(_alert(cwd=cwd)) is True


def test_approve_subcommand_first(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    clear_session()
    alert = _alert()
    append_alert(alert)
    assert action_main(["approve", alert.id, "--scope", "session"]) == 0
    assert list(iter_alerts())[0].status == "approved"


def test_dismiss_updates_status_without_allowlist(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    clear_session()
    alert = _alert()
    append_alert(alert)
    assert action_main([alert.id, "dismiss"]) == 0
    assert list(iter_alerts())[0].status == "dismissed"
    fp = fingerprint(
        alert.rule,
        alert.basename,
        frozenset(["--dangerously-skip-permissions"]),
        alert.cwd,
    )
    assert is_allowed(fp, alert.cwd) is False


def test_kill_child_with_yes(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    planned: list[object] = []
    executed: list[list[int]] = []

    def fake_plan(*args, **kwargs):
        planned.append((args, kwargs))
        return [101]

    monkeypatch.setattr("sentinel.action.plan_kill", fake_plan)
    monkeypatch.setattr(
        "sentinel.action.execute_kill",
        lambda pids, **k: executed.append(list(pids)),
    )
    assert action_main(["kill", alert.id, "--yes"]) == 0
    assert planned
    kwargs = planned[0][1]
    assert kwargs.get("mode") == "child" or (
        len(planned[0][0]) >= 3 and planned[0][0][2] == "child"
    )
    assert executed == [[101]]
    assert list(iter_alerts())[0].status == "killed"


def test_kill_session_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    modes: list[str] = []

    def fake_plan(*args, **kwargs):
        mode = kwargs.get("mode")
        if mode is None and len(args) >= 3:
            mode = args[2]
        modes.append(mode)
        return [100, 101]

    monkeypatch.setattr("sentinel.action.plan_kill", fake_plan)
    monkeypatch.setattr("sentinel.action.execute_kill", lambda pids, **k: None)
    assert action_main([alert.id, "kill", "--session", "--yes"]) == 0
    assert modes == ["session"]
    assert list(iter_alerts())[0].status == "killed"


def test_kill_refuses_without_yes_when_not_tty(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    executed: list[list[int]] = []
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [101])
    monkeypatch.setattr(
        "sentinel.action.execute_kill",
        lambda pids, **k: executed.append(list(pids)),
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert action_main(["kill", alert.id]) == 1
    assert executed == []
    assert list(iter_alerts())[0].status == "open"


def test_kill_session_precious_refuses_yes_without_tty(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(cwd="/home/tav/Work/prod")
    append_alert(alert)
    executed: list[list[int]] = []
    monkeypatch.setattr(
        "sentinel.action.load_precious_worktrees",
        lambda: ["/home/tav/Work/prod"],
    )
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [100, 101])
    monkeypatch.setattr(
        "sentinel.action.execute_kill",
        lambda pids, **k: executed.append(list(pids)),
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert action_main(["kill", alert.id, "--session", "--yes"]) == 1
    assert executed == []
    assert list(iter_alerts())[0].status == "open"


def test_kill_child_yes_allowed_on_precious(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(cwd="/home/tav/Work/prod")
    append_alert(alert)
    executed: list[list[int]] = []
    monkeypatch.setattr(
        "sentinel.action.load_precious_worktrees",
        lambda: ["/home/tav/Work/prod"],
    )
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [101])
    monkeypatch.setattr(
        "sentinel.action.execute_kill",
        lambda pids, **k: executed.append(list(pids)),
    )
    assert action_main(["kill", alert.id, "--yes"]) == 0
    assert executed == [[101]]
    assert list(iter_alerts())[0].status == "killed"


def test_kill_does_not_allowlist(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    clear_session()
    alert = _alert()
    append_alert(alert)
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [101])
    monkeypatch.setattr("sentinel.action.execute_kill", lambda pids, **k: None)
    assert action_main(["kill", alert.id, "--yes"]) == 0
    fp = fingerprint(
        alert.rule,
        alert.basename,
        frozenset(["--dangerously-skip-permissions"]),
        alert.cwd,
    )
    assert is_allowed(fp, alert.cwd) is False


def test_pause_writes_iso_timestamp(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    frozen = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("sentinel.action._now", lambda: frozen)
    from sentinel.action import is_paused

    assert action_main(["pause", "1h"]) == 0
    text = (tmp_path / "sentinel" / "pause_until").read_text(encoding="utf-8").strip()
    assert text == (frozen + timedelta(hours=1)).isoformat()
    assert is_paused(now=frozen) is True
    assert is_paused(now=frozen + timedelta(minutes=59)) is True
    assert is_paused(now=frozen + timedelta(hours=1)) is False


def test_is_paused_false_without_file(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    from sentinel.action import is_paused

    assert is_paused() is False


def test_pause_refuses_over_cap(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from sentinel.action import pause_until_path

    assert action_main(["pause", "25h"]) == 2
    assert not pause_until_path().exists()


def test_pause_boundary_equal_to_cap_is_allowed(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from sentinel.action import pause_until_path

    assert action_main(["pause", "24h"]) == 0
    assert pause_until_path().exists()


def test_pause_refuses_over_configured_cap(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    cfg_dir = tmp_path / "config" / "sentinel"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text('[notify]\npause_max = "2h"\n')
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert action_main(["pause", "3h"]) == 2
    assert action_main(["pause", "1h"]) == 0


def test_is_paused_false_when_pause_until_exceeds_cap(monkeypatch, tmp_path):
    from datetime import timedelta

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    frozen = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("sentinel.action._now", lambda: frozen)
    from sentinel.action import is_paused, write_pause

    write_pause(timedelta(days=30), now=frozen)  # bypasses cmd_pause's own cap check
    assert is_paused(now=frozen) is False
    assert is_paused(now=frozen + timedelta(days=1)) is False


def test_investigate_prints_detail(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    assert action_main(["investigate", alert.id]) == 0
    out = capsys.readouterr().out
    assert alert.id in out
    assert alert.rule in out
    assert alert.cwd in out
    assert " ".join(alert.cmdline) in out or str(alert.cmdline) in out
    assert list(iter_alerts())[0].status == "investigated"


def test_list_and_status_and_menu(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    assert action_main(["list"]) == 0
    listed = capsys.readouterr().out
    assert alert.id in listed
    assert "R-BYPASS" in listed

    assert action_main(["status"]) == 0
    status_out = capsys.readouterr().out.lower()
    assert "open" in status_out

    assert action_main([alert.id, "menu"]) == 0
    menu = capsys.readouterr().out.lower()
    assert "approve" in menu
    assert "kill" in menu
    assert "investigate" in menu
    assert "dismiss" in menu


def test_unknown_alert_id_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert action_main(["dismiss", "missing-id"]) == 1


def test_kill_permission_error_leaves_open(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)

    def boom(*args, **kwargs):
        raise PermissionError("pid 101 not owned by user")

    monkeypatch.setattr("sentinel.action.plan_kill", boom)
    monkeypatch.setattr("sentinel.action.execute_kill", lambda pids, **k: None)
    assert action_main(["kill", alert.id, "--yes"]) == 1
    assert list(iter_alerts())[0].status == "open"


def test_kill_refuses_stale_alert_without_starttime(monkeypatch, tmp_path, capsys):
    from datetime import datetime, timedelta, timezone

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    alert.ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    append_alert(alert)
    killed: list = []
    monkeypatch.setattr("sentinel.action.execute_kill", lambda plan: killed.append(plan))
    assert action_main([alert.id, "kill", "--yes"]) == 1
    assert "start time" in capsys.readouterr().err
    assert killed == []
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [101])
    assert action_main([alert.id, "kill", "--yes", "--force-stale"]) == 0
    assert killed == [[101]]


def test_kill_passes_recorded_starttime(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(pids=[101], evidence={"flag": "--yolo", "flags": ["--yolo"], "starttime": 500, "instance": "101:500"})
    append_alert(alert)
    seen: dict = {}

    def fake_plan(pids, child_pids=None, mode="child", **kw):
        seen.update(kw)
        return []

    monkeypatch.setattr("sentinel.action.plan_kill", fake_plan)
    monkeypatch.setattr("sentinel.action.execute_kill", lambda plan: None)
    assert action_main([alert.id, "kill", "--yes"]) == 0
    assert seen["expected_starttime"] == {101: 500}


def test_notify_prints_effective_policy_and_sources(monkeypatch, tmp_path, capsys):
    assert action_main(["notify"]) == 0
    out = capsys.readouterr().out
    assert "high    on " in out and "low     off" in out and "source: config" in out
    assert "sticky" in out and "burst" in out and "prefs" in out


def test_notify_severity_writes_prefs_merged_0600(monkeypatch, tmp_path):
    import json
    import stat

    from sentinel.notify import prefs_path

    assert action_main(["notify", "--severity", "low=on"]) == 0
    assert action_main(["notify", "--severity", "high=off"]) == 0
    data = json.loads(prefs_path().read_text())
    assert data["severities"] == {"high": False, "low": True}
    assert stat.S_IMODE(prefs_path().stat().st_mode) == 0o600


def test_notify_rejects_bad_value(capsys):
    assert action_main(["notify", "--severity", "high=maybe"]) == 1
    assert "invalid" in capsys.readouterr().err


def test_notify_reset_removes_file():
    from sentinel.notify import prefs_path

    action_main(["notify", "--severity", "low=on"])
    assert prefs_path().exists()
    assert action_main(["notify", "--reset"]) == 0
    assert not prefs_path().exists()


def test_notify_json_output(capsys):
    import json

    action_main(["notify", "--severity", "medium=off"])
    capsys.readouterr()
    assert action_main(["notify", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["medium"] is False and data["source"]["medium"] == "prefs" and data["source"]["high"] == "config"


def test_open_reveals_existing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    target = tmp_path / "watched" / "settings.json"
    target.parent.mkdir()
    target.write_text("{}", encoding="utf-8")
    alert = _alert(rule="R-HOOK-WRITE", paths=[str(target)], cwd="", pids=[])
    mode, path = open_target(alert)
    assert mode == "select"
    assert path == target
    assert open_argv(mode, path) == [
        "uwsm-app",
        "--",
        "nautilus",
        "--select",
        target.as_uri(),
    ]
    append_alert(alert)
    launched: list[list[str]] = []
    monkeypatch.setattr("sentinel.action.shutil.which", lambda name: "/usr/bin/nautilus")
    monkeypatch.setattr(
        "sentinel.action.launch_detached",
        lambda argv, **k: launched.append(list(argv)),
    )
    assert action_main([alert.id, "open"]) == 0
    assert launched == [open_argv("select", target)]


def test_open_falls_back_to_parent_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    missing = tmp_path / "watched" / "gone.json"
    missing.parent.mkdir()
    alert = _alert(rule="R-HOOK-WRITE", paths=[str(missing)], cwd="", pids=[])
    mode, path = open_target(alert)
    assert mode == "dir"
    assert path == missing.parent
    assert open_argv(mode, path) == [
        "uwsm-app",
        "--",
        "nautilus",
        "--new-window",
        str(path),
    ]


def test_open_uses_cwd_for_process_alert(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    cwd = tmp_path / "repo"
    cwd.mkdir()
    alert = _alert(paths=None, cwd=str(cwd))
    mode, path = open_target(alert)
    assert mode == "dir"
    assert path == cwd


def test_open_logs_opens_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _alert()
    mode, path = open_target(alert, logs=True)
    assert mode == "dir"
    assert path == state_dir()
    assert path == tmp_path / "state" / "sentinel"


def test_open_refuses_relative_path_and_missing_location(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    relative = _alert(paths=["relative/file.json"], cwd="")
    with pytest.raises(ValueError):
        open_target(relative)
    missing = _alert(paths=None, cwd="")
    with pytest.raises(ValueError):
        open_target(missing)
    rel_cwd = _alert(paths=None, cwd="not/absolute")
    with pytest.raises(ValueError):
        open_target(rel_cwd)


def test_open_unknown_alert_fails(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert action_main(["open", "missing-id"]) == 1
    assert "unknown alert" in capsys.readouterr().err


def test_menu_lists_open_and_logs(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _alert()
    append_alert(alert)
    assert action_main([alert.id, "menu"]) == 0
    menu = capsys.readouterr().out
    assert f"sentinel-action {alert.id} open" in menu
    assert f"sentinel-action {alert.id} open --logs" in menu
    assert "approve --scope" in menu
