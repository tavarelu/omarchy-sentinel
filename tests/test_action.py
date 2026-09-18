from datetime import datetime, timedelta, timezone

import pytest

from sentinel.action import cmd_menu, open_argv, open_target
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
        cwd="/home/user/Work/scratch",
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
    alert = _alert(cwd="/home/user/Work/prod")
    append_alert(alert)
    executed: list[list[int]] = []
    monkeypatch.setattr(
        "sentinel.action.load_precious_worktrees",
        lambda: ["/home/user/Work/prod"],
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
    alert = _alert(cwd="/home/user/Work/prod")
    append_alert(alert)
    executed: list[list[int]] = []
    monkeypatch.setattr(
        "sentinel.action.load_precious_worktrees",
        lambda: ["/home/user/Work/prod"],
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
        # Must be non-empty: an empty plan is now a refusal, not a silent success.
        return [101]

    monkeypatch.setattr("sentinel.action.plan_kill", fake_plan)
    monkeypatch.setattr("sentinel.action.execute_kill", lambda plan: None)
    assert action_main([alert.id, "kill", "--yes"]) == 0
    assert seen["expected_starttime"] == {101: 500}


def test_kill_refuses_alert_with_no_pids(monkeypatch, tmp_path, capsys):
    """A write-rule alert carries no pid, so kill must refuse instead of
    reporting success. inotify names the file that changed, never the writer."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(rule="R-HOOK-WRITE", pids=[], evidence={"path": "/tmp/x"})
    append_alert(alert)
    killed: list = []
    monkeypatch.setattr("sentinel.action.execute_kill", lambda plan: killed.append(plan))
    assert action_main([alert.id, "kill", "--yes"]) == 1
    err = capsys.readouterr().err
    assert "records no process id" in err
    assert "R-HOOK-WRITE" in err
    assert killed == []
    # The alert must stay open: nothing was killed, so nothing is resolved.
    assert list(iter_alerts())[0].status == "open"


def test_kill_refuses_when_every_pid_is_gone(monkeypatch, tmp_path, capsys):
    """Recorded pids that have exited or been recycled leave an empty plan."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(evidence={"flag": "--yolo", "flags": ["--yolo"], "starttime": 500})
    append_alert(alert)
    killed: list = []
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [])
    monkeypatch.setattr("sentinel.action.execute_kill", lambda plan: killed.append(plan))
    assert action_main([alert.id, "kill", "--yes"]) == 1
    assert "no live target" in capsys.readouterr().err
    assert killed == []
    assert list(iter_alerts())[0].status == "open"


def test_kill_with_no_target_never_prompts(monkeypatch, tmp_path):
    """The plan is built before consent is asked, so an unkillable alert must
    not put a y/N prompt in front of the user at all."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(rule="R-SELF", pids=[], evidence={"path": "/tmp/x"})
    append_alert(alert)
    asked: list = []

    def fake_confirm(**kwargs):
        asked.append(kwargs)
        return True

    monkeypatch.setattr("sentinel.action.confirm_kill", fake_confirm)
    monkeypatch.setattr("sentinel.action.execute_kill", lambda plan: None)
    assert action_main([alert.id, "kill"]) == 1
    assert asked == []


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


def test_menu_non_tty_keeps_cheat_sheet_even_with_isatty_kwarg_unset(monkeypatch, tmp_path, capsys):
    # Re-run of test_menu_lists_open_and_logs's assertions through cmd_menu
    # directly, proving the isatty=None default still resolves to the
    # non-tty cheat sheet under pytest's captured stdin.
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _alert()
    append_alert(alert)
    assert cmd_menu(alert.id) == 0
    menu = capsys.readouterr().out
    assert f"sentinel-action {alert.id} open" in menu
    assert "approve --scope" in menu
    assert "0 nothing" not in menu


def test_menu_interactive_dispatch(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _alert()
    append_alert(alert)
    rc = cmd_menu(alert.id, isatty=True, prompt=lambda _: "9")
    assert rc == 0
    assert list(iter_alerts())[0].status == "dismissed"
    out = capsys.readouterr().out
    assert "9 dismiss" in out


def test_menu_interactive_dispatch_approve_session(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    clear_session()
    alert = _alert()
    append_alert(alert)
    rc = cmd_menu(alert.id, isatty=True, prompt=lambda _: "1")
    assert rc == 0
    assert list(iter_alerts())[0].status == "approved"
    fp = fingerprint(
        alert.rule,
        alert.basename,
        frozenset(["--dangerously-skip-permissions"]),
        "",
    )
    assert is_allowed(fp, alert.cwd) is True


def test_menu_interactive_dispatch_zero_does_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    rc = cmd_menu(alert.id, isatty=True, prompt=lambda _: "0")
    assert rc == 0
    assert list(iter_alerts())[0].status == "open"


def test_menu_interactive_unrecognized_choice_does_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    rc = cmd_menu(alert.id, isatty=True, prompt=lambda _: "x")
    assert rc == 0
    assert list(iter_alerts())[0].status == "open"
    assert "unrecognized choice" in capsys.readouterr().err


def test_menu_interactive_kill_child_no_pids_does_not_crash(monkeypatch, tmp_path):
    # No PIDs on the alert: plan_kill has nothing to kill. Selecting "5" in
    # the menu must not raise, and must not silently mark the alert killed
    # via a confirmation the menu keypress itself supplied.
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(pids=[], evidence={"flag": "--yolo", "flags": ["--yolo"]})
    append_alert(alert)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = cmd_menu(alert.id, isatty=True, prompt=lambda _: "5")
    assert rc in (0, 1)
    assert list(iter_alerts())[0].status == "open"


def test_menu_interactive_kill_session_precious_still_requires_tty_phrase(monkeypatch, tmp_path):
    # The menu's own isatty=True (for reading the numbered choice) must not
    # leak into kill.confirm_kill's separate tty/phrase gate — selecting "6"
    # is never sufficient consent to kill a precious worktree on its own.
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert(cwd="/home/user/Work/prod")
    append_alert(alert)
    monkeypatch.setattr(
        "sentinel.action.load_precious_worktrees",
        lambda: ["/home/user/Work/prod"],
    )
    executed: list[list[int]] = []
    monkeypatch.setattr("sentinel.action.plan_kill", lambda *a, **k: [100, 101])
    monkeypatch.setattr(
        "sentinel.action.execute_kill",
        lambda pids, **k: executed.append(list(pids)),
    )
    # The real terminal running the menu has no tty from pytest's point of
    # view unless we say so — confirm it refuses without one.
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = cmd_menu(alert.id, isatty=True, prompt=lambda _: "6")
    assert rc == 1
    assert executed == []
    assert list(iter_alerts())[0].status == "open"


def test_approve_many_ids_in_one_call(monkeypatch, tmp_path):
    """The panel's "approve checked" sends every id at once so the allowlist and
    the alert log are each rewritten once, not once per alert."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alerts = [_alert(cwd=f"/home/user/Work/p{i}") for i in range(3)]
    for a in alerts:
        append_alert(a)
    ids = [a.id for a in alerts]
    assert action_main(["approve", *ids, "--scope", "this-repo"]) == 0
    assert [a.status for a in iter_alerts()] == ["approved"] * 3


def test_approve_all_targets_only_open_alerts(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    keep = _alert(cwd="/home/user/Work/kept")
    keep.status = "dismissed"
    append_alert(keep)
    live = [_alert(cwd=f"/home/user/Work/a{i}") for i in range(2)]
    for a in live:
        append_alert(a)
    assert action_main(["approve", "--all", "--scope", "this-repo"]) == 0
    by_id = {a.id: a.status for a in iter_alerts()}
    assert by_id[keep.id] == "dismissed"  # already closed, left alone
    assert all(by_id[a.id] == "approved" for a in live)


def test_dismiss_all_closes_every_open_alert(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alerts = [_alert(cwd=f"/home/user/Work/d{i}") for i in range(3)]
    for a in alerts:
        append_alert(a)
    assert action_main(["dismiss", "--all"]) == 0
    assert [a.status for a in iter_alerts()] == ["dismissed"] * 3


def test_bulk_approve_is_atomic_on_unknown_id(monkeypatch, tmp_path, capsys):
    """One bad id must fail the whole batch before anything is written, rather
    than approving half the selection and leaving the rest open."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    good = _alert()
    append_alert(good)
    assert action_main(["approve", good.id, "does-not-exist"]) == 1
    assert "unknown alert: does-not-exist" in capsys.readouterr().err
    assert [a.status for a in iter_alerts()] == ["open"]


def test_bulk_on_empty_selection_is_not_an_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    closed = _alert()
    closed.status = "approved"
    append_alert(closed)
    assert action_main(["dismiss", "--all"]) == 0
    assert "no open alerts" in capsys.readouterr().out
    assert action_main(["approve"]) == 2
    assert "no alert id given" in capsys.readouterr().err
