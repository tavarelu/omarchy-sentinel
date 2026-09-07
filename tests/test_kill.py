import signal
from pathlib import Path

import pytest

from sentinel.kill import (
    confirm_kill,
    cwd_is_precious,
    execute_kill,
    plan_kill,
    session_kill_requires_confirm,
)


def test_kill_refuses_foreign_uid(monkeypatch):
    from sentinel.kill import plan_kill

    monkeypatch.setattr("os.getuid", lambda: 1000)

    def get_uid(pid: int) -> int:
        return 0

    with pytest.raises(PermissionError):
        plan_kill(
            alert_pids=[100, 101],
            child_pids=[101],
            mode="child",
            get_uid=get_uid,
        )


def test_default_targets_child_not_supervisor():
    plan = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        mode="child",
        get_uid=lambda pid: None,
    )
    assert plan == [101]


def test_session_targets_all_alert_pids():
    plan = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        mode="session",
        get_uid=lambda pid: None,
    )
    assert plan == [100, 101]


def test_plan_kill_allows_own_uid():
    plan = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        mode="child",
        get_uid=lambda pid: 1000,
        uid=1000,
    )
    assert plan == [101]


def test_plan_kill_exited_pid_is_kept():
    plan = plan_kill(
        alert_pids=[101],
        child_pids=[101],
        mode="child",
        get_uid=lambda pid: None,
        uid=1000,
    )
    assert plan == [101]


def test_plan_kill_refuses_if_any_target_is_foreign():
    def get_uid(pid: int) -> int:
        return 1000 if pid == 101 else 0

    with pytest.raises(PermissionError):
        plan_kill(
            alert_pids=[100, 101],
            child_pids=[101],
            mode="session",
            get_uid=get_uid,
            uid=1000,
        )


def test_execute_kill_sigterm_then_sigkill_survivors():
    signals: list[tuple[int, int]] = []
    alive = {101: True}

    def kill_fn(pid: int, sig: int) -> None:
        signals.append((pid, sig))
        if sig == signal.SIGKILL:
            alive[pid] = False

    sleeps: list[float] = []
    execute_kill(
        [101],
        kill=kill_fn,
        sleep=lambda s: sleeps.append(s),
        alive=lambda pid: alive.get(pid, False),
    )
    assert signals[0] == (101, signal.SIGTERM)
    assert sleeps == [3.0]
    assert signals[1] == (101, signal.SIGKILL)


def test_execute_kill_skips_sigkill_if_term_reaped():
    signals: list[tuple[int, int]] = []

    def kill_fn(pid: int, sig: int) -> None:
        signals.append((pid, sig))

    execute_kill(
        [5],
        kill=kill_fn,
        sleep=lambda s: None,
        alive=lambda pid: False,
    )
    assert signals == [(5, signal.SIGTERM)]


def test_execute_kill_exited_pid_is_success():
    def kill_fn(pid: int, sig: int) -> None:
        raise ProcessLookupError()

    result = execute_kill(
        [99],
        kill=kill_fn,
        sleep=lambda s: None,
        alive=lambda pid: False,
    )
    assert result == [99]


def test_plan_kill_default_mode_is_child():
    plan = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        get_uid=lambda pid: None,
    )
    assert plan == [101]


def test_cwd_is_precious_matches_prefix_and_nested():
    prefixes = ["/home/user/Work/prod"]
    assert cwd_is_precious("/home/user/Work/prod", prefixes)
    assert cwd_is_precious("/home/user/Work/prod/src", prefixes)
    assert not cwd_is_precious("/home/user/Work/scratch", prefixes)
    assert not cwd_is_precious("/home/user/Work/prod2", prefixes)
    assert not cwd_is_precious("/home/user/Work/prod", [])
    assert not cwd_is_precious("", prefixes)


def test_session_kill_requires_confirm_on_precious_prefix():
    prefixes = ["/home/user/Work/prod"]
    assert session_kill_requires_confirm("/home/user/Work/prod/app", prefixes)
    assert not session_kill_requires_confirm("/home/user/Work/scratch", prefixes)
    assert not session_kill_requires_confirm("/home/user/Work/prod", [])


def test_confirm_kill_session_precious_needs_typed_phrase():
    assert (
        confirm_kill(
            yes=True,
            session=True,
            precious=True,
            isatty=False,
        )
        is False
    )
    assert (
        confirm_kill(
            yes=True,
            session=True,
            precious=True,
            isatty=True,
            prompt=lambda _: "kill session",
        )
        is True
    )
    assert (
        confirm_kill(
            yes=True,
            session=True,
            precious=True,
            isatty=True,
            prompt=lambda _: "no",
        )
        is False
    )


def test_confirm_kill_yes_enough_for_child_or_non_precious_session():
    assert confirm_kill(yes=True, session=False, precious=True) is True
    assert confirm_kill(yes=True, session=True, precious=False) is True


def test_config_template_precious_worktrees_empty():
    import tomllib

    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "packaging" / "config.toml").read_text(encoding="utf-8"))
    section = data.get("kill", data)
    assert section.get("precious_worktrees") == []


def test_plan_kill_skips_recycled_pid():
    warned: list[str] = []
    plan = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        mode="child",
        get_uid=lambda pid: None,
        expected_starttime={101: 500},
        get_starttime=lambda pid: 900,
        warn=warned.append,
    )
    assert plan == []
    assert warned and "recycled" in warned[0]


def test_plan_kill_keeps_matching_or_unknown_starttime():
    plan = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        mode="child",
        get_uid=lambda pid: None,
        expected_starttime={101: 500},
        get_starttime=lambda pid: 500,
        warn=lambda m: None,
    )
    assert plan == [101]
    plan2 = plan_kill(
        alert_pids=[100, 101],
        child_pids=[101],
        mode="child",
        get_uid=lambda pid: None,
        expected_starttime={101: 500},
        get_starttime=lambda pid: None,  # process already gone
        warn=lambda m: None,
    )
    assert plan2 == [101]
