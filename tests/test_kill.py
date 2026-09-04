import signal

import pytest

from sentinel.kill import execute_kill, plan_kill


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
