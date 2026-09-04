from __future__ import annotations

import errno
import os
import signal
import time
from collections.abc import Callable, Sequence

TERM_WAIT_SEC = 3.0


def pid_uid(pid: int) -> int | None:
    """Return the uid of a live pid, or None if it has already exited."""
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except FileNotFoundError:
        return None
    except OSError as e:
        raise PermissionError(f"cannot verify owner of pid {pid}") from e


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        raise
    return True


def plan_kill(
    alert_pids: Sequence[int],
    child_pids: Sequence[int] | None = None,
    mode: str = "child",
    *,
    get_uid: Callable[[int], int | None] | None = None,
    uid: int | None = None,
) -> list[int]:
    """Return the PID list for a narrow kill. Refuse any live non-owned pid."""
    if mode not in {"child", "session"}:
        raise ValueError(f"invalid kill mode: {mode!r}")
    if mode == "child":
        wanted = [int(p) for p in (child_pids or ())]
        allowed = {int(p) for p in alert_pids}
        targets = [p for p in wanted if p in allowed] if allowed else wanted
    else:
        targets = [int(p) for p in alert_pids]
    ordered: list[int] = []
    seen: set[int] = set()
    for pid in targets:
        if pid in seen:
            continue
        seen.add(pid)
        ordered.append(pid)
    me = os.getuid() if uid is None else uid
    lookup = get_uid if get_uid is not None else pid_uid
    foreign: list[int] = []
    for pid in ordered:
        owner = lookup(pid)
        if owner is not None and int(owner) != int(me):
            foreign.append(pid)
    if foreign:
        raise PermissionError(
            "refuse kill of non-owned pid(s): " + ", ".join(str(p) for p in foreign)
        )
    return ordered


def execute_kill(
    pids: Sequence[int],
    *,
    wait_sec: float = TERM_WAIT_SEC,
    kill: Callable[[int, int], None] | None = None,
    sleep: Callable[[float], None] | None = None,
    alive: Callable[[int], bool] | None = None,
) -> list[int]:
    """SIGTERM each pid, wait, SIGKILL survivors. Already-exited pids succeed."""
    kill_fn = os.kill if kill is None else kill
    sleep_fn = time.sleep if sleep is None else sleep
    alive_fn = pid_alive if alive is None else alive
    target = [int(p) for p in pids]

    def _signal(pid: int, sig: int) -> None:
        try:
            kill_fn(pid, sig)
        except ProcessLookupError:
            return
        except OSError as e:
            if e.errno == errno.ESRCH:
                return
            raise

    for pid in target:
        _signal(pid, signal.SIGTERM)
    sleep_fn(wait_sec)
    for pid in target:
        if not alive_fn(pid):
            continue
        _signal(pid, signal.SIGKILL)
    return target
