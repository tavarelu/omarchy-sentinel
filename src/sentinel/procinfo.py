# SPDX-License-Identifier: Apache-2.0
"""Process identity from /proc, metadata only.

A PID is recycled; a (pid, starttime) pair is not. starttime is field 22 of
/proc/<pid>/stat, in clock ticks since boot, and it never changes for the life
of the process (verified on Linux 7.1, `man 5 proc`).
"""

from __future__ import annotations

from pathlib import Path


def _stat_fields(pid: int, proc_root: str | Path = "/proc") -> list[str] | None:
    try:
        raw = (Path(proc_root) / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    end = raw.rfind(")")
    if end < 0:
        return None
    # Fields after the comm; comm itself may contain spaces and parentheses.
    return raw[end + 2 :].split()


def read_starttime(pid: int, proc_root: str | Path = "/proc") -> int | None:
    fields = _stat_fields(pid, proc_root)
    if fields is None or len(fields) < 20:
        return None
    try:
        return int(fields[19])  # field 22
    except ValueError:
        return None


def read_ppid(pid: int, proc_root: str | Path = "/proc") -> int | None:
    fields = _stat_fields(pid, proc_root)
    if fields is None or len(fields) < 2:
        return None
    try:
        return int(fields[1])  # field 4
    except ValueError:
        return None


def instance_key(pid: int, starttime: int | None) -> str:
    return f"{int(pid)}:{'?' if starttime is None else int(starttime)}"
