# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.fsutil import open_private
from sentinel.models import Alert
from sentinel.paths import state_dir
from sentinel.procinfo import instance_key, read_starttime
from sentinel.rules import evaluate_process, extract_bypass_flags

LAUNCHES_FILENAME = "launches.jsonl"


def launches_path() -> Path:
    return state_dir() / LAUNCHES_FILENAME


def record_launch(
    basename: str,
    argv: list[str],
    *,
    exe: str | None = None,
    cwd: str | None = None,
    pid: int | None = None,
    ppid: int | None = None,
    extra_bypass_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Append one launch record to state_dir()/launches.jsonl and return it."""
    cmdline = [basename, *argv]
    flags = extract_bypass_flags(cmdline, extra_bypass_flags)
    real_pid = pid if pid is not None else os.getpid()
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "basename": basename,
        "cmdline": cmdline,
        "cwd": cwd if cwd is not None else os.getcwd(),
        "exe": exe or "",
        "pid": pid if pid is not None else os.getpid(),
        "ppid": ppid if ppid is not None else os.getppid(),
        "flags": flags,
        # The wrapper shell execs into the agent, so its pid and start time
        # survive the exec and identify the agent process instance.
        "starttime": read_starttime(real_pid),
    }
    with open_private(launches_path(), "a") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")
    return record


def launch_to_alert(
    record: dict[str, Any],
    *,
    extra_bypass_flags: list[str] | None = None,
) -> Alert | None:
    """Convert a launches.jsonl record into an Alert via evaluate_process."""
    cmdline = list(record.get("cmdline") or [])
    basename = record.get("basename") or (cmdline[0] if cmdline else "")
    exe = record.get("exe") or basename
    cwd = record.get("cwd") or ""
    alert = evaluate_process(
        cmdline,
        exe,
        cwd,
        extra_bypass_flags=extra_bypass_flags,
    )
    if alert is None:
        return None
    pid = record.get("pid")
    if pid is not None:
        alert.pids = [int(pid)]
        starttime = record.get("starttime")
        alert.evidence["starttime"] = starttime
        alert.evidence["instance"] = instance_key(int(pid), starttime)
    alert.evidence["source"] = "launches"
    if record.get("ts"):
        alert.evidence["launch_ts"] = record["ts"]
    return alert


def main(argv: list[str] | None = None) -> int:
    """CLI: python -m sentinel.wrap_record <basename> [--] <args...>

    Optional env:
      SENTINEL_LAUNCH_PID — wrapper shell PID (survives exec into the real binary)
      SENTINEL_LAUNCH_PPID — parent of the wrapper shell ($PPID)
      SENTINEL_REAL_<NAME> — real executable path recorded as exe
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(
            "usage: python -m sentinel.wrap_record <basename> [--] <args...>",
            file=sys.stderr,
        )
        return 2
    basename = args.pop(0)
    if args and args[0] == "--":
        args.pop(0)
    exe = os.environ.get(f"SENTINEL_REAL_{_env_name(basename)}", "")
    pid = _env_int("SENTINEL_LAUNCH_PID")
    ppid = _env_int("SENTINEL_LAUNCH_PPID")
    record_launch(basename, args, exe=exe or None, pid=pid, ppid=ppid)
    return 0


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _env_name(basename: str) -> str:
    return basename.upper().replace("-", "_")


if __name__ == "__main__":
    raise SystemExit(main())
