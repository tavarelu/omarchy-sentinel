# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

STATUSES = frozenset({"open", "approved", "killed", "investigated", "dismissed"})


@dataclass
class Alert:
    id: str
    ts: str
    rule: str
    severity: str
    summary: str
    pids: list[int]
    exe: str
    basename: str
    cmdline: list[str]
    cwd: str
    evidence: dict[str, Any]
    status: str = "open"
    parent: dict[str, Any] | None = None
    paths: list[str] | None = None
    writer_pid: int | None = None
    hashes: dict[str, str] | None = None

    @classmethod
    def new(
        cls,
        *,
        rule: str,
        severity: str,
        summary: str,
        pids: list[int],
        exe: str,
        basename: str,
        cmdline: list[str],
        cwd: str,
        evidence: dict[str, Any],
        parent: dict[str, Any] | None = None,
        paths: list[str] | None = None,
        writer_pid: int | None = None,
        hashes: dict[str, str] | None = None,
        status: str = "open",
    ) -> Alert:
        if status not in STATUSES:
            raise ValueError(f"invalid status: {status!r}")
        return cls(
            id=str(uuid4()),
            ts=datetime.now(timezone.utc).isoformat(),
            rule=rule,
            severity=severity,
            summary=summary,
            pids=list(pids),
            exe=exe,
            basename=basename,
            cmdline=list(cmdline),
            cwd=cwd,
            evidence=dict(evidence),
            status=status,
            parent=parent,
            paths=list(paths) if paths is not None else None,
            writer_pid=writer_pid,
            hashes=dict(hashes) if hashes is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        return cls(
            id=data["id"],
            ts=data["ts"],
            rule=data["rule"],
            severity=data["severity"],
            summary=data["summary"],
            pids=list(data["pids"]),
            exe=data["exe"],
            basename=data["basename"],
            cmdline=list(data["cmdline"]),
            cwd=data["cwd"],
            evidence=dict(data.get("evidence") or {}),
            status=data.get("status", "open"),
            parent=data.get("parent"),
            paths=data.get("paths"),
            writer_pid=data.get("writer_pid"),
            hashes=data.get("hashes"),
        )
