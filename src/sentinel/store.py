# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sentinel.fsutil import ensure_private_dir, open_private, write_private_atomic
from sentinel.models import STATUSES, Alert
from sentinel.paths import state_dir

ALERTS_FILENAME = "alerts.jsonl"
LOCK_FILENAME = "alerts.lock"
ROTATED_FILENAME = "alerts.jsonl.1"
MAX_ROWS = 5000
MAX_BYTES = 5_000_000


def _alerts_path() -> Path:
    return state_dir() / ALERTS_FILENAME


@contextmanager
def _locked():
    """One writer at a time across the daemon and every sentinel-action process."""
    ensure_private_dir(state_dir())
    fd = os.open(state_dir() / LOCK_FILENAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _row_count(path: Path) -> int:
    n = 0
    with path.open("rb") as f:
        for _ in f:
            n += 1
    return n


def rotate_if_needed(max_rows: int | None = None, max_bytes: int | None = None) -> bool:
    """Move the live log aside when it is too big. Call with the lock held."""
    max_rows = MAX_ROWS if max_rows is None else max_rows
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
    path = _alerts_path()
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return False
    rotate = size >= max_bytes
    if not rotate and size >= max_rows * 64 and _row_count(path) >= max_rows:
        rotate = True
    if not rotate:
        return False
    os.replace(path, path.with_name(ROTATED_FILENAME))
    return True


def append_alert(alert: Alert) -> None:
    with _locked():
        rotate_if_needed()
        with open_private(_alerts_path(), "a") as f:
            f.write(json.dumps(alert.to_dict(), separators=(",", ":")) + "\n")


def iter_alerts() -> Iterator[Alert]:
    path = _alerts_path()
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield Alert.from_dict(json.loads(line))
            except (json.JSONDecodeError, KeyError, TypeError):
                # A torn line during a concurrent append; the writer holds the
                # lock, so the next read sees it whole.
                continue


def update_alert_status(id: str, status: str) -> None:
    if status not in STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    path = _alerts_path()
    with _locked():
        if not path.exists():
            raise KeyError(id)
        rows = list(iter_alerts())
        found = False
        for alert in rows:
            if alert.id == id:
                alert.status = status
                found = True
        if not found:
            raise KeyError(id)
        text = "".join(json.dumps(a.to_dict(), separators=(",", ":")) + "\n" for a in rows)
        write_private_atomic(path, text)
