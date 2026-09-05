# SPDX-License-Identifier: Apache-2.0
"""Private files and directories for Sentinel state.

Alert logs carry agent command lines and project paths, so nothing Sentinel
writes is readable by other users (security review S3): directories 0700,
files 0600, rewrites atomic.
"""

from __future__ import annotations

import os
import stat as _stat
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    try:
        if _stat.S_IMODE(path.stat().st_mode) != DIR_MODE:
            os.chmod(path, DIR_MODE)
    except OSError:
        pass
    return path


def open_private(path: Path, mode: str = "a"):
    """Open for append ('a') or truncate ('w'), creating with 0600."""
    path = Path(path)
    ensure_private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC)
    fd = os.open(path, flags, FILE_MODE)
    try:
        if _stat.S_IMODE(os.fstat(fd).st_mode) != FILE_MODE:
            os.fchmod(fd, FILE_MODE)
    except OSError:
        pass
    return os.fdopen(fd, "a" if mode == "a" else "w", encoding="utf-8")


def write_private_atomic(path: Path, text: str) -> None:
    """Write text to a 0600 temp file beside path and rename it into place."""
    path = Path(path)
    ensure_private_dir(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
