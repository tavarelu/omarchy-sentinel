# SPDX-License-Identifier: Apache-2.0
"""State ledger and CLI-announce channel for W3-07 tamper evidence.

StateLedger tells the daemon whether a write to one of its own operational
files was made by Sentinel itself (recorded directly, or announced by a
sibling `sentinel-*` process and confirmed by a matching sha256) or by
something else ("foreign"). The control socket is a narrow attack surface by
design: it accepts only `{"path": ..., "sha256": ...}` announcements, nothing
that changes daemon behaviour (no pause/dismiss/approve/reload), and every
datagram is received with SO_PASSCRED so the sender pid is known and mirrored
to the journal. A process that forges a correct announcement (matching hash)
defeats the 'ours' classification -- that is tamper evidence via the journal
sender pid, not prevention, which is a stated non-goal.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.fsutil import FILE_MODE, ensure_private_dir, open_private
from sentinel.journal import mirror_event
from sentinel.paths import state_dir

CONTROL_SOCK_NAME = "control.sock"
NONCE_FILENAME = ".cli-writes"
IGNORED_STATE_NAMES = frozenset(
    {
        "alerts.lock",
        "alerts.jsonl.1",
        CONTROL_SOCK_NAME,
        NONCE_FILENAME,
    }
)
_ANNOUNCE_TIMEOUT = 0.2
_RECV_BUFSIZE = 65536
_ANCILLARY_SIZE = socket.CMSG_SPACE(struct.calcsize("3i"))


def is_ignored_state_file(path: Path | str) -> bool:
    """True for transient files in state_dir that Sentinel itself manages and
    which must never be classified through the state ledger or evaluate_write:
    temporary staging files (.tmp), locks, rotated logs, and sockets/nonces."""
    p = Path(path)
    name = p.name
    if name.endswith(".tmp"):
        return True
    if name in IGNORED_STATE_NAMES:
        return True
    return False


def control_socket_path() -> Path:
    return state_dir() / CONTROL_SOCK_NAME


def cli_writes_nonce_path() -> Path:
    return state_dir() / NONCE_FILENAME


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str | None:
    try:
        return sha256_bytes(Path(path).read_bytes())
    except OSError:
        return None


def _path_inside_state_dir(path: Path) -> bool:
    try:
        path.resolve().relative_to(state_dir().resolve())
        return True
    except (ValueError, OSError):
        return False


def _valid_announce_obj(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and set(obj.keys()) == {"path", "sha256"}
        and isinstance(obj.get("path"), str)
        and isinstance(obj.get("sha256"), str)
    )


@dataclass(frozen=True)
class _Fingerprint:
    size: int
    mtime_ns: int
    sha256: str


class StateLedger:
    """Tracks (size, mtime_ns, sha256) of paths Sentinel itself last wrote, plus
    pending CLI announcements. `check(path)` classifies the path's *current*
    on-disk content against that memory."""

    def __init__(self) -> None:
        self._records: dict[str, _Fingerprint] = {}
        self._announced: dict[str, str] = {}
        self.dropped = 0

    def _fingerprint(self, path: Path) -> _Fingerprint | None:
        try:
            st = path.stat()
            data = path.read_bytes()
        except OSError:
            return None
        return _Fingerprint(size=st.st_size, mtime_ns=st.st_mtime_ns, sha256=sha256_bytes(data))

    def record(self, path: Path | str) -> None:
        """The daemon calls this right after every write it makes itself."""
        path = Path(path)
        key = str(path)
        fp = self._fingerprint(path)
        if fp is None:
            self._records.pop(key, None)
        else:
            self._records[key] = fp
        # A direct record from the daemon supersedes any stale pending announce.
        self._announced.pop(key, None)

    def last_size(self, path: Path | str) -> int | None:
        rec = self._records.get(str(Path(path)))
        return rec.size if rec is not None else None

    def announce(self, path: Path | str, sha256: str) -> None:
        """Sent by a CLI process before and after its own write."""
        self._announced[str(Path(path))] = str(sha256)

    def check(self, path: Path | str) -> str:
        """'unchanged' | 'ours' | 'foreign' for the path's current content."""
        path = Path(path)
        key = str(path)
        fp = self._fingerprint(path)
        if fp is None:
            # Nothing on disk right now; deletion detection is out of scope.
            return "unchanged"
        rec = self._records.get(key)
        if rec is not None and rec.size == fp.size and rec.sha256 == fp.sha256:
            return "unchanged"
        announced = self._announced.get(key)
        if announced is not None and announced == fp.sha256:
            return "ours"
        return "foreign"


# ------------------------------------------------------------- CLI side


def announce_write(path: Path | str, sha256: str, *, timeout: float = _ANNOUNCE_TIMEOUT) -> None:
    """CLI-side: tell the daemon `path`'s next observed content will be `sha256`.
    Falls back to a nonce file the daemon consumes at startup when the socket
    is absent (daemon not running). Never raises."""
    payload = json.dumps(
        {"path": str(path), "sha256": str(sha256)}, separators=(",", ":")
    ).encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, str(control_socket_path()))
        return
    except OSError:
        pass
    try:
        _append_nonce(path, sha256)
    except OSError:
        return


def _append_nonce(path: Path | str, sha256: str) -> None:
    line = json.dumps({"path": str(path), "sha256": str(sha256)}, separators=(",", ":")) + "\n"
    with open_private(cli_writes_nonce_path(), "a") as f:
        f.write(line)


def consume_cli_writes(ledger: StateLedger) -> None:
    """Daemon startup: apply pending nonce-file announcements, then clear it."""
    path = cli_writes_nonce_path()
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not _valid_announce_obj(obj):
            continue
        p = Path(obj["path"])
        if not _path_inside_state_dir(p):
            continue
        ledger.announce(p, obj["sha256"])
    try:
        path.unlink()
    except OSError:
        pass


# ------------------------------------------------------------- daemon side


def create_control_socket() -> socket.socket | None:
    """AF_UNIX/SOCK_DGRAM, mode 0600, SO_PASSCRED, non-blocking. None on any
    failure (never a hard requirement for the daemon to run)."""
    try:
        ensure_private_dir(state_dir())
        path = control_socket_path()
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(str(path))
        os.chmod(path, FILE_MODE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        sock.setblocking(False)
        return sock
    except OSError:
        return None


def drain_control_socket(
    sock: socket.socket,
    ledger: StateLedger,
    *,
    on_announce: Callable[[Path, int | None], None] | None = None,
) -> None:
    """Non-blocking: apply every pending datagram. Only `{"path":...,
    "sha256":...}` announcements for a path inside state_dir() are accepted;
    anything else is dropped and counted (ledger.dropped)."""
    while True:
        try:
            data, ancdata, _flags, _addr = sock.recvmsg(_RECV_BUFSIZE, _ANCILLARY_SIZE)
        except BlockingIOError:
            return
        except OSError:
            return
        sender_pid: int | None = None
        for level, cmsg_type, cmsg_data in ancdata:
            if level == socket.SOL_SOCKET and cmsg_type == socket.SCM_CREDENTIALS:
                try:
                    pid, _uid, _gid = struct.unpack("3i", cmsg_data[: struct.calcsize("3i")])
                    sender_pid = pid
                except struct.error:
                    sender_pid = None
        try:
            obj = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            ledger.dropped += 1
            continue
        if not _valid_announce_obj(obj):
            ledger.dropped += 1
            continue
        p = Path(obj["path"])
        if not _path_inside_state_dir(p):
            ledger.dropped += 1
            continue
        ledger.announce(p, obj["sha256"])
        try:
            mirror_event(
                {
                    "SYSLOG_IDENTIFIER": "sentinel",
                    "SENTINEL_EVENT": "cli-announce",
                    "SENTINEL_SENDER_PID": str(sender_pid) if sender_pid is not None else "",
                    "SENTINEL_PATH": str(p),
                    "MESSAGE": f"cli announce: {p}",
                }
            )
        except Exception:
            pass
        if on_announce is not None:
            on_announce(p, sender_pid)
