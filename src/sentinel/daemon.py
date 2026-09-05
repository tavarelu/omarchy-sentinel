# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ctypes
import json
import os
import select
import struct
import time
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from datetime import datetime, timezone

from sentinel.allowlist import clear_session, decide, fingerprint, load_all, remove
from sentinel.keys import alert_flag_set, alert_location, candidate_prefixes
from sentinel.models import Alert
from sentinel.paths import config_dir, default_config_path, state_dir
from sentinel.rules import evaluate_process, evaluate_write
from sentinel.scout import WATCHLIST_FILENAME, scout, write_watchlist
from sentinel.store import append_alert
from sentinel.wrap_record import LAUNCHES_FILENAME, launch_to_alert, launches_path

SAMPLER_MIN = 2.0
SAMPLER_MAX = 5.0
DEFAULT_SAMPLER_INTERVAL = 3.0
DEFAULT_COALESCE_WINDOW = 60.0

DEFAULT_AGENT_BASENAMES: frozenset[str] = frozenset(
    {
        "claude",
        "codex",
        "cursor",
        "cursor-agent",
        "grok",
    }
)

WATCH_KINDS = frozenset({"hooks", "settings", "mcp", "auth"})
OPERATIONAL_NAMES = frozenset(
    {
        "alerts.jsonl",
        "launches.jsonl",
        "health.json",
        "allowlist.json",
        "allowlist-session.json",
        "watchlist.json",
    }
)
_DELETED_SUFFIX = " (deleted)"

# inotify_init1 flags share values with open(2).
IN_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0x80000))
IN_NONBLOCK = int(getattr(os, "O_NONBLOCK", 0x800))
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

WATCH_MASK = (
    IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

_EVENT_HDR = struct.Struct("iIII")
_LIBC: ctypes.CDLL | None = None


def _clamp_interval(value: float) -> float:
    return min(SAMPLER_MAX, max(SAMPLER_MIN, float(value)))


def _libc() -> ctypes.CDLL:
    global _LIBC
    if _LIBC is None:
        lib = ctypes.CDLL(None, use_errno=True)
        lib.inotify_init1.argtypes = [ctypes.c_int]
        lib.inotify_init1.restype = ctypes.c_int
        lib.inotify_add_watch.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        lib.inotify_add_watch.restype = ctypes.c_int
        _LIBC = lib
    return _LIBC


def _oserror(path: str | None = None) -> OSError:
    err = ctypes.get_errno()
    return OSError(err, os.strerror(err), path)


class Coalescer:
    """Suppress duplicate alert keys inside a sliding window."""

    def __init__(
        self,
        window_sec: float = DEFAULT_COALESCE_WINDOW,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.window_sec = float(window_sec)
        self._clock = clock
        self._last: dict[str, float] = {}

    def should_emit(self, key: str) -> bool:
        now = self._clock()
        prev = self._last.get(key)
        if prev is not None and (now - prev) < self.window_sec:
            return False
        if len(self._last) > 256:
            cutoff = now - self.window_sec
            self._last = {k: t for k, t in self._last.items() if t > cutoff}
        self._last[key] = now
        return True


@dataclass(frozen=True)
class InotifyEvent:
    wd: int
    mask: int
    cookie: int
    name: str


class Inotify:
    """Thin libc inotify wrapper (stdlib ctypes, no extra deps)."""

    def __init__(self) -> None:
        fd = _libc().inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if fd < 0:
            raise _oserror()
        self.fd = fd
        self.wd_to_path: dict[int, Path] = {}

    def add_watch(self, path: Path | str, mask: int = WATCH_MASK) -> int:
        path = Path(path)
        wd = _libc().inotify_add_watch(self.fd, os.fsencode(str(path)), mask)
        if wd < 0:
            raise _oserror(str(path))
        self.wd_to_path[wd] = path
        return wd

    def read_events(self) -> list[InotifyEvent]:
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        events: list[InotifyEvent] = []
        offset = 0
        hdr_size = _EVENT_HDR.size
        while offset + hdr_size <= len(data):
            wd, mask, cookie, name_len = _EVENT_HDR.unpack_from(data, offset)
            end = offset + hdr_size + name_len
            if end > len(data):
                break
            name = ""
            if name_len:
                raw = data[offset + hdr_size : end]
                name = raw.split(b"\x00", 1)[0].decode("utf-8", "surrogateescape")
            events.append(InotifyEvent(wd=wd, mask=mask, cookie=cookie, name=name))
            offset = end
        return events

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        self.wd_to_path.clear()


def watch_roots_from_entries(entries: Iterable[Mapping[str, Any]]) -> list[Path]:
    """Watch listed hooks/settings/mcp/auth files plus hook parent dirs."""
    roots: list[Path] = []
    seen: set[Path] = set()
    for entry in entries:
        kind = entry.get("kind")
        if kind not in WATCH_KINDS:
            continue
        path = Path(entry["path"])
        if path not in seen:
            seen.add(path)
            roots.append(path)
        if kind == "hooks":
            parent = path.parent
            if parent not in seen:
                seen.add(parent)
                roots.append(parent)
    return roots


def refresh_watchlist(home: Path | None = None) -> Path:
    result = scout(Path(home) if home is not None else Path.home())
    return write_watchlist(result)


def load_config(
    path: Path | None = None,
    *,
    defaults: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "sampler_interval": DEFAULT_SAMPLER_INTERVAL,
        "coalesce_window": DEFAULT_COALESCE_WINDOW,
        "extra_bypass_flags": [],
        "known_basenames": sorted(DEFAULT_AGENT_BASENAMES),
        "inotify": True,
    }
    if defaults:
        cfg.update(dict(defaults))
    cfg_path = path
    if cfg_path is None and defaults is None:
        candidate = default_config_path()
        if candidate.is_file():
            cfg_path = candidate
    if cfg_path is not None and Path(cfg_path).is_file():
        with Path(cfg_path).open("rb") as f:
            data = tomllib.load(f)
        section = data.get("daemon", data)
        if isinstance(section, dict):
            for key in (
                "sampler_interval",
                "coalesce_window",
                "extra_bypass_flags",
                "known_basenames",
            ):
                if key in section:
                    cfg[key] = section[key]
    cfg["sampler_interval"] = _clamp_interval(
        cfg.get("sampler_interval", DEFAULT_SAMPLER_INTERVAL)
    )
    cfg["coalesce_window"] = float(
        cfg.get("coalesce_window", DEFAULT_COALESCE_WINDOW)
    )
    return cfg


def coalesce_key(alert: Alert) -> str:
    loc = alert.cwd or (alert.paths[0] if alert.paths else "")
    return f"{alert.rule}|{alert.basename}|{loc}"


def _allow_decision(alert: Alert, now: datetime | None = None) -> tuple[str, str]:
    """(allowed|expired|none, fingerprint) with the allowlist files read once.

    Tests the global prefix first, then the location and each parent, so an
    approval keyed by sentinel-action (see keys.approval_prefix) always matches.
    """
    when = now if now is not None else datetime.now(timezone.utc)
    flags = alert_flag_set(alert)
    location = alert_location(alert)
    session, persisted = load_all()
    expired_fp: str | None = None
    for prefix in candidate_prefixes(location):
        fp = fingerprint(alert.rule, alert.basename, flags, prefix)
        verdict = decide(session, persisted, fp, location, when)
        if verdict == "allowed":
            return "allowed", fp
        if verdict == "expired" and expired_fp is None:
            expired_fp = fp
    if expired_fp is not None:
        return "expired", expired_fp
    return "none", ""


def _is_alert_allowed(alert: Alert, now: datetime | None = None) -> bool:
    return _allow_decision(alert, now)[0] == "allowed"


def expired_alert(alert: Alert, fp: str) -> Alert:
    """Spec section 8: an expired approval that recurs is R-ALLOW-EXPIRE (low), not a new panic."""
    return Alert.new(
        rule="R-ALLOW-EXPIRE",
        severity="low",
        summary=f"{alert.basename or alert.rule} approval expired; pattern recurred",
        pids=list(alert.pids),
        exe=alert.exe,
        basename=alert.basename,
        cmdline=list(alert.cmdline),
        cwd=alert.cwd,
        evidence={
            "expired_scope": "24h",
            "fingerprint": fp,
            "original_rule": alert.rule,
            **({"flags": sorted(alert_flag_set(alert))} if alert_flag_set(alert) else {}),
        },
        parent=alert.parent,
        paths=alert.paths,
        writer_pid=alert.writer_pid,
        hashes=alert.hashes,
    )


def _exe_basename(exe: str) -> str:
    name = Path(exe).name
    if name.endswith(_DELETED_SUFFIX):
        return name[: -len(_DELETED_SUFFIX)]
    return name


def process_name_candidates(
    exe: str,
    cmdline: Sequence[str],
    comm: str = "",
) -> set[str]:
    """exe basename (minus ' (deleted)'), cmdline token basenames, and comm."""
    names: set[str] = set()
    stripped = comm.strip()
    if stripped:
        names.add(stripped)
    if exe:
        names.add(_exe_basename(exe))
    for tok in cmdline:
        base = Path(tok).name
        if base:
            names.add(base)
    return names


def _readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def _read_comm(pid_dir: Path) -> str:
    try:
        return (pid_dir / "comm").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _read_cmdline(pid_dir: Path) -> list[str]:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return []
    if not raw:
        return []
    return [p.decode("utf-8", "surrogateescape") for p in raw.split(b"\0") if p]


class Daemon:
    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        cfg = dict(config or {})
        self.sampler_interval = _clamp_interval(
            cfg.get("sampler_interval", DEFAULT_SAMPLER_INTERVAL)
        )
        window = float(cfg.get("coalesce_window", DEFAULT_COALESCE_WINDOW))
        self._clock = cfg.get("clock", time.monotonic)
        self._wall_clock = cfg.get("wall_clock", lambda: datetime.now(timezone.utc))
        self.coalescer = Coalescer(window_sec=window, clock=self._clock)
        self._extra_flags = list(cfg.get("extra_bypass_flags") or [])
        known = cfg.get("known_basenames")
        self._known = (
            set(known) if known is not None else set(DEFAULT_AGENT_BASENAMES)
        )
        if "notify" in cfg and cfg["notify"] is not None:
            self._notify: Callable[[Alert], None] = cfg["notify"]
        else:
            from sentinel.notify import send_alert

            self._notify = send_alert
        self._stop = cfg.get("stop")
        self._proc_root = Path(cfg.get("proc_root", "/proc"))
        self._home = Path(cfg.get("home", Path.home()))
        self._enable_inotify = bool(cfg.get("inotify", True))
        self._last_sample: float | None = None
        self._watch_override = (
            [Path(p) for p in cfg["watch_paths"]] if "watch_paths" in cfg else None
        )
        self._self_override = (
            [Path(p) for p in cfg["self_paths"]] if "self_paths" in cfg else None
        )
        self._watch_roots: list[Path] = list(self._watch_override or [])
        self._inotify: Inotify | None = None
        # Watch descriptors added for directories that appeared under a watched
        # dir at runtime (Claude Code's history.jsonl.lock is one). They are
        # transient by nature; losing one is not a lost root.
        self._auto_wds: set[int] = set()
        self._self_refresh = False
        path = launches_path()
        try:
            self._launches_offset = path.stat().st_size if path.exists() else 0
        except OSError:
            self._launches_offset = 0

    def _stopped(self) -> bool:
        return self._stop is not None and self._stop.is_set()

    def _self_paths(self) -> list[Path]:
        if self._self_override is not None:
            return list(self._self_override)
        return [config_dir(), state_dir()]

    def _load_watch_paths(self) -> None:
        if self._watch_override is not None:
            self._watch_roots = list(self._watch_override)
            return
        path = state_dir() / WATCHLIST_FILENAME
        if not path.exists():
            self._watch_roots = []
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._watch_roots = []
            return
        self._watch_roots = watch_roots_from_entries(data.get("paths") or [])

    def _ensure_watchlist(self) -> None:
        if self._watch_override is not None:
            self._watch_roots = list(self._watch_override)
            return
        state_dir().mkdir(parents=True, exist_ok=True)
        config_dir().mkdir(parents=True, exist_ok=True)
        if not (state_dir() / WATCHLIST_FILENAME).exists():
            self._self_refresh = True
            try:
                refresh_watchlist(self._home)
            finally:
                self._self_refresh = False
        self._load_watch_paths()

    def _dirs_to_watch(self) -> list[Path]:
        dirs: set[Path] = set()
        if self._self_override is None:
            for path in (config_dir(), state_dir()):
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except OSError:
                    continue
        for raw in [*self._self_paths(), *self._watch_roots]:
            path = Path(raw)
            try:
                if path.is_dir():
                    dirs.add(path.resolve())
                elif path.parent.is_dir():
                    dirs.add(path.parent.resolve())
            except OSError:
                continue
        return sorted(dirs)

    def _close_inotify(self) -> None:
        if self._inotify is not None:
            self._inotify.close()
            self._inotify = None

    def _rebuild_watches(self) -> None:
        self._close_inotify()
        self._auto_wds = set()
        if not self._enable_inotify:
            return
        try:
            self._inotify = Inotify()
        except OSError:
            self._inotify = None
            return
        for directory in self._dirs_to_watch():
            try:
                self._inotify.add_watch(directory)
            except OSError:
                continue

    def emit(self, alert: Alert) -> None:
        decision, fp = _allow_decision(alert, self._wall_clock())
        if decision == "allowed":
            return
        if decision == "expired":
            remove(fp)
            alert = expired_alert(alert, fp)
        if not self.coalescer.should_emit(coalesce_key(alert)):
            return
        append_alert(alert)
        self._notify(alert)

    def handle_write(
        self,
        path: Path,
        writer_pid: int | None = None,
        writer_exe: str | None = None,
        writer_cmdline: Sequence[str] | None = None,
    ) -> None:
        path = Path(path)
        if path.name in OPERATIONAL_NAMES:
            return
        alert = evaluate_write(
            path,
            writer_pid,
            writer_exe,
            self_paths=self._self_paths(),
            watch_paths=self._watch_roots,
            writer_cmdline=writer_cmdline,
        )
        if alert is None:
            return
        self.emit(alert)

    def handle_process(
        self,
        cmdline: list[str],
        exe: str,
        cwd: str,
        pid: int | None = None,
        parent: dict[str, Any] | None = None,
    ) -> None:
        alert = evaluate_process(
            cmdline,
            exe,
            cwd,
            extra_bypass_flags=self._extra_flags,
        )
        if alert is None:
            return
        if pid is not None:
            alert.pids = [int(pid)]
        if parent is not None:
            alert.parent = parent
        self.emit(alert)

    def handle_overflow(self) -> None:
        alert = Alert.new(
            rule="R-SELF",
            severity="medium",
            summary="inotify queue overflow; refreshing watchlist",
            pids=[],
            exe="",
            basename="inotify",
            cmdline=[],
            cwd="",
            evidence={"event": "IN_Q_OVERFLOW"},
        )
        self.emit(alert)
        self._self_refresh = True
        try:
            refresh_watchlist(self._home)
            if self._watch_override is None:
                self._load_watch_paths()
            if self._inotify is not None:
                self._rebuild_watches()
        finally:
            self._self_refresh = False

    def handle_watch_lost(self, path: Path | None = None, mask: int = 0) -> None:
        loc = str(path) if path is not None else ""
        event = "IN_DELETE_SELF" if mask & IN_DELETE_SELF else "IN_MOVE_SELF"
        verb = "deleted" if event == "IN_DELETE_SELF" else "moved"
        alert = Alert.new(
            rule="R-SELF",
            severity="medium",
            summary=f"watched root {verb}; refreshing watchlist",
            pids=[],
            exe="",
            basename="inotify",
            cmdline=[],
            cwd=loc,
            evidence={"event": event, "path": loc},
        )
        self.emit(alert)
        self._self_refresh = True
        try:
            if self._watch_override is None:
                refresh_watchlist(self._home)
                self._load_watch_paths()
            if self._enable_inotify:
                self._rebuild_watches()
        finally:
            self._self_refresh = False

    def consume_launches(self) -> None:
        path = launches_path()
        if not path.exists():
            return
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size < self._launches_offset:
            self._launches_offset = 0
        try:
            with path.open(encoding="utf-8") as f:
                f.seek(self._launches_offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    alert = launch_to_alert(
                        record,
                        extra_bypass_flags=self._extra_flags,
                    )
                    if alert is not None:
                        self.emit(alert)
                self._launches_offset = f.tell()
        except OSError:
            return

    def sample_proc(self) -> None:
        root = self._proc_root
        if not root.is_dir():
            return
        our_pid = os.getpid()
        try:
            pid_dirs = list(root.iterdir())
        except OSError:
            return
        for pid_dir in pid_dirs:
            name = pid_dir.name
            if not name.isdigit():
                continue
            pid = int(name)
            if pid == our_pid:
                continue
            cmdline = _read_cmdline(pid_dir)
            if not cmdline:
                continue
            exe = _readlink(pid_dir / "exe")
            comm = _read_comm(pid_dir)
            if self._known:
                names = process_name_candidates(exe, cmdline, comm)
                if names.isdisjoint(self._known):
                    continue
            cwd = _readlink(pid_dir / "cwd")
            self.handle_process(cmdline, exe or cmdline[0], cwd, pid=pid)

    def maybe_sample(self) -> bool:
        now = self._clock()
        if (
            self._last_sample is not None
            and (now - self._last_sample) < self.sampler_interval
        ):
            return False
        self.consume_launches()
        self.sample_proc()
        self._last_sample = now
        return True

    def _sample_timeout(self) -> float:
        if self._last_sample is None:
            return 0.0
        remaining = self.sampler_interval - (self._clock() - self._last_sample)
        return max(0.0, remaining)

    def tick(self) -> None:
        self.maybe_sample()

    def _on_fs_event(self, path: Path, mask: int) -> None:
        if path.name == LAUNCHES_FILENAME:
            self.consume_launches()
            return
        if path.name in OPERATIONAL_NAMES:
            return
        self.handle_write(path)

    def _drain_inotify(self) -> None:
        if self._inotify is None:
            return
        overflow = False
        lost: Path | None = None
        lost_mask = 0
        lost_any = False
        for event in self._inotify.read_events():
            if event.mask & IN_Q_OVERFLOW:
                overflow = True
                continue
            base = self._inotify.wd_to_path.get(event.wd)
            if base is None:
                continue
            path = (base / event.name) if event.name else base
            if event.mask & IN_CREATE and event.mask & IN_ISDIR:
                try:
                    self._auto_wds.add(self._inotify.add_watch(path))
                except OSError:
                    pass
            if event.mask & IN_ISDIR and not event.mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                # A directory appearing, moving or vanishing is not a content
                # write; the files inside it raise their own events.
                continue
            if event.mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                self._inotify.wd_to_path.pop(event.wd, None)
                if event.wd in self._auto_wds:
                    # A transient directory (a lock dir, a temp dir) went away.
                    # Not a root, not evidence, and no reason to re-inventory.
                    self._auto_wds.discard(event.wd)
                    continue
                lost = path
                lost_mask = event.mask
                lost_any = True
                continue
            if event.mask & IN_IGNORED:
                self._inotify.wd_to_path.pop(event.wd, None)
                self._auto_wds.discard(event.wd)
                continue
            self._on_fs_event(path, event.mask)
        if overflow:
            self.handle_overflow()
        elif lost_any:
            self.handle_watch_lost(lost, lost_mask)

    def run(self) -> None:
        if not self._stopped():
            clear_session()
            self._ensure_watchlist()
            self._rebuild_watches()
        try:
            while not self._stopped():
                timeout = self._sample_timeout()
                ino = self._inotify
                if ino is not None and ino.fd >= 0:
                    ready, _, _ = select.select([ino.fd], [], [], timeout)
                    if self._stopped():
                        break
                    if ready:
                        self._drain_inotify()
                elif self._stop is not None:
                    self._stop.wait(timeout)
                else:
                    time.sleep(timeout)
                if self._stopped():
                    break
                self.maybe_sample()
        finally:
            self._close_inotify()


def run_forever(config: Mapping[str, Any] | None = None) -> None:
    if config is None:
        config = load_config()
    Daemon(config).run()


if __name__ == "__main__":
    run_forever()
