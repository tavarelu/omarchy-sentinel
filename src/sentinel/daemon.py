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

from sentinel.action import PAUSE_FILENAME, load_pause_max
from sentinel.allowlist import (
    allowlist_path,
    clear_session,
    decide,
    fingerprint,
    load_all,
    remove,
    session_path,
)
from sentinel.fsutil import ensure_private_dir
from sentinel.journal import mirror_alert
from sentinel.keys import alert_flag_set, alert_location, candidate_prefixes
from sentinel.models import Alert
from sentinel.notify import STICKY_EVENTS
from sentinel.paths import config_dir, default_config_path, state_dir
from sentinel.procinfo import instance_key, read_starttime
from sentinel.rules import evaluate_process, evaluate_write
from sentinel.scout import WATCHLIST_FILENAME, scout, write_watchlist
from sentinel.statewatch import StateLedger, consume_cli_writes, create_control_socket, drain_control_socket
from sentinel.store import ALERTS_FILENAME, alerts_path, append_alert
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
        "pause_until",
        "alerts.lock",
        "alerts.jsonl.tmp",
        "alerts.jsonl.1",
        "notify-prefs.json",
        "notify-burst.json",
    }
)
SCANS_DIRNAME = "scans"
PROCESS_RULES = frozenset({"R-BYPASS", "R-CHILD-SHELL"})


def _is_scan_report(path: Path) -> bool:
    """sentinel-scan reports live in state_dir()/scans/<tree-digest>.json.

    They are Sentinel's own files written by a CLI, not the daemon, so they are
    classified through the ledger (announced -> ours, else foreign) rather than
    through evaluate_write, which would raise R-SELF for every scan.
    """
    return path.suffix == ".json" and path.parent == state_dir() / SCANS_DIRNAME
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
    """Duplicate-suppression key. Process alerts key on the process instance so
    a recycled pid or a fresh launch is never mistaken for the previous one; the
    seen registry, not the coalescer, dedupes the same instance."""
    instance = (alert.evidence or {}).get("instance")
    if instance and alert.rule in PROCESS_RULES:
        return f"{alert.rule}|{alert.basename}|{instance}"
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
        # State ledger and pause cap must exist before the Notifier below (it
        # wires on_state_write=self._ledger.record so BurstTracker.save's own
        # write to notify-burst.json is recorded as ours, not foreign).
        self._ledger = StateLedger()
        self._pause_max = cfg.get("pause_max", load_pause_max())
        self._control_sock = (
            create_control_socket() if cfg.get("control_socket", True) else None
        )
        if "notify" in cfg and cfg["notify"] is not None:
            self._notify: Callable[[Alert], None] = cfg["notify"]
        else:
            from sentinel.notify import Notifier, load_policy

            self._notify = Notifier(
                load_policy(),
                clock=lambda: self._wall_clock().timestamp(),
                wall_clock=self._wall_clock,
                on_state_write=self._ledger.record,
            ).send
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
        # One alert per process instance: rule|pid:starttime|flags -> alert id.
        self._seen: dict[str, str] = {}
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

    def _refresh_watchlist(self) -> Path:
        """refresh_watchlist() also writes via scout.write_watchlist, which
        already announces over the control socket; recording directly here too
        means the daemon's own baseline is correct even before that
        announcement is drained (no race against the next inotify event)."""
        path = refresh_watchlist(self._home)
        self._ledger.record(path)
        return path

    def _ensure_watchlist(self) -> None:
        if self._watch_override is not None:
            self._watch_roots = list(self._watch_override)
            return
        ensure_private_dir(state_dir())
        ensure_private_dir(config_dir())
        if not (state_dir() / WATCHLIST_FILENAME).exists():
            self._refresh_watchlist()
        self._load_watch_paths()

    def _dirs_to_watch(self) -> list[Path]:
        dirs: set[Path] = set()
        if self._self_override is None:
            for path in (config_dir(), state_dir()):
                try:
                    ensure_private_dir(path)
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

    def _seen_key(self, alert: Alert) -> str | None:
        instance = (alert.evidence or {}).get("instance")
        if alert.rule not in PROCESS_RULES or not instance:
            return None
        return f"{alert.rule}|{instance}|{','.join(sorted(alert_flag_set(alert)))}"

    def _prune_seen(self, live_pids: set[int]) -> None:
        dead = [k for k in self._seen if int(k.split("|", 2)[1].split(":", 1)[0]) not in live_pids]
        for k in dead:
            del self._seen[k]

    def _store_and_dispatch(self, alert: Alert) -> None:
        append_alert(alert)
        self._ledger.record(alerts_path())
        try:
            mirror_alert(alert)
        except Exception:
            pass
        self._notify(alert)

    def emit(self, alert: Alert) -> None:
        if alert.rule == "R-SELF" and (alert.evidence or {}).get("event") in STICKY_EVENTS:
            # Self-defense tamper evidence is never allowlist-suppressible: an
            # attacker who could pre-silence R-SELF via an ordinary allowlist
            # entry (fingerprint() is a public deterministic function) would
            # defeat this packet's entire premise. Already deduplicated
            # "once per distinct content" by the state ledger at the call
            # site, so this also bypasses the time-windowed coalescer.
            self._store_and_dispatch(alert)
            return
        decision, fp = _allow_decision(alert, self._wall_clock())
        if decision == "allowed":
            return
        if decision == "expired":
            remove(fp)
            self._ledger.record(allowlist_path())
            self._ledger.record(session_path())
            alert = expired_alert(alert, fp)
        key = self._seen_key(alert)
        if key is not None and key in self._seen:
            return  # this process instance already has its one alert
        if not self.coalescer.should_emit(coalesce_key(alert)):
            return
        if key is not None:
            self._seen[key] = alert.id
        self._store_and_dispatch(alert)

    def handle_write(
        self,
        path: Path,
        writer_pid: int | None = None,
        writer_exe: str | None = None,
        writer_cmdline: Sequence[str] | None = None,
    ) -> None:
        path = Path(path)
        if path.name in OPERATIONAL_NAMES or _is_scan_report(path):
            # Writer identity is unavailable from inotify and the ledger is a
            # more precise signal for Sentinel's own files, so these are
            # classified by content rather than skipped (W3-07 R9).
            self._classify_operational_write(path)
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

    def _raise_tamper_alert(self, evidence: dict[str, Any], path: Path) -> None:
        event = evidence["event"]
        summary = {
            "foreign-write": f"sentinel state written by an unknown process: {path.name}",
            "alert-log-truncated": "sentinel alert log was truncated",
            "pause-over-cap": "pause_until exceeds the configured pause cap",
        }.get(event, f"sentinel self-defense: {event}")
        alert = Alert.new(
            rule="R-SELF",
            severity="high",
            summary=summary,
            pids=[],
            exe="",
            basename="",
            cmdline=[],
            cwd="",
            evidence=evidence,
            paths=[str(path)],
        )
        self.emit(alert)
        # Re-baseline so an identical repeat of this exact (still-tampered)
        # content does not raise a second alert -- "once per distinct content".
        self._ledger.record(path)

    def _pause_over_cap_value(self, path: Path) -> str | None:
        """The raw pause_until text if it exceeds self._pause_max from the
        daemon's own wall clock right now; else None."""
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not raw:
            return None
        try:
            until = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        if until - self._wall_clock() > self._pause_max:
            return raw
        return None

    def _classify_pause_write(self, path: Path) -> None:
        verdict = self._ledger.check(path)
        over = self._pause_over_cap_value(path)
        if over is not None:
            if verdict == "unchanged":
                return  # already alerted for this exact content
            self._raise_tamper_alert(
                {"event": "pause-over-cap", "until": over, "path": str(path)}, path
            )
            return
        if verdict != "foreign":
            return
        self._raise_tamper_alert({"event": "foreign-write", "path": str(path)}, path)

    def _classify_operational_write(self, path: Path) -> None:
        if path.name == PAUSE_FILENAME:
            self._classify_pause_write(path)
            return
        prev_size = self._ledger.last_size(path)
        verdict = self._ledger.check(path)
        if verdict != "foreign":
            return
        evidence: dict[str, Any] = {"event": "foreign-write", "path": str(path)}
        if path.name == ALERTS_FILENAME and prev_size is not None:
            try:
                cur_size = path.stat().st_size
            except OSError:
                cur_size = 0
            if cur_size < prev_size:
                evidence = {
                    "event": "alert-log-truncated",
                    "path": str(path),
                    "size_before": prev_size,
                    "size_after": cur_size,
                }
        self._raise_tamper_alert(evidence, path)

    def handle_process(
        self,
        cmdline: list[str],
        exe: str,
        cwd: str,
        pid: int | None = None,
        parent: dict[str, Any] | None = None,
        starttime: int | None = None,
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
            alert.evidence["starttime"] = starttime
            alert.evidence["instance"] = instance_key(int(pid), starttime)
            alert.evidence.setdefault("source", "sampler")
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
        self._refresh_watchlist()
        if self._watch_override is None:
            self._load_watch_paths()
        if self._inotify is not None:
            self._rebuild_watches()

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
        if self._watch_override is None:
            self._refresh_watchlist()
            self._load_watch_paths()
        if self._enable_inotify:
            self._rebuild_watches()

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
        live: set[int] = set()
        for pid_dir in pid_dirs:
            name = pid_dir.name
            if not name.isdigit():
                continue
            pid = int(name)
            live.add(pid)
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
            starttime = read_starttime(pid, root)
            self.handle_process(cmdline, exe or cmdline[0], cwd, pid=pid, starttime=starttime)
        self._prune_seen(live)

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
        # OPERATIONAL_NAMES writes are no longer ignored here either (W3-07
        # R9): handle_write now classifies them through the ledger.
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

    def _seed_ledger(self) -> None:
        """Baseline every operational file's current on-disk state at startup,
        so a daemon restart does not itself flag every pre-existing file as
        foreign on the first check. pause_until is handled separately: an
        over-cap value already on disk at startup must still be flagged once,
        not silently absorbed as a trusted baseline (a mute attempt survives
        a restart otherwise)."""
        for name in OPERATIONAL_NAMES:
            if name == PAUSE_FILENAME:
                continue
            path = state_dir() / name
            if path.exists():
                self._ledger.record(path)
        pause_path = state_dir() / PAUSE_FILENAME
        if pause_path.exists():
            over = self._pause_over_cap_value(pause_path)
            if over is not None:
                self._raise_tamper_alert(
                    {"event": "pause-over-cap", "until": over, "path": str(pause_path)},
                    pause_path,
                )
            else:
                self._ledger.record(pause_path)

    def _drain_control_socket(self) -> None:
        if self._control_sock is None:
            return
        drain_control_socket(self._control_sock, self._ledger)

    def _close_control_socket(self) -> None:
        if self._control_sock is not None:
            try:
                self._control_sock.close()
            except OSError:
                pass
            self._control_sock = None

    def run(self) -> None:
        if not self._stopped():
            clear_session()
            self._ledger.record(session_path())
            self._ensure_watchlist()
            self._rebuild_watches()
            self._seed_ledger()
            consume_cli_writes(self._ledger)
        try:
            while not self._stopped():
                timeout = self._sample_timeout()
                ino = self._inotify
                fds: list[int] = []
                if ino is not None and ino.fd >= 0:
                    fds.append(ino.fd)
                if self._control_sock is not None:
                    fds.append(self._control_sock.fileno())
                if fds:
                    ready, _, _ = select.select(fds, [], [], timeout)
                    if self._stopped():
                        break
                    if ino is not None and ino.fd in ready:
                        self._drain_inotify()
                    if self._control_sock is not None and self._control_sock.fileno() in ready:
                        self._drain_control_socket()
                elif self._stop is not None:
                    self._stop.wait(timeout)
                else:
                    time.sleep(timeout)
                if self._stopped():
                    break
                self.maybe_sample()
        finally:
            self._close_inotify()
            self._close_control_socket()


def run_forever(config: Mapping[str, Any] | None = None) -> None:
    if config is None:
        config = load_config()
    Daemon(config).run()


if __name__ == "__main__":
    run_forever()
