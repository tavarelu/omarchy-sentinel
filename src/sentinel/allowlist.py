from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from sentinel.paths import state_dir

Scope = Literal["session", "24h", "this-repo", "forever"]
SCOPES = frozenset({"session", "24h", "this-repo", "forever"})

ALLOWLIST_FILENAME = "allowlist.json"
SESSION_FILENAME = "allowlist-session.json"

Decision = Literal["allowed", "expired", "none"]


def fingerprint(
    rule: str,
    basename: str,
    flag_set: frozenset[str] | set[str],
    cwd_prefix: str,
) -> str:
    flags = ",".join(sorted(flag_set))
    payload = f"{rule}\0{basename}\0{flags}\0{cwd_prefix}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _allowlist_path() -> Path:
    return state_dir() / ALLOWLIST_FILENAME


def _session_path() -> Path:
    # Session approvals must cross the process boundary between sentinel-action
    # and the daemon, so they live in a file the daemon deletes on startup.
    return state_dir() / SESSION_FILENAME


def _load_file(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(data, dict) and "entries" in data:
        entries = data["entries"]
        return entries if isinstance(entries, dict) else {}
    return data if isinstance(data, dict) else {}


def _save_file(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump({"entries": entries}, f, separators=(",", ":"))


def _load_persisted() -> dict[str, dict[str, Any]]:
    return _load_file(_allowlist_path())


def _save_persisted(entries: dict[str, dict[str, Any]]) -> None:
    _save_file(_allowlist_path(), entries)


def _load_session() -> dict[str, dict[str, Any]]:
    return _load_file(_session_path())


def load_all() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """(session entries, persisted entries) read once, for one decision."""
    return _load_session(), _load_persisted()


def _cwd_matches_prefix(cwd: str, prefix: str) -> bool:
    cwd_path = Path(cwd)
    prefix_path = Path(prefix)
    if cwd_path == prefix_path:
        return True
    try:
        cwd_path.relative_to(prefix_path)
        return True
    except ValueError:
        return False


def _entry_expired(entry: dict[str, Any], now: datetime) -> bool:
    if entry.get("scope") != "24h":
        return False
    expires_at = entry.get("expires_at")
    if expires_at is None:
        return True
    return now >= datetime.fromisoformat(expires_at)


def _entry_allows(entry: dict[str, Any], cwd: str, now: datetime) -> bool:
    if _entry_expired(entry, now):
        return False
    if entry.get("scope") == "this-repo":
        prefix = entry.get("cwd_prefix", "")
        if not _cwd_matches_prefix(cwd, prefix):
            return False
    return True


def decide(
    session: dict[str, dict[str, Any]],
    persisted: dict[str, dict[str, Any]],
    fp: str,
    cwd: str,
    now: datetime,
) -> Decision:
    """allowed / expired / none for one fingerprint against already-loaded entries."""
    entry = session.get(fp)
    if entry is None:
        entry = persisted.get(fp)
    if entry is None:
        return "none"
    if _entry_expired(entry, now):
        return "expired"
    return "allowed" if _entry_allows(entry, cwd, now) else "none"


def approve(fp: str, scope: Scope, cwd_prefix: str) -> None:
    if scope not in SCOPES:
        raise ValueError(f"invalid scope: {scope!r}")
    entry: dict[str, Any] = {
        "scope": scope,
        "cwd_prefix": cwd_prefix,
        "expires_at": None,
    }
    if scope == "24h":
        entry["expires_at"] = (
            datetime.now(timezone.utc) + timedelta(hours=24)
        ).isoformat()
    if scope == "session":
        session = _load_session()
        session[fp] = entry
        _save_file(_session_path(), session)
        return
    entries = _load_persisted()
    entries[fp] = entry
    _save_persisted(entries)
    # Drop any stale session copy for the same fingerprint.
    session = _load_session()
    if fp in session:
        del session[fp]
        _save_file(_session_path(), session)


def is_allowed(fp: str, cwd: str, now: datetime | None = None) -> bool:
    when = now if now is not None else datetime.now(timezone.utc)
    session, persisted = load_all()
    return decide(session, persisted, fp, cwd, when) == "allowed"


def remove(fp: str) -> None:
    """Forget one fingerprint everywhere (used when a 24h approval expires)."""
    entries = _load_persisted()
    if fp in entries:
        del entries[fp]
        _save_persisted(entries)
    session = _load_session()
    if fp in session:
        del session[fp]
        _save_file(_session_path(), session)


def clear_session() -> None:
    """Session scope ends here: called by the daemon at startup."""
    try:
        _session_path().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass
