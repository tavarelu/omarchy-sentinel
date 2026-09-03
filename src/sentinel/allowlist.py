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

# Session-scoped approvals live in memory only (cleared on restart / clear_session).
_session: dict[str, dict[str, Any]] = {}


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


def _load_persisted() -> dict[str, dict[str, Any]]:
    path = _allowlist_path()
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "entries" in data:
        entries = data["entries"]
        return entries if isinstance(entries, dict) else {}
    return data if isinstance(data, dict) else {}


def _save_persisted(entries: dict[str, dict[str, Any]]) -> None:
    path = _allowlist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump({"entries": entries}, f, separators=(",", ":"))


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


def _entry_allows(entry: dict[str, Any], cwd: str, now: datetime) -> bool:
    scope = entry.get("scope")
    if scope == "24h":
        expires_at = entry.get("expires_at")
        if expires_at is None:
            return False
        expiry = datetime.fromisoformat(expires_at)
        if now >= expiry:
            return False
    if scope == "this-repo":
        prefix = entry.get("cwd_prefix", "")
        if not _cwd_matches_prefix(cwd, prefix):
            return False
    return True


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
        _session[fp] = entry
        return
    entries = _load_persisted()
    entries[fp] = entry
    # Drop any stale session copy for the same fingerprint.
    _session.pop(fp, None)
    _save_persisted(entries)


def is_allowed(fp: str, cwd: str, now: datetime | None = None) -> bool:
    when = now if now is not None else datetime.now(timezone.utc)
    if fp in _session:
        return _entry_allows(_session[fp], cwd, when)
    entries = _load_persisted()
    entry = entries.get(fp)
    if entry is None:
        return False
    return _entry_allows(entry, cwd, when)


def clear_session() -> None:
    _session.clear()
