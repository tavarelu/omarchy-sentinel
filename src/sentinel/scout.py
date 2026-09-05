# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.fsutil import write_private_atomic
from sentinel.paths import state_dir

WATCHLIST_FILENAME = "watchlist.json"

DEFAULT_SEEDS: list[str] = [
    ".claude",
    ".codex",
    ".cursor",
    ".config/Cursor",
    ".config/claude",
    ".config/sentinel",
    ".local/state/sentinel",
]

SETTINGS_NAMES = frozenset({"settings.json", "settings.local.json"})


def classify_kind(path: Path) -> str:
    """Heuristic kind from filename/dirname only — never file bodies."""
    name = path.name
    if name in SETTINGS_NAMES:
        return "settings"
    parts_lower = [part.lower() for part in path.parts]
    name_lower = name.lower()
    if any("hook" in part for part in parts_lower):
        return "hooks"
    if "auth" in name_lower or "credentials" in name_lower:
        return "auth"
    if any("mcp" in part for part in parts_lower):
        return "mcp"
    return "other"


def _entry_for(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path.resolve()),
        "kind": classify_kind(path),
        "size": st.st_size,
        "mtime": st.st_mtime,
    }


def scout(home: Path, seeds: list[str] | None = None) -> dict[str, Any]:
    """Inventory seed trees under home; metadata only (path, size, mtime, kind)."""
    home = Path(home)
    seed_list = list(DEFAULT_SEEDS if seeds is None else seeds)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()

    for seed in seed_list:
        root = home / seed
        if not root.exists():
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = [p for p in root.rglob("*") if p.is_file()]
        for path in candidates:
            entry = _entry_for(path)
            key = entry["path"]
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)

    entries.sort(key=lambda e: e["path"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "home": str(home.resolve()),
        "paths": entries,
    }


def write_watchlist(result: dict[str, Any]) -> Path:
    path = state_dir() / WATCHLIST_FILENAME
    write_private_atomic(path, json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path
