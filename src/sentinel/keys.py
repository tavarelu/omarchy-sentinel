# SPDX-License-Identifier: Apache-2.0
"""Shared keying for approvals: one definition of where an alert happened and what it carried.

Invariant: the CLI (approve) and the daemon (suppress) must derive identical
fingerprints for the same alert, or Approve silently does nothing.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.models import Alert
from sentinel.rules import extract_bypass_flags

WRITE_RULES = frozenset({"R-HOOK-WRITE", "R-SELF"})
GLOBAL_PREFIX = ""
SCOPES_GLOBAL = frozenset({"session", "24h", "forever"})


def alert_location(alert: Alert) -> str:
    """cwd for process rules; the first path for write rules; empty otherwise."""
    if alert.cwd:
        return alert.cwd
    if alert.paths:
        return alert.paths[0]
    return ""


def alert_flag_set(alert: Alert) -> frozenset[str]:
    """Flags from evidence, falling back to the cmdline; identical on both sides."""
    evidence = alert.evidence or {}
    flags = evidence.get("flags")
    if isinstance(flags, list) and flags:
        return frozenset(str(x) for x in flags)
    flag = evidence.get("flag")
    if flag:
        return frozenset({str(flag)})
    return frozenset(extract_bypass_flags(list(alert.cmdline or [])))


def repo_root(path: str) -> str:
    """Nearest directory at or above ``path`` containing ``.git``; else ``path`` itself.

    A missing path is treated as a directory so synthetic cwds still key sanely.
    """
    if not path:
        return ""
    p = Path(path)
    start = p.parent if p.is_file() else p
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return str(candidate)
    return str(p)


def approval_prefix(alert: Alert, scope: str) -> str:
    """The cwd_prefix an approval is keyed on for ``scope``.

    session / 24h / forever apply anywhere (empty prefix). this-repo means the
    git repository of the cwd for process rules, and the exact file for write rules.
    """
    if scope in SCOPES_GLOBAL:
        return GLOBAL_PREFIX
    if scope == "this-repo":
        location = alert_location(alert)
        if alert.rule in WRITE_RULES:
            return location
        return repo_root(location)
    raise ValueError(f"invalid scope: {scope!r}")


def candidate_prefixes(location: str) -> list[str]:
    """Prefixes the daemon must test: the global one, then the location and its parents."""
    out = [GLOBAL_PREFIX]
    if location:
        p = Path(location)
        out.append(str(p))
        out.extend(str(x) for x in p.parents)
    return out
