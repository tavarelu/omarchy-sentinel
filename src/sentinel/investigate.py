# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from typing import Any

from sentinel.models import Alert

# Keys that look like token / auth / body secrets (not path *values*).
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(token|auth|password|secret|credential|refresh|api_?key|body)s?$",
    re.IGNORECASE,
)
_SENSITIVE_SUBSTR_RE = re.compile(
    r"(access_token|refresh_token|auth_body|file_body|id_token|"
    r"api_key|apikey|passwd|password|secret|credential)",
    re.IGNORECASE,
)


def _is_sensitive_key(key: str) -> bool:
    norm = str(key).replace("-", "_")
    if _SENSITIVE_KEY_RE.search(norm):
        return True
    if _SENSITIVE_SUBSTR_RE.search(norm):
        return True
    lower = norm.lower()
    return lower in {"token", "auth", "body", "refresh"}


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Drop keys named like token/auth/body; recurse into nested dicts/lists."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive_key(key):
            continue
        out[key] = _redact_value(value)
    return out


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def format_detail(alert: Alert) -> str:
    lines = [
        f"id:       {alert.id}",
        f"ts:       {alert.ts}",
        f"rule:     {alert.rule}",
        f"severity: {alert.severity}",
        f"status:   {alert.status}",
        f"summary:  {alert.summary}",
        f"exe:      {alert.exe}",
        f"basename: {alert.basename}",
        f"cmdline:  {' '.join(alert.cmdline)}",
        f"cwd:      {alert.cwd}",
        f"pids:     {', '.join(str(p) for p in alert.pids)}",
    ]
    if alert.parent:
        parent = (
            redact_mapping(alert.parent)
            if isinstance(alert.parent, dict)
            else alert.parent
        )
        lines.append(f"parent:   {parent}")
    if alert.paths:
        lines.append("paths:")
        for path in alert.paths:
            lines.append(f"  {path}")
    if alert.hashes:
        lines.append("hashes:")
        for path, digest in alert.hashes.items():
            lines.append(f"  {path}: {digest}")
    if alert.writer_pid is not None:
        lines.append(f"writer_pid: {alert.writer_pid}")
    if alert.evidence:
        lines.append(f"evidence: {redact_mapping(alert.evidence)}")
    return "\n".join(lines) + "\n"


def _pager_argv() -> list[str]:
    raw = os.environ.get("PAGER") or "less"
    parts = shlex.split(raw)
    return parts or ["less"]


def page_detail(alert: Alert) -> None:
    """Show local alert detail via $PAGER or less; print if not a tty."""
    text = format_detail(alert)
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        print(text, end="")
        return
    argv = _pager_argv()
    try:
        subprocess.run(argv, input=text, text=True, check=False)
    except OSError:
        print(text, end="")
