# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentinel.models import Alert
from sentinel.paths import config_dir
from sentinel.rules import extract_bypass_flags

ALLOWED_KEYS = frozenset(
    {
        "rule",
        "severity",
        "basename",
        "flags",
        "cwd",
        "parent_basename",
        "paths",
        "hashes",
        "writer_pid",
    }
)

HttpPost = Callable[..., str]


def _flag_list(alert: Alert) -> list[str]:
    flags = alert.evidence.get("flags") if alert.evidence else None
    if isinstance(flags, list) and flags:
        return [str(x) for x in flags]
    flag = alert.evidence.get("flag") if alert.evidence else None
    if flag:
        return [str(flag)]
    return extract_bypass_flags(alert.cmdline)


def _parent_basename(parent: dict[str, Any] | None) -> str | None:
    if not parent:
        return None
    raw = parent.get("basename") or parent.get("exe") or ""
    if not raw:
        return None
    return Path(str(raw)).name


def _path_names(paths: list[str] | None) -> list[str] | None:
    if not paths:
        return None
    return [Path(p).name for p in paths]


def build_redacted_bundle(alert: Alert) -> dict[str, Any]:
    """Metadata-only cloud payload. Never includes bodies/transcripts/tokens/env."""
    bundle: dict[str, Any] = {
        "rule": alert.rule,
        "severity": alert.severity,
        "basename": alert.basename,
        "flags": _flag_list(alert),
        "cwd": alert.cwd,
        "parent_basename": _parent_basename(alert.parent),
        "paths": _path_names(alert.paths),
        "hashes": dict(alert.hashes) if alert.hashes else None,
        "writer_pid": alert.writer_pid,
    }
    return {k: v for k, v in bundle.items() if k in ALLOWED_KEYS}


def resolve_api_key() -> str | None:
    env = os.environ.get("SENTINEL_API_KEY")
    if env:
        return env.strip() or None
    path = config_dir() / "api_key"
    if not path.is_file():
        return None
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return None
    if mode & 0o077:
        return None
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _default_http_post(bundle: dict[str, Any], *, api_key: str) -> str:
    url = os.environ.get(
        "SENTINEL_SUMMARIZE_URL",
        "https://api.x.ai/v1/chat/completions",
    )
    model = os.environ.get("SENTINEL_SUMMARIZE_MODEL", "grok-2-latest")
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Summarize this Sentinel security alert in plain language. "
                    "Use only the provided metadata; invent nothing."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(bundle, separators=(",", ":")),
            },
        ],
        "temperature": 0,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    choices = body.get("choices") or []
    if not choices:
        raise ValueError("empty summarize response")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise ValueError("empty summarize content")
    return str(content).strip()


def summarize(
    alert: Alert,
    *,
    http_post: HttpPost | None = None,
) -> str | None:
    """Opt-in oneshot cloud digest. Returns None on missing key or HTTP failure."""
    api_key = resolve_api_key()
    if not api_key:
        return None
    bundle = build_redacted_bundle(alert)
    post = http_post if http_post is not None else _default_http_post
    try:
        return post(bundle, api_key=api_key)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, TypeError, KeyError):
        return None
    except Exception:
        return None
