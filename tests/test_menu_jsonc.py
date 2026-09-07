from __future__ import annotations

import json
import re
from pathlib import Path

JSONC_PATH = Path(__file__).resolve().parents[1] / "packaging" / "omarchy-menu-sentinel.jsonc"

_LINE_COMMENT_RE = re.compile(r"(?<!:)//.*$", re.MULTILINE)


def _load() -> dict:
    text = JSONC_PATH.read_text(encoding="utf-8")
    stripped = _LINE_COMMENT_RE.sub("", text)
    return json.loads(stripped)


def test_every_menu_action_wrapped_in_floating_terminal():
    data = _load()
    actioned = [v for v in data.values() if isinstance(v, dict) and "action" in v]
    assert actioned, "no menu rows had an action"
    for row in actioned:
        assert row["action"].startswith(
            "omarchy-launch-floating-terminal-with-presentation "
        ), row


def test_menu_jsonc_still_valid_after_comment_stripping():
    data = _load()
    for key in (
        "sentinel",
        "sentinel.alerts",
        "sentinel.status",
        "sentinel.inventory",
        "sentinel.pause",
    ):
        assert key in data, key
        assert "icon" in data[key]
        assert "label" in data[key]
    assert data["sentinel.alerts"]["action"].endswith("sentinel-action list")
    assert data["sentinel.status"]["action"].endswith("sentinel-action status")
    assert data["sentinel.inventory"]["action"].endswith("sentinel-scout --refresh")
    assert data["sentinel.pause"]["action"].endswith("sentinel-action pause 1h")
