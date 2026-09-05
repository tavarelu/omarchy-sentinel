# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from sentinel.models import STATUSES, Alert
from sentinel.paths import state_dir

ALERTS_FILENAME = "alerts.jsonl"


def _alerts_path() -> Path:
    return state_dir() / ALERTS_FILENAME


def append_alert(alert: Alert) -> None:
    path = _alerts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(alert.to_dict(), separators=(",", ":")) + "\n")


def iter_alerts() -> Iterator[Alert]:
    path = _alerts_path()
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield Alert.from_dict(json.loads(line))


def update_alert_status(id: str, status: str) -> None:
    if status not in STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    path = _alerts_path()
    if not path.exists():
        raise KeyError(id)
    rows = list(iter_alerts())
    found = False
    updated: list[Alert] = []
    for alert in rows:
        if alert.id == id:
            alert.status = status
            found = True
        updated.append(alert)
    if not found:
        raise KeyError(id)
    with path.open("w", encoding="utf-8") as f:
        for alert in updated:
            f.write(json.dumps(alert.to_dict(), separators=(",", ":")) + "\n")
