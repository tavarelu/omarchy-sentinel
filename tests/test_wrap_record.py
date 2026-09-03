import json
import os
from pathlib import Path

from sentinel.wrap_record import (
    extract_bypass_flags,
    launch_to_alert,
    record_launch,
)


def test_extract_flags():
    flags = extract_bypass_flags(
        ["claude", "--dangerously-skip-permissions", "do stuff"]
    )
    assert "--dangerously-skip-permissions" in flags


def test_extract_flags_none():
    assert extract_bypass_flags(["claude", "do", "stuff"]) == []


def test_record_launch_appends_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    cwd = str(tmp_path / "proj")
    Path(cwd).mkdir()
    monkeypatch.chdir(cwd)

    record = record_launch(
        "claude",
        ["--dangerously-skip-permissions", "do stuff"],
    )
    assert record["basename"] == "claude"
    assert record["cmdline"] == [
        "claude",
        "--dangerously-skip-permissions",
        "do stuff",
    ]
    assert record["cwd"] == cwd
    assert "--dangerously-skip-permissions" in record["flags"]
    assert record["pid"] == os.getpid()

    path = tmp_path / "sentinel" / "launches.jsonl"
    assert path.is_file()
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    loaded = json.loads(lines[0])
    assert loaded["basename"] == "claude"
    assert loaded["flags"] == record["flags"]


def test_launch_to_alert_rbypass():
    alert = launch_to_alert(
        {
            "basename": "claude",
            "cmdline": ["claude", "--dangerously-skip-permissions"],
            "cwd": "/tmp/scratch",
            "exe": "/usr/bin/claude",
            "flags": ["--dangerously-skip-permissions"],
            "pid": 1234,
        }
    )
    assert alert is not None
    assert alert.rule == "R-BYPASS"
    assert alert.pids == [1234]
    assert alert.exe == "/usr/bin/claude"
    assert alert.cwd == "/tmp/scratch"


def test_launch_to_alert_none_without_flags():
    assert (
        launch_to_alert(
            {
                "basename": "claude",
                "cmdline": ["claude", "hello"],
                "cwd": "/tmp",
                "exe": "/usr/bin/claude",
                "flags": [],
                "pid": 1,
            }
        )
        is None
    )
