# SPDX-License-Identifier: Apache-2.0
"""Black-box acceptance suite for the user-visible alert path.

Drives the real CLI (`action_main`) and the real `Daemon.emit` inside a
temporary XDG tree. Assertions land on recorded argv and process output,
never on private helpers.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.action import open_argv, open_target
from sentinel.cli import action_main
from sentinel.daemon import Daemon
from sentinel.models import Alert
from sentinel.paths import state_dir

SECRET_BODY = "ACCEPTANCE-SECRET-BODY-DO-NOT-TOAST\n"
SECTION_ORDER = (
    "What fired",
    "Evidence",
    "Verify it yourself",
    "Limits",
    "Where the logs are",
    "Actions",
)
_SOURCE_RE = re.compile(r"\[.+\]")


@dataclass
class Clock:
    """Deterministic wall/monotonic clock; advance instead of sleeping."""

    t: float = 1_700_000_000.0

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)

    def monotonic(self) -> float:
        return self.t

    def wall(self) -> datetime:
        return datetime.fromtimestamp(self.t, tz=timezone.utc)


@dataclass
class Isolated:
    tmp: Path
    bindir: Path
    omarchy_log: Path
    open_log: Path
    id_file: Path
    clock: Clock
    secret_file: Path
    seq: int = 0
    _file_manager: bool = False
    _env: dict[str, str] = field(default_factory=dict)

    def recorded_omarchy(self) -> list[list[str]]:
        if not self.omarchy_log.is_file():
            return []
        return [
            json.loads(line)
            for line in self.omarchy_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def clear_omarchy(self) -> None:
        self.omarchy_log.write_text("", encoding="utf-8")

    def daemon(self) -> Daemon:
        return Daemon(
            {
                "clock": self.clock.monotonic,
                "wall_clock": self.clock.wall,
                "inotify": False,
                "coalesce_window": 0.0,
            }
        )

    def make_alert(self, **kwargs: object) -> Alert:
        self.seq += 1
        n = self.seq
        kwargs.setdefault("rule", "R-BYPASS")
        kwargs.setdefault("severity", "medium")
        kwargs.setdefault(
            "summary", f"acceptance alert {n} used a bypass flag"
        )
        kwargs.setdefault("pids", [10_000 + n])
        kwargs.setdefault("exe", "/usr/bin/claude")
        kwargs.setdefault("basename", "claude")
        kwargs.setdefault(
            "cmdline", ["claude", "--dangerously-skip-permissions"]
        )
        kwargs.setdefault("cwd", str(self.tmp / f"proj {n}"))
        evidence = dict(kwargs.get("evidence") or {})  # type: ignore[arg-type]
        evidence.setdefault("flag", "--dangerously-skip-permissions")
        evidence.setdefault("schema", 2)
        evidence.setdefault("source", "sampler")
        kwargs["evidence"] = evidence
        return Alert.new(**kwargs)  # type: ignore[arg-type]

    def sticky_alert(self, *, severity: str = "high") -> Alert:
        path = str(state_dir() / "alerts.jsonl")
        return self.make_alert(
            rule="R-SELF",
            severity=severity,
            summary="foreign write under Sentinel state",
            pids=[],
            exe="",
            basename="sentinel",
            cmdline=[],
            cwd=str(state_dir()),
            evidence={"event": "foreign-write", "path": path, "schema": 2},
            paths=[path],
        )

    def write_alerted_file(self, name: str = "settings.json") -> Path:
        folder = self.tmp / "agent home" / "hooks"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_text(SECRET_BODY, encoding="utf-8")
        return path

    def enable_file_manager(self) -> None:
        if self._file_manager:
            return
        nautilus = self.bindir / "nautilus"
        nautilus.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        nautilus.chmod(nautilus.stat().st_mode | stat.S_IEXEC)
        uwsm = self.bindir / "uwsm-app"
        uwsm.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "log = Path(os.environ['SENTINEL_ACCEPTANCE_OPEN_LOG'])\n"
            "log.parent.mkdir(parents=True, exist_ok=True)\n"
            "with log.open('a', encoding='utf-8') as f:\n"
            "    f.write(json.dumps(sys.argv) + '\\n')\n",
            encoding="utf-8",
        )
        uwsm.chmod(uwsm.stat().st_mode | stat.S_IEXEC)
        self._file_manager = True

    def wait_open_argv(self, n: int = 1, timeout: float = 2.0) -> list[list[str]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.open_log.is_file():
                lines = [
                    json.loads(line)
                    for line in self.open_log.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                if len(lines) >= n:
                    return lines
        raise AssertionError(f"timed out waiting for {n} open argv line(s)")


def _path_without_nautilus(bindir: Path) -> str:
    parts = [str(bindir)]
    for part in os.environ.get("PATH", "").split(os.pathsep):
        if not part:
            continue
        if (Path(part) / "nautilus").exists():
            continue
        parts.append(part)
    return os.pathsep.join(parts)


def _write_omarchy_stub(bindir: Path, log: Path, id_file: Path) -> Path:
    stub = bindir / "omarchy"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "log = Path(os.environ['SENTINEL_ACCEPTANCE_OMARCHY_LOG'])\n"
        "ids = Path(os.environ['SENTINEL_ACCEPTANCE_OMARCHY_ID'])\n"
        "log.parent.mkdir(parents=True, exist_ok=True)\n"
        "with log.open('a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps(sys.argv) + '\\n')\n"
        "n = 1\n"
        "if ids.is_file():\n"
        "    n = int(ids.read_text(encoding='utf-8').strip() or '0') + 1\n"
        "ids.write_text(str(n), encoding='utf-8')\n"
        "print(n)\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    log.write_text("", encoding="utf-8")
    id_file.write_text("0", encoding="utf-8")
    return stub


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Isolated:
    """Isolated XDG tree, stub `omarchy` first on PATH, controllable clock."""
    state_home = tmp_path / "state"
    config_home = tmp_path / "config"
    bindir = tmp_path / "bin"
    state_home.mkdir()
    config_home.mkdir()
    bindir.mkdir()
    omarchy_log = tmp_path / "omarchy.argv.jsonl"
    open_log = tmp_path / "open.argv.jsonl"
    id_file = tmp_path / "omarchy.id"
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text(SECRET_BODY, encoding="utf-8")
    _write_omarchy_stub(bindir, omarchy_log, id_file)
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("SENTINEL_ACCEPTANCE_OMARCHY_LOG", str(omarchy_log))
    monkeypatch.setenv("SENTINEL_ACCEPTANCE_OMARCHY_ID", str(id_file))
    monkeypatch.setenv("SENTINEL_ACCEPTANCE_OPEN_LOG", str(open_log))
    monkeypatch.setenv("PATH", _path_without_nautilus(bindir))
    env = {
        "XDG_STATE_HOME": str(state_home),
        "XDG_CONFIG_HOME": str(config_home),
        "PATH": _path_without_nautilus(bindir),
    }
    return Isolated(
        tmp=tmp_path,
        bindir=bindir,
        omarchy_log=omarchy_log,
        open_log=open_log,
        id_file=id_file,
        clock=Clock(),
        secret_file=secret_file,
        _env=env,
    )


def _assert_argv_invariants(argv: list[object], *, forbidden: str = SECRET_BODY) -> None:
    assert isinstance(argv, list)
    assert argv, "recorded argv must not be empty"
    for item in argv:
        assert isinstance(item, str), f"argv element is not str: {item!r}"
        assert "\n" not in item, f"argv element contains a newline: {item!r}"
        assert "\r" not in item, f"argv element contains a carriage return: {item!r}"
        body = forbidden.strip()
        assert body not in item, "argv element contains a file body"


def assert_all_recorded(isolated: Isolated) -> None:
    for argv in isolated.recorded_omarchy():
        _assert_argv_invariants(argv)
    if isolated.open_log.is_file():
        for line in isolated.open_log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                _assert_argv_invariants(json.loads(line))


def _is_summary(argv: list[str]) -> bool:
    return "-p" in argv and any(item.startswith("Sentinel:") for item in argv)


def _is_individual(argv: list[str]) -> bool:
    return "menu" in argv and "-p" not in argv


def _flag_value(argv: list[str], flag: str) -> str | None:
    try:
        i = argv.index(flag)
    except ValueError:
        return None
    if i + 1 >= len(argv):
        return None
    return argv[i + 1]


def _section_map(text: str) -> dict[str, list[str]]:
    lines = text.splitlines()
    positions: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if line in SECTION_ORDER:
            positions.append((i, line))
    out: dict[str, list[str]] = {}
    for idx, (start, title) in enumerate(positions):
        end = positions[idx + 1][0] if idx + 1 < len(positions) else len(lines)
        out[title] = lines[start + 1 : end]
    return out


# ------------------------------------------------------------------ burst


def test_burst_five_toasts_then_summary_rewritten_in_place(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    alerts = [
        isolated.make_alert(severity="medium", summary=f"burst {i}")
        for i in range(7)
    ]
    for alert in alerts:
        daemon.emit(alert)
        isolated.clock.advance(1)

    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 7
    individuals = recorded[:5]
    summaries = recorded[5:]
    assert all(_is_individual(a) for a in individuals)
    assert all(_is_summary(a) for a in summaries)
    assert all(not _is_summary(a) for a in individuals)

    first_summary = summaries[0]
    assert _flag_value(first_summary, "-r") is None
    assert any("6 medium" in item for item in first_summary)
    assert any("Sentinel: 6 alerts" in item for item in first_summary)

    printed_id = isolated.id_file.read_text(encoding="utf-8").strip()
    # The first summary is the 6th omarchy call; its printed id is 6.
    assert printed_id == "7"
    second = summaries[1]
    assert _flag_value(second, "-r") == "6"
    assert any("7 medium" in item for item in second)
    assert any("Sentinel: 7 alerts" in item for item in second)
    assert_all_recorded(isolated)


def test_burst_quiet_gap_resets_tracker(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    for i in range(6):
        daemon.emit(isolated.make_alert(severity="medium", summary=f"pre {i}"))
        isolated.clock.advance(1)
    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 6
    assert _is_summary(recorded[-1])

    isolated.clock.advance(600)
    isolated.clear_omarchy()
    daemon.emit(isolated.make_alert(severity="medium", summary="after quiet"))
    after = isolated.recorded_omarchy()
    assert len(after) == 1
    assert _is_individual(after[0])
    assert not _is_summary(after[0])
    assert_all_recorded(isolated)


# --------------------------------------------------------------- timeouts


def test_timeouts_high_30s_medium_15s_normal_urgency(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    high = isolated.make_alert(severity="high", summary="high timeout")
    medium = isolated.make_alert(severity="medium", summary="medium timeout")
    daemon.emit(high)
    daemon.emit(medium)
    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 2
    high_argv, medium_argv = recorded
    assert _is_individual(high_argv)
    assert _is_individual(medium_argv)
    assert _flag_value(high_argv, "-u") == "normal"
    assert _flag_value(high_argv, "-t") == "30000"
    assert _flag_value(medium_argv, "-u") == "normal"
    assert _flag_value(medium_argv, "-t") == "15000"
    assert "critical" not in high_argv
    assert "critical" not in medium_argv
    assert_all_recorded(isolated)


def test_high_toast_is_not_critical(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    daemon.emit(isolated.make_alert(severity="high", summary="must expire"))
    argv = isolated.recorded_omarchy()[0]
    assert _flag_value(argv, "-u") == "normal"
    assert "critical" not in argv
    assert _flag_value(argv, "-t") == "30000"
    assert_all_recorded(isolated)


# ----------------------------------------------------------------- sticky


def test_sticky_self_tamper_is_critical_no_timeout(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    daemon.emit(isolated.sticky_alert())
    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 1
    argv = recorded[0]
    assert _is_individual(argv)
    assert _flag_value(argv, "-u") == "critical"
    assert "-t" not in argv
    assert_all_recorded(isolated)


def test_sticky_sent_while_paused(isolated: Isolated) -> None:
    # `pause` is always written against real wall-clock time (sentinel-action
    # has no fake-clock override); align the fixture's deterministic daemon
    # clock to real time first so is_paused()'s W3-07 pause_max cap check
    # (pause_until - now) sees a normal ~1h gap rather than years of drift
    # against the fixture's fixed epoch.
    isolated.clock.t = time.time()
    rc = action_main(["pause", "1h"])
    assert rc == 0
    daemon = isolated.daemon()
    isolated.clear_omarchy()
    daemon.emit(isolated.make_alert(severity="medium", summary="paused should drop"))
    assert isolated.recorded_omarchy() == []
    daemon.emit(isolated.sticky_alert())
    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 1
    assert _flag_value(recorded[0], "-u") == "critical"
    assert_all_recorded(isolated)


def test_sticky_sent_when_severity_off(isolated: Isolated) -> None:
    rc = action_main(["notify", "--severity", "high=off"])
    assert rc == 0
    daemon = isolated.daemon()
    isolated.clear_omarchy()
    daemon.emit(isolated.make_alert(severity="high", summary="high is off"))
    assert isolated.recorded_omarchy() == []
    daemon.emit(isolated.sticky_alert(severity="high"))
    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 1
    assert _flag_value(recorded[0], "-u") == "critical"
    assert_all_recorded(isolated)


# ----------------------------------------------------------------- filter


def test_notify_severity_off_silences_and_writes_prefs(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    daemon.emit(isolated.make_alert(severity="high", summary="before off"))
    assert len(isolated.recorded_omarchy()) == 1

    rc = action_main(["notify", "--severity", "high=off"])
    assert rc == 0
    prefs = state_dir() / "notify-prefs.json"
    assert prefs.is_file()
    data = json.loads(prefs.read_text(encoding="utf-8"))
    assert data["severities"]["high"] is False

    isolated.clear_omarchy()
    daemon.emit(isolated.make_alert(severity="high", summary="after off"))
    assert isolated.recorded_omarchy() == []
    assert_all_recorded(isolated)


def test_notify_severity_on_restores(isolated: Isolated) -> None:
    assert action_main(["notify", "--severity", "high=off"]) == 0
    daemon = isolated.daemon()
    daemon.emit(isolated.make_alert(severity="high", summary="still off"))
    assert isolated.recorded_omarchy() == []

    assert action_main(["notify", "--severity", "high=on"]) == 0
    prefs = json.loads((state_dir() / "notify-prefs.json").read_text(encoding="utf-8"))
    assert prefs["severities"]["high"] is True
    isolated.clear_omarchy()
    daemon.emit(isolated.make_alert(severity="high", summary="restored"))
    recorded = isolated.recorded_omarchy()
    assert len(recorded) == 1
    assert _is_individual(recorded[0])
    assert_all_recorded(isolated)


def test_notify_json_prints_effective_policy(
    isolated: Isolated, capsys: pytest.CaptureFixture[str]
) -> None:
    assert action_main(["notify", "--severity", "high=off"]) == 0
    capsys.readouterr()
    rc = action_main(["notify", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["high"] is False
    assert payload["medium"] is True
    assert payload["low"] is False
    assert payload["source"]["high"] == "prefs"
    assert payload["prefs_path"] == str(state_dir() / "notify-prefs.json")


def test_prefs_cannot_change_urgency_or_timeout(isolated: Isolated) -> None:
    prefs = state_dir() / "notify-prefs.json"
    prefs.parent.mkdir(parents=True, exist_ok=True)
    prefs.write_text(
        json.dumps(
            {
                "version": 1,
                "severities": {"high": True, "medium": True, "low": True},
                "urgency": "critical",
                "timeout_ms": 1,
                "high_timeout": 1,
                "high": {"urgency": "critical", "timeout_ms": 1},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    daemon = isolated.daemon()
    daemon.emit(isolated.make_alert(severity="high", summary="prefs must not mutate"))
    argv = isolated.recorded_omarchy()[0]
    assert _flag_value(argv, "-u") == "normal"
    assert _flag_value(argv, "-t") == "30000"
    assert "critical" not in argv
    assert_all_recorded(isolated)


# ------------------------------------------------------------ investigate


def test_investigate_six_sections_in_order(
    isolated: Isolated, capsys: pytest.CaptureFixture[str]
) -> None:
    alerted = isolated.write_alerted_file()
    alert = isolated.make_alert(
        rule="R-HOOK-WRITE",
        severity="high",
        summary="hooks file written",
        pids=[],
        exe="",
        basename="unknown",
        cmdline=[],
        cwd=str(alerted.parent),
        evidence={"path": str(alerted), "event": "IN_CLOSE_WRITE", "schema": 2},
        paths=[str(alerted)],
    )
    isolated.daemon().emit(alert)
    capsys.readouterr()
    rc = action_main([alert.id, "investigate"])
    assert rc == 0
    out = capsys.readouterr().out
    positions = [out.splitlines().index(title) for title in SECTION_ORDER]
    assert positions == sorted(positions)
    for title in SECTION_ORDER:
        assert title in out


def test_investigate_evidence_facts_have_bracketed_source(
    isolated: Isolated, capsys: pytest.CaptureFixture[str]
) -> None:
    alerted = isolated.write_alerted_file()
    alert = isolated.make_alert(
        rule="R-HOOK-WRITE",
        severity="medium",
        summary="hooks file written",
        pids=[],
        exe="",
        basename="unknown",
        cmdline=[],
        cwd=str(alerted.parent),
        evidence={"path": str(alerted), "event": "IN_CLOSE_WRITE", "schema": 2},
        paths=[str(alerted)],
    )
    isolated.daemon().emit(alert)
    capsys.readouterr()
    assert action_main([alert.id, "investigate"]) == 0
    sections = _section_map(capsys.readouterr().out)
    facts = [line for line in sections["Evidence"] if line.strip()]
    assert facts, "expected at least one evidence fact"
    for line in facts:
        assert _SOURCE_RE.search(line), f"evidence fact missing [source]: {line!r}"


def test_investigate_quotes_paths_with_spaces(
    isolated: Isolated, capsys: pytest.CaptureFixture[str]
) -> None:
    alerted = isolated.write_alerted_file()
    assert " " in str(alerted)
    alert = isolated.make_alert(
        rule="R-HOOK-WRITE",
        severity="medium",
        summary="hooks file written",
        pids=[],
        exe="",
        basename="unknown",
        cmdline=[],
        cwd=str(alerted.parent),
        evidence={"path": str(alerted), "event": "IN_CLOSE_WRITE", "schema": 2},
        paths=[str(alerted)],
    )
    isolated.daemon().emit(alert)
    capsys.readouterr()
    assert action_main([alert.id, "investigate"]) == 0
    sections = _section_map(capsys.readouterr().out)
    verify = "\n".join(sections["Verify it yourself"])
    assert f"'{alerted}'" in verify or f'"{alerted}"' in verify


def test_investigate_legacy_schema_still_renders(
    isolated: Isolated, capsys: pytest.CaptureFixture[str]
) -> None:
    alerted = isolated.write_alerted_file("legacy.json")
    row = {
        "id": "00000000-0000-4000-8000-00000000old1",
        "ts": "2025-01-01T00:00:00+00:00",
        "rule": "R-HOOK-WRITE",
        "severity": "medium",
        "summary": "legacy hook write",
        "pids": [],
        "exe": "",
        "basename": "unknown",
        "cmdline": [],
        "cwd": str(alerted.parent),
        "evidence": {"path": str(alerted)},
        "paths": [str(alerted)],
        "status": "open",
    }
    alerts_path = state_dir() / "alerts.jsonl"
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    alerts_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    rc = action_main([row["id"], "investigate"])
    assert rc == 0
    out = capsys.readouterr().out
    positions = [out.splitlines().index(title) for title in SECTION_ORDER]
    assert positions == sorted(positions)
    assert "recorded before evidence v2" in out


# ------------------------------------------------------------------- open


def test_open_reveals_alerted_file(isolated: Isolated) -> None:
    alerted = isolated.write_alerted_file()
    alert = isolated.make_alert(
        rule="R-HOOK-WRITE",
        summary="open me",
        pids=[],
        exe="",
        basename="unknown",
        cmdline=[],
        cwd=str(alerted.parent),
        evidence={"path": str(alerted), "schema": 2},
        paths=[str(alerted)],
    )
    isolated.daemon().emit(alert)
    mode, path = open_target(alert, logs=False)
    argv = open_argv(mode, path)
    _assert_argv_invariants(argv)
    assert argv[0] == "uwsm-app"
    assert "--select" in argv
    assert alerted.as_uri() in argv
    assert str(alerted) not in argv or alerted.as_uri() in argv

    isolated.enable_file_manager()
    rc = action_main([alert.id, "open"])
    assert rc == 0
    launched = isolated.wait_open_argv(1)
    _assert_argv_invariants(launched[0])
    assert launched[0][0].endswith("uwsm-app") or launched[0][0] == "uwsm-app"
    assert "--select" in launched[0]
    assert alerted.as_uri() in launched[0]


def test_open_logs_opens_state_directory(isolated: Isolated) -> None:
    alerted = isolated.write_alerted_file()
    alert = isolated.make_alert(
        rule="R-HOOK-WRITE",
        summary="open logs",
        pids=[],
        exe="",
        basename="unknown",
        cmdline=[],
        cwd=str(alerted.parent),
        evidence={"path": str(alerted), "schema": 2},
        paths=[str(alerted)],
    )
    isolated.daemon().emit(alert)
    mode, path = open_target(alert, logs=True)
    argv = open_argv(mode, path)
    _assert_argv_invariants(argv)
    assert argv[0] == "uwsm-app"
    assert "--new-window" in argv
    assert str(state_dir()) in argv

    isolated.enable_file_manager()
    if isolated.open_log.exists():
        isolated.open_log.write_text("", encoding="utf-8")
    rc = action_main([alert.id, "open", "--logs"])
    assert rc == 0
    launched = isolated.wait_open_argv(1)
    _assert_argv_invariants(launched[0])
    assert "--new-window" in launched[0]
    assert str(state_dir()) in launched[0]


def test_open_prints_path_when_file_manager_absent(
    isolated: Isolated, capsys: pytest.CaptureFixture[str]
) -> None:
    alerted = isolated.write_alerted_file()
    alert = isolated.make_alert(
        rule="R-HOOK-WRITE",
        summary="no nautilus",
        pids=[],
        exe="",
        basename="unknown",
        cmdline=[],
        cwd=str(alerted.parent),
        evidence={"path": str(alerted), "schema": 2},
        paths=[str(alerted)],
    )
    isolated.daemon().emit(alert)
    capsys.readouterr()
    rc = action_main([alert.id, "open"])
    captured = capsys.readouterr()
    assert rc == 1
    assert str(alerted) in captured.out
    assert not isolated.open_log.is_file() or isolated.open_log.read_text() == ""


# ---------------------------------------------------------- free invariants


def test_recorded_argv_invariants_hold_for_every_call(isolated: Isolated) -> None:
    daemon = isolated.daemon()
    daemon.emit(isolated.make_alert(severity="high", summary="inv high"))
    daemon.emit(isolated.make_alert(severity="medium", summary="inv medium"))
    daemon.emit(isolated.sticky_alert())
    for argv in isolated.recorded_omarchy():
        _assert_argv_invariants(argv)
        assert all(isinstance(item, str) for item in argv)
    assert_all_recorded(isolated)
