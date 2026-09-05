"""Test 3, the joint adversarial suite: harness half.

Grok writes the cases under ``cases/`` as the red team; this file loads every one of them and asserts
exactly what the case declares. The contract both halves are written against is ``SCHEMA.md`` in this
directory. The harness deliberately fails on an expectation key it does not implement, so a case can never
pass by asserting nothing.
"""

from __future__ import annotations

import io
import json
import os
import stat
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from sentinel.action import action_main
from sentinel.models import Alert
from sentinel.notify import Notifier, load_policy

CASES_DIR = Path(__file__).parent / "cases"
# Gates a case may name in "requires". A case naming anything else is skipped, not failed, so the red team
# can write cases ahead of the feature.
IMPLEMENTED = {"ux-01"}
EXPECT_KEYS = {
    "no_exception", "toasts", "summaries", "urgencies", "timeouts", "argv_excludes",
    "body_contains", "body_excludes", "exit_code", "stdout_contains", "stdout_excludes",
    "state_modes", "state_json_keys", "unchanged",
}


def _cases() -> list[Path]:
    return sorted(CASES_DIR.glob("*.json"))


class Recorder:
    """Stands in for `omarchy notification send`; records argv and hands back a notification id."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.next_id = 77

    def __call__(self, argv: list[str]) -> str | None:
        self.calls.append(list(argv))
        return f"{self.next_id}\n" if "-p" in argv else ""

    @property
    def toasts(self) -> list[list[str]]:
        return [c for c in self.calls if "-p" not in c and "-r" not in c]

    @property
    def summaries(self) -> list[list[str]]:
        return [c for c in self.calls if "-p" in c or "-r" in c]

    def values_after(self, flag: str) -> list[str]:
        out: list[str] = []
        for argv in self.calls:
            for i, tok in enumerate(argv):
                if tok == flag and i + 1 < len(argv):
                    out.append(argv[i + 1])
        return sorted(set(out))


def _alert_from_stub(stub: dict, i: int) -> Alert:
    return Alert.new(
        rule=stub.get("rule", "R-BYPASS"),
        severity=stub.get("severity", "high"),
        summary=stub.get("summary", f"case alert {i}"),
        pids=stub.get("pids", []),
        exe=stub.get("exe", "/usr/bin/agent"),
        basename=stub.get("basename", "agent"),
        cmdline=stub.get("cmdline", ["agent", "--yolo"]),
        cwd=stub.get("cwd", "/tmp"),
        evidence=stub.get("evidence", {}),
        paths=stub.get("paths"),
    )


def _write_state(case: dict, state: Path) -> dict[str, bytes]:
    state.mkdir(parents=True, exist_ok=True)
    before: dict[str, bytes] = {}
    for name, text in (case.get("state") or {}).items():
        p = state / name
        p.write_text(text)
        before[name] = p.read_bytes()
    for name, mode in (case.get("state_mode") or {}).items():
        os.chmod(state / name, int(mode, 8))
    return before


def _run_notify(case: dict, recorder: Recorder, config_path: Path | None) -> None:
    action = case["action"]
    clock = [1000.0]
    step = float(action.get("interval_sec", 1))
    n = Notifier(load_policy(config_path), runner=recorder, clock=lambda: clock[0])
    for i, stub in enumerate(action.get("alerts", [])):
        n.send(_alert_from_stub(stub, i))
        clock[0] += step


def _run_cli(case: dict) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = action_main(list(case["action"]["argv"]))
    return rc, buf.getvalue()


@pytest.mark.parametrize("path", _cases(), ids=lambda p: p.stem)
def test_case(path: Path, tmp_path, monkeypatch):
    case = json.loads(path.read_text())
    assert case["id"] == path.stem, f"{path.name}: id must match the filename stem"
    for key in ("title", "author", "why", "action", "expect"):
        assert key in case, f"{path.name}: missing required key {key!r}"
    missing = set(case.get("requires") or []) - IMPLEMENTED
    if missing:
        pytest.skip(f"needs {', '.join(sorted(missing))}")
    expect = case["expect"]
    unknown = set(expect) - EXPECT_KEYS
    assert not unknown, f"{path.name}: harness does not implement {sorted(unknown)} (see SCHEMA.md)"

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    state = tmp_path / "state" / "sentinel"
    before = _write_state(case, state)
    config_path = None
    if "config" in case:
        config_path = tmp_path / "config" / "sentinel" / "config.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(case["config"])

    recorder = Recorder()
    rc, out, raised = 0, "", None
    try:
        if case["action"]["type"] == "notify":
            _run_notify(case, recorder, config_path)
        elif case["action"]["type"] == "cli":
            rc, out = _run_cli(case)
        else:
            pytest.fail(f"{path.name}: unknown action type {case['action']['type']!r}")
    except Exception as exc:  # noqa: BLE001 - the case decides whether this is a failure
        raised = exc

    # Invariants every case gets for free: argv is always a list of plain strings, so nothing reaches a
    # shell, and no argv element smuggles a newline into the notification server.
    for argv in recorder.calls:
        assert isinstance(argv, list) and all(isinstance(t, str) for t in argv), f"{path.name}: argv not a list of str"
        assert not any("\n" in t for t in argv), f"{path.name}: newline in argv {argv!r}"

    if expect.get("no_exception", True):
        assert raised is None, f"{path.name}: raised {raised!r}"
    else:
        assert raised is not None, f"{path.name}: expected an exception, none raised"

    if "toasts" in expect:
        assert len(recorder.toasts) == expect["toasts"], f"toasts: {recorder.toasts}"
    if "summaries" in expect:
        assert len(recorder.summaries) == expect["summaries"], f"summaries: {recorder.summaries}"
    if "urgencies" in expect:
        assert recorder.values_after("-u") == sorted(expect["urgencies"])
    if "timeouts" in expect:
        assert recorder.values_after("-t") == sorted(str(t) for t in expect["timeouts"])
    if "argv_excludes" in expect:
        flat = [t for argv in recorder.calls for t in argv]
        for banned in expect["argv_excludes"]:
            assert banned not in flat, f"argv contains {banned!r}"
    blob = "\n".join(" ".join(argv) for argv in recorder.calls)
    for needle in expect.get("body_contains", []):
        assert needle in blob, f"argv missing {needle!r}"
    for needle in expect.get("body_excludes", []):
        assert needle not in blob, f"argv leaked {needle!r}"
    if "exit_code" in expect:
        assert rc == expect["exit_code"], f"stdout was: {out}"
    for needle in expect.get("stdout_contains", []):
        assert needle in out, f"stdout missing {needle!r}: {out}"
    for needle in expect.get("stdout_excludes", []):
        assert needle not in out, f"stdout leaked {needle!r}: {out}"
    for name, mode in (expect.get("state_modes") or {}).items():
        actual = stat.S_IMODE(os.stat(state / name).st_mode)
        assert actual == int(mode, 8), f"{name}: mode {actual:o} != {mode}"
    for name, keys in (expect.get("state_json_keys") or {}).items():
        data = json.loads((state / name).read_text())
        assert set(keys) <= set(data), f"{name}: missing {sorted(set(keys) - set(data))}"
    for name in expect.get("unchanged", []):
        assert (state / name).read_bytes() == before[name], f"{name} was modified"


def test_cases_directory_is_wired():
    """Guards against the harness silently testing nothing if the cases go missing."""
    assert CASES_DIR.is_dir(), "tests/joint/cases/ is missing"
    assert _cases(), "no case files found; Grok's red-team cases are the other half of Test 3"
