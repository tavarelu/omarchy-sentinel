# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import dataclasses
import json
import os
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from sentinel import scan
from sentinel.cli import scan_main
from sentinel.paths import state_dir
from sentinel.scan import (
    ScanResult,
    ScannerNotInstalled,
    build_sandbox_argv,
    parse_report,
    run_scan,
    sanitize_report,
    severity_for,
    tree_hash,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scan"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# (a) fixture -> ScanResult
# ---------------------------------------------------------------------------


def test_parse_report_populates_scan_result_from_fixture():
    data = _load("self_scan_safe.json")
    result = parse_report(data)
    assert result.tool == "skillspector"
    assert result.version == "2.9.6"
    assert result.score == 0
    assert result.recommendation == "SAFE"
    assert result.severity == severity_for("SAFE") == "low"
    assert result.ok is True
    assert result.error is None
    assert result.counts == {}
    assert result.top == []
    # Not among the keys parse_report is allowed to read (claim 2); filled
    # in later by the runner, not by parse_report itself.
    assert result.root is None
    assert result.tree_hash is None
    assert result.report_path is None
    assert result.sandbox is None


@pytest.mark.parametrize(
    "recommendation,expected",
    [("SAFE", "low"), ("CAUTION", "medium"), ("DO_NOT_INSTALL", "high")],
)
def test_parse_report_maps_recommendation_to_severity(recommendation, expected):
    data = {
        "risk_assessment": {"score": 1, "severity": "X", "recommendation": recommendation},
        "issues": [],
        "suppressed": [],
    }
    result = parse_report(data)
    assert result.severity == expected == severity_for(recommendation)


def test_severity_for_unknown_recommendation_fails_safe():
    # Must NOT silently return "low" -- an unrecognized verdict from the
    # scanner has to fail loud, not under-classify.
    with pytest.raises(ValueError):
        severity_for("BOGUS")


# ---------------------------------------------------------------------------
# (b) malformed/missing keys -> ok=False, never raises
# ---------------------------------------------------------------------------


def test_parse_report_missing_required_key_yields_ok_false_not_raises():
    result = parse_report({})
    assert result.ok is False
    assert result.error

    result2 = parse_report({"skill": {}})
    assert result2.ok is False
    assert result2.error

    data = _load("missing_keys_report.json")
    result3 = parse_report(data)
    assert result3.ok is False
    assert result3.error


def test_parse_report_non_dict_input_yields_ok_false_not_raises():
    for bad in (None, [], "not a dict", 42):
        result = parse_report(bad)
        assert result.ok is False
        assert result.error


# ---------------------------------------------------------------------------
# (c) code_snippet never in the parsed result
# ---------------------------------------------------------------------------


def test_scan_result_has_no_code_snippet_field():
    assert "code_snippet" not in {f.name for f in dataclasses.fields(ScanResult)}


def test_parse_report_never_carries_code_snippet():
    data = _load("self_scan_risky.json")
    snippets = [i["code_snippet"] for i in data["issues"] if i.get("code_snippet")]
    assert snippets, "fixture must actually carry code_snippet to make this test real"

    result = parse_report(data)
    flat = json.dumps(dataclasses.asdict(result))
    assert "code_snippet" not in flat
    for snippet in snippets:
        assert snippet not in flat


# ---------------------------------------------------------------------------
# (d) top caps at 3, counts reflect severities
# ---------------------------------------------------------------------------


def test_top_caps_at_three_entries_with_only_safe_shape():
    data = _load("self_scan_risky.json")
    result = parse_report(data)
    assert len(result.top) == 3
    for entry in result.top:
        assert set(entry.keys()) == {"title", "file", "line"}
        assert "\n" not in (entry["title"] or "")
        # top[].title must never be raw source (the `finding` field) --
        # it is built from `pattern`, a short human-readable label.
        assert len(entry["title"]) < 120


def test_counts_reflects_issue_severities():
    data = _load("self_scan_risky.json")
    result = parse_report(data)
    assert sum(result.counts.values()) == len(data["issues"]) == 5
    assert set(result.counts) <= {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# tree_hash
# ---------------------------------------------------------------------------


def _make_tree(root: Path) -> None:
    (root / "a.txt").write_text("hello")
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_text("world")
    (root / "sub" / "c.txt").write_text("!")


def test_tree_hash_stable_across_mtime_change(tmp_path):
    _make_tree(tmp_path)
    h1 = tree_hash(tmp_path)
    target = tmp_path / "a.txt"
    os.utime(target, (target.stat().st_atime + 100, target.stat().st_mtime + 100))
    h2 = tree_hash(tmp_path)
    assert h1 == h2


def test_tree_hash_differs_on_content_change(tmp_path):
    _make_tree(tmp_path)
    h1 = tree_hash(tmp_path)
    (tmp_path / "a.txt").write_text("hellp")  # one byte flipped
    h2 = tree_hash(tmp_path)
    assert h1.digest != h2.digest


def test_tree_hash_refuses_non_directory_root(tmp_path):
    f = tmp_path / "a_file.txt"
    f.write_text("x")
    with pytest.raises(NotADirectoryError):
        tree_hash(f)


def test_tree_hash_symlink_never_opens_target(tmp_path, monkeypatch):
    target = Path("/etc/hostname")
    if not target.exists():
        pytest.skip("/etc/hostname not present on this runner")

    link = tmp_path / "link"
    link.symlink_to(target)

    opened: list[str] = []
    real_open = open

    def spy_open(path, *a, **k):
        opened.append(str(path))
        return real_open(path, *a, **k)

    import builtins

    monkeypatch.setattr(builtins, "open", spy_open)
    result = tree_hash(tmp_path)
    assert str(target) not in opened
    assert result.digest


def test_tree_hash_oversized_file_counted_in_skipped_not_read(tmp_path, monkeypatch):
    big = tmp_path / "big.bin"
    size = scan.HASH_MAX_BYTES + 1
    with open(big, "wb") as f:
        f.seek(size - 1)
        f.write(b"\0")

    calls: list[str] = []
    real_sha256_file = scan._sha256_file

    def spy(path):
        calls.append(path)
        return real_sha256_file(path)

    monkeypatch.setattr(scan, "_sha256_file", spy)
    result = tree_hash(tmp_path)
    assert calls == []
    assert ("big.bin", size) in result.skipped
    assert result.files_hashed == 0


def test_tree_hash_stops_at_file_count_cap_and_sets_truncated(tmp_path, monkeypatch):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text(str(i))
    monkeypatch.setattr(scan, "MAX_FILES", 3)
    result = tree_hash(tmp_path)
    assert result.truncated is True
    assert result.files_hashed <= 3


def test_tree_hash_stops_at_depth_cap_and_sets_truncated(tmp_path, monkeypatch):
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "deep.txt").write_text("deep")
    (tmp_path / "shallow.txt").write_text("shallow")

    monkeypatch.setattr(scan, "MAX_DEPTH", 1)
    result = tree_hash(tmp_path)
    assert result.truncated is True
    # the deep file must not have been hashed
    assert not any(rel == "a/b/c/deep.txt" for rel, _ in result.skipped)
    assert result.files_hashed <= 2


def test_tree_hash_skips_auth_named_files_without_opening_them(tmp_path, monkeypatch):
    secret = tmp_path / "credentials.json"
    secret.write_text('{"token": "super-secret"}')

    calls: list[str] = []
    real_sha256_file = scan._sha256_file

    def spy(path):
        calls.append(path)
        return real_sha256_file(path)

    monkeypatch.setattr(scan, "_sha256_file", spy)
    result = tree_hash(tmp_path)
    assert calls == []
    assert any(rel == "credentials.json" for rel, _ in result.skipped)


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_sanitize_report_strips_code_snippet_and_truncates_long_fields():
    data = _load("self_scan_risky.json")
    sanitized = sanitize_report(data)

    def walk(obj):
        if isinstance(obj, dict):
            assert "code_snippet" not in obj
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(sanitized)

    long_issue = next(i for i in data["issues"] if len(i.get("code_snippet") or "") > 1024)
    sanitized_issue = next(
        i
        for i in sanitized["issues"]
        if i.get("location") == long_issue.get("location") and i.get("id") == long_issue.get("id")
    )
    assert "explanation" in sanitized_issue or "finding" in sanitized_issue
    for value in sanitized_issue.values():
        if isinstance(value, str):
            assert len(value.encode("utf-8")) <= 1024 + len(scan.TRUNCATION_MARKER)


def test_sanitize_report_truncates_oversized_issue_string_field():
    issue = dict(_load("self_scan_risky.json")["issues"][0])
    issue.pop("code_snippet", None)
    issue["explanation"] = "x" * 2000
    data = {"issues": [issue], "suppressed": []}
    sanitized = sanitize_report(data)
    value = sanitized["issues"][0]["explanation"]
    assert len(value) < 2000
    assert value.endswith(scan.TRUNCATION_MARKER)


# ---------------------------------------------------------------------------
# Sandbox argv
# ---------------------------------------------------------------------------


def test_sandbox_argv_uses_systemd_run_transient_service_when_available(tmp_path, monkeypatch):
    def fake_which(name):
        return f"/usr/bin/{name}" if name == "systemd-run" else None

    monkeypatch.setattr(scan.shutil, "which", fake_which)
    inner = ["/opt/scanner/bin/skillspector", "scan", str(tmp_path)]
    argv, sandbox = build_sandbox_argv(inner, root=tmp_path, timeout=30)
    assert sandbox == "systemd-run"
    assert argv[0].endswith("systemd-run")
    for flag in ("--user", "--wait", "--collect", "--pipe"):
        assert flag in argv
    assert "--scope" not in argv
    assert ("-p", "PrivateNetwork=yes") == tuple(argv[argv.index("-p") : argv.index("-p") + 2])
    assert "MemoryMax=1G" in argv
    assert f"RuntimeMaxSec=30" in argv
    assert "ProtectSystem=strict" in argv
    assert any(a.startswith("ReadOnlyPaths=") for a in argv)
    assert "--" in argv
    assert argv[argv.index("--") + 1 :] == inner


def test_sandbox_argv_drops_privatenetwork_when_osv_lookup_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(
        scan.shutil, "which", lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None
    )
    argv, _ = build_sandbox_argv(["scanner"], root=tmp_path, timeout=30, osv_lookup=True)
    assert "PrivateNetwork=yes" not in argv


def test_sandbox_falls_back_to_unshare_when_systemd_run_missing(tmp_path, monkeypatch):
    def fake_which(name):
        return "/usr/bin/unshare" if name == "unshare" else None

    monkeypatch.setattr(scan.shutil, "which", fake_which)
    argv, sandbox = build_sandbox_argv(["scanner", "x"], root=tmp_path, timeout=10)
    assert sandbox == "unshare"
    assert argv[0].endswith("unshare")
    assert "-rn" in argv
    assert argv[-2:] == ["scanner", "x"]


def test_sandbox_reports_none_when_neither_tool_available(tmp_path, monkeypatch):
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    argv, sandbox = build_sandbox_argv(["scanner", "x"], root=tmp_path, timeout=10)
    assert sandbox == "none"
    assert argv == ["scanner", "x"]


def test_sandbox_argv_rejects_root_with_whitespace(tmp_path, monkeypatch):
    monkeypatch.setattr(
        scan.shutil, "which", lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None
    )
    bad_root = tmp_path / "has space"
    bad_root.mkdir()
    with pytest.raises(ValueError):
        build_sandbox_argv(["scanner"], root=bad_root, timeout=10)


# ---------------------------------------------------------------------------
# Runner: argv array, timeout, missing scanner, disk write, no-raw-on-disk
# ---------------------------------------------------------------------------


def test_runner_builds_argv_array_never_a_shell_string_and_honours_timeout(
    tmp_path, monkeypatch
):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert isinstance(argv, list)
        stdout = json.dumps(_load("self_scan_safe.json"))
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(scan, "resolve_scanner_binary", lambda: Path("/opt/fake/skillspector"))
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)  # sandbox="none", simplest argv

    root = tmp_path / "target"
    root.mkdir()
    (root / "f.txt").write_text("x")

    result = run_scan(root, timeout=17)
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert kwargs.get("timeout") == 17
    assert result.ok is True
    assert result.sandbox == "none"


def test_scan_main_missing_scanner_exits_nonzero_with_one_line_instruction(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(scan, "resolve_scanner_binary", lambda: None)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    rc = scan_main([str(tmp_path)])
    assert rc != 0
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line]
    assert len(lines) == 1
    assert "Traceback" not in out
    assert "install-scanner.sh" in out


def test_scan_main_writes_sanitized_report_under_state_dir_private_mode(
    tmp_path, monkeypatch, capsys
):
    risky = _load("self_scan_risky.json")
    snippets = [i["code_snippet"] for i in risky["issues"] if i.get("code_snippet")]

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(risky), stderr="")

    state_home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    monkeypatch.setattr(scan, "resolve_scanner_binary", lambda: Path("/opt/fake/skillspector"))
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)

    root = tmp_path / "target"
    root.mkdir()
    (root / "f.txt").write_text("x")

    rc = scan_main([str(root)])
    assert rc == 0

    scans_dir = state_dir() / "scans"
    assert stat.S_IMODE(scans_dir.stat().st_mode) == 0o700
    written = list(scans_dir.glob("*.json"))
    assert len(written) == 1
    report_file = written[0]
    assert stat.S_IMODE(report_file.stat().st_mode) == 0o600

    raw_text = report_file.read_text(encoding="utf-8")
    loaded = json.loads(raw_text)

    def walk(obj):
        if isinstance(obj, dict):
            assert "code_snippet" not in obj
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(loaded)
    for snippet in snippets:
        assert snippet not in raw_text


def test_raw_scanner_output_never_touches_disk_before_sanitization(tmp_path, monkeypatch):
    risky = _load("self_scan_risky.json")

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(risky), stderr="")

    captured = {}

    def fake_write(path, text):
        captured["text"] = text

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(scan, "resolve_scanner_binary", lambda: Path("/opt/fake/skillspector"))
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(scan, "write_private_atomic", fake_write)

    root = tmp_path / "target"
    root.mkdir()
    run_scan(root, timeout=30)

    assert "text" in captured
    assert "code_snippet" not in captured["text"]


def test_run_scan_never_raises_on_malformed_scanner_output(tmp_path, monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="not json{{{", stderr="")

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(scan, "resolve_scanner_binary", lambda: Path("/opt/fake/skillspector"))
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)

    root = tmp_path / "target"
    root.mkdir()
    result = run_scan(root, timeout=5)
    assert result.ok is False
    assert result.error


def test_run_scan_raises_scanner_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "resolve_scanner_binary", lambda: None)
    root = tmp_path / "target"
    root.mkdir()
    with pytest.raises(ScannerNotInstalled):
        run_scan(root, timeout=5)


# ---------------------------------------------------------------------------
# Source-level acceptance guards (turn the manual grep into a real test)
# ---------------------------------------------------------------------------


def test_scan_source_has_no_shell_or_network_calls():
    src = (REPO_ROOT / "src" / "sentinel" / "scan.py").read_text(encoding="utf-8")
    for banned in (
        "shell=True",
        "os.system",
        "/bin/sh",
        "import urllib",
        "import requests",
        "import http.client",
        "import socket",
        "sudo",
    ):
        assert banned not in src, banned


def test_daemon_never_imports_scan_module():
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sentinel.daemon, sys; assert 'sentinel.scan' not in sys.modules",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


def test_pyproject_declares_sentinel_scan_entry_point():
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["sentinel-scan"] == "sentinel.cli:scan_main"
