from __future__ import annotations

import pytest

from sentinel.keys import (
    alert_flag_set,
    alert_location,
    approval_prefix,
    candidate_prefixes,
    repo_root,
)
from sentinel.models import Alert


def _proc(cwd="/a/b/c", flags=None, cmdline=None) -> Alert:
    fl = ["--yolo"] if flags is None else flags
    ev = {"flags": fl, "flag": fl[0]} if fl else {}
    return Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="x",
        pids=[1],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=cmdline if cmdline is not None else ["claude", *fl],
        cwd=cwd,
        evidence=ev,
    )


def _write(path: str) -> Alert:
    return Alert.new(
        rule="R-HOOK-WRITE",
        severity="high",
        summary="x",
        pids=[],
        exe="",
        basename="",
        cmdline=[],
        cwd="",
        evidence={"path": path},
        paths=[path],
    )


def test_alert_location_process_vs_write():
    assert alert_location(_proc(cwd="/p/q")) == "/p/q"
    assert alert_location(_write("/h/.claude/settings.json")) == "/h/.claude/settings.json"
    assert alert_location(_proc(cwd="")) == ""


def test_alert_flag_set_prefers_evidence_then_cmdline():
    assert alert_flag_set(_proc(flags=["--yolo", "--trust-all"])) == frozenset({"--yolo", "--trust-all"})
    bare = _proc(flags=[], cmdline=["claude", "--dangerously-skip-permissions"])
    assert alert_flag_set(bare) == frozenset({"--dangerously-skip-permissions"})
    assert alert_flag_set(_write("/x")) == frozenset()


def test_repo_root_finds_git_dir_from_dir_and_file(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    deep = root / "sub" / "deep"
    deep.mkdir(parents=True)
    f = deep / "file.txt"
    f.write_text("x")
    assert repo_root(str(deep)) == str(root)
    assert repo_root(str(f)) == str(root)
    nogit = tmp_path / "plain" / "dir"
    assert repo_root(str(nogit)) == str(nogit)
    assert repo_root("") == ""


def test_approval_prefix_by_scope(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    sub = root / "sub"
    sub.mkdir()
    a = _proc(cwd=str(sub))
    for scope in ("session", "24h", "forever"):
        assert approval_prefix(a, scope) == ""
    assert approval_prefix(a, "this-repo") == str(root)
    w = _write(str(root / ".claude" / "settings.json"))
    assert approval_prefix(w, "this-repo") == str(root / ".claude" / "settings.json")
    with pytest.raises(ValueError):
        approval_prefix(a, "weekly")


def test_candidate_prefixes_global_first_then_parents():
    got = candidate_prefixes("/a/b/c")
    assert got[0] == ""
    assert got[1:] == ["/a/b/c", "/a/b", "/a", "/"]
    assert candidate_prefixes("") == [""]
