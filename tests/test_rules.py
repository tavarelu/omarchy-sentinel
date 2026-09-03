from pathlib import Path

from sentinel.rules import evaluate_process, evaluate_write


def test_rbypass_detects_skip_permissions():
    alert = evaluate_process(
        ["claude", "--dangerously-skip-permissions"],
        "/usr/bin/claude",
        "/tmp/scratch",
    )
    assert alert is not None
    assert alert.rule == "R-BYPASS"
    assert alert.severity == "high"
    assert alert.basename == "claude"
    assert alert.exe == "/usr/bin/claude"
    assert alert.cwd == "/tmp/scratch"
    assert "--dangerously-skip-permissions" in alert.evidence.get("flag", "")


def test_rbypass_detects_other_flags():
    for flag in ("bypassPermissions", "--yolo", "trust-all", "--trust-all"):
        alert = evaluate_process(["codex", flag], "/usr/bin/codex", "/tmp")
        assert alert is not None, flag
        assert alert.rule == "R-BYPASS"
        assert alert.evidence["flag"] == flag


def test_rbypass_extra_flags():
    alert = evaluate_process(
        ["claude", "--please-yolo"],
        "/usr/bin/claude",
        "/tmp",
        extra_bypass_flags=["--please-yolo"],
    )
    assert alert is not None and alert.rule == "R-BYPASS"


def test_rbypass_none_without_flags():
    assert (
        evaluate_process(["claude", "do", "stuff"], "/usr/bin/claude", "/tmp") is None
    )


def test_rself_on_sentinel_config(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("x=1\n")
    alert = evaluate_write(
        p, writer_pid=9, writer_exe="/usr/bin/nano", self_paths=[tmp_path]
    )
    assert alert is not None and alert.rule == "R-SELF"
    assert alert.severity == "high"
    assert alert.writer_pid == 9
    assert alert.paths == [str(p.resolve())]


def test_rself_alerts_even_from_editor(tmp_path):
    p = tmp_path / "allowlist.json"
    p.write_text("{}\n")
    alert = evaluate_write(
        p, writer_pid=1, writer_exe="/usr/bin/vim", self_paths=[tmp_path]
    )
    assert alert is not None and alert.rule == "R-SELF"


def test_rself_non_sentinel_writers_alert(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("x=1\n")
    for exe in ("/usr/bin/nano", "/usr/bin/touch"):
        alert = evaluate_write(
            p, writer_pid=9, writer_exe=exe, self_paths=[tmp_path]
        )
        assert alert is not None and alert.rule == "R-SELF", exe


def test_rself_sentinel_writer_ignored(tmp_path):
    p = tmp_path / "watchlist.json"
    p.write_text("{}\n")
    for exe in (
        "/usr/bin/sentinel",
        "/usr/local/bin/sentinel-daemon",
        "/home/x/.local/bin/sentinel-scout",
    ):
        assert (
            evaluate_write(p, writer_pid=1, writer_exe=exe, self_paths=[tmp_path])
            is None
        ), exe


def test_rself_python_module_sentinel_ignored(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("x=1\n")
    assert (
        evaluate_write(
            p,
            writer_pid=2,
            writer_exe="/usr/bin/python3",
            self_paths=[tmp_path],
            writer_cmdline=["python3", "-m", "sentinel.cli", "scout"],
        )
        is None
    )


def test_rhook_write_non_editor(tmp_path):
    watch = tmp_path / "hooks"
    watch.mkdir()
    p = watch / "pre.sh"
    p.write_text("#!/bin/sh\n")
    alert = evaluate_write(
        p,
        writer_pid=42,
        writer_exe="/usr/bin/python3",
        watch_paths=[watch],
    )
    assert alert is not None and alert.rule == "R-HOOK-WRITE"
    assert alert.severity == "high"
    assert alert.writer_pid == 42


def test_rhook_write_ignored_for_editor(tmp_path):
    watch = tmp_path / "settings"
    watch.mkdir()
    p = watch / "settings.json"
    p.write_text("{}\n")
    alert = evaluate_write(
        p,
        writer_pid=7,
        writer_exe="/usr/bin/nano",
        watch_paths=[watch],
    )
    assert alert is None


def test_write_outside_lists_is_none(tmp_path):
    other = tmp_path / "unrelated.txt"
    other.write_text("x\n")
    assert (
        evaluate_write(
            other,
            writer_pid=1,
            writer_exe="/usr/bin/python3",
            self_paths=[tmp_path / "sentinel"],
            watch_paths=[tmp_path / "hooks"],
        )
        is None
    )
