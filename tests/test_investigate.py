import shlex
from unittest.mock import MagicMock

from sentinel.investigate import (
    SECTION_ORDER,
    action_lines,
    format_detail,
    page_detail,
    render_sections,
)
from sentinel.models import Alert


def _alert(**overrides) -> Alert:
    data = dict(
        rule="R-CONFIG",
        severity="medium",
        summary="settings.json changed",
        pids=[42],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--print"],
        cwd="/home/tav/Work/scratch",
        evidence={
            "flag": "settings-write",
            "token": "sk-secret-should-not-appear",
            "auth": {"refresh": "leak"},
            "auth_body": "raw-auth-json",
            "body": "file-contents-leak",
            "access_token": "also-secret",
            "ok_meta": "safe",
        },
        paths=["/home/tav/.claude/settings.json", "/home/tav/.claude/auth.json"],
        hashes={
            "/home/tav/.claude/settings.json": "sha256:abc",
            "/home/tav/.claude/auth.json": "sha256:def",
        },
        parent={"pid": 1, "exe": "foot", "token": "parent-secret"},
        writer_pid=99,
    )
    data.update(overrides)
    return Alert.new(**data)


def test_format_detail_includes_core_fields():
    alert = _alert()
    text = format_detail(alert)
    assert alert.rule in text
    assert " ".join(alert.cmdline) in text
    assert alert.cwd in text
    assert "/home/tav/.claude/settings.json" in text
    assert "sha256:abc" in text
    assert "sha256:def" in text
    assert str(alert.writer_pid) in text
    assert "foot" in text


def test_format_detail_excludes_token_auth_body_keys():
    alert = _alert()
    text = format_detail(alert)
    assert "sk-secret-should-not-appear" not in text
    assert "raw-auth-json" not in text
    assert "file-contents-leak" not in text
    assert "also-secret" not in text
    assert "parent-secret" not in text
    assert "leak" not in text
    # path names mentioning auth.json are metadata and must remain
    assert "/home/tav/.claude/auth.json" in text
    assert "ok_meta" in text
    assert "safe" in text


def test_page_detail_uses_pager_env(monkeypatch):
    alert = _alert()
    calls: list[object] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return MagicMock(returncode=0)

    monkeypatch.setenv("PAGER", "mycustompager")
    monkeypatch.setattr("sentinel.investigate.subprocess.run", fake_run)
    monkeypatch.setattr("sentinel.investigate.sys.stdin", MagicMock(isatty=lambda: True))
    monkeypatch.setattr("sentinel.investigate.sys.stdout", MagicMock(isatty=lambda: True))

    page_detail(alert)
    assert calls, "expected pager subprocess"
    argv, kwargs = calls[0]
    assert argv[0] == "mycustompager"
    assert format_detail(alert) in (kwargs.get("input") or "")


def test_page_detail_defaults_to_less(monkeypatch):
    alert = _alert()
    calls: list[object] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return MagicMock(returncode=0)

    monkeypatch.delenv("PAGER", raising=False)
    monkeypatch.setattr("sentinel.investigate.subprocess.run", fake_run)
    monkeypatch.setattr("sentinel.investigate.sys.stdin", MagicMock(isatty=lambda: True))
    monkeypatch.setattr("sentinel.investigate.sys.stdout", MagicMock(isatty=lambda: True))

    page_detail(alert)
    assert calls[0][0] == "less"


def test_page_detail_prints_when_not_tty(monkeypatch, capsys):
    alert = _alert()
    monkeypatch.setattr(
        "sentinel.investigate.sys.stdout",
        MagicMock(isatty=lambda: False),
    )
    monkeypatch.setattr(
        "sentinel.investigate.subprocess.run",
        MagicMock(side_effect=AssertionError("pager must not run")),
    )
    printed: list[str] = []

    def fake_print(*args, **kwargs):
        end = kwargs.get("end", "\n")
        printed.append(" ".join(str(a) for a in args) + end)

    monkeypatch.setattr("builtins.print", fake_print)
    page_detail(alert)
    assert printed
    assert printed[0] == format_detail(alert)


def _bypass_sampler(**overrides) -> Alert:
    data = dict(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[4242],
        exe="/x/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd="/tmp/work",
        evidence={
            "schema": 2,
            "flag": "--yolo",
            "flags": ["--yolo"],
            "starttime": 7,
            "instance": "4242:7",
            "source": "sampler",
        },
    )
    data.update(overrides)
    return Alert.new(**data)


def _bypass_launch(**overrides) -> Alert:
    data = dict(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[4242],
        exe="/x/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd="/tmp/work",
        evidence={
            "schema": 2,
            "flag": "--yolo",
            "flags": ["--yolo"],
            "starttime": 7,
            "instance": "4242:7",
            "source": "launches",
            "launch_ts": "2026-09-05T12:00:00+00:00",
        },
    )
    data.update(overrides)
    return Alert.new(**data)


def _hook_write(**overrides) -> Alert:
    path = "/tmp/hooks/settings.json"
    data = dict(
        rule="R-HOOK-WRITE",
        severity="high",
        summary="write to watched path by unknown",
        pids=[],
        exe="",
        basename="",
        cmdline=[],
        cwd="",
        evidence={"schema": 2, "path": path},
        paths=[path],
        hashes={path: "abc123def"},
        writer_pid=None,
    )
    data.update(overrides)
    return Alert.new(**data)


def _self_foreign(**overrides) -> Alert:
    path = "/tmp/sentinel-state/alerts.jsonl"
    data = dict(
        rule="R-SELF",
        severity="high",
        summary="foreign write to sentinel state",
        pids=[],
        exe="",
        basename="",
        cmdline=[],
        cwd="",
        evidence={
            "schema": 2,
            "event": "foreign-write",
            "path": path,
            "size_before": 100,
            "size_after": 140,
        },
        paths=[path],
    )
    data.update(overrides)
    return Alert.new(**data)


def _child_shell(**overrides) -> Alert:
    data = dict(
        rule="R-CHILD-SHELL",
        severity="high",
        summary="claude spawned interactive bash",
        pids=[100, 200],
        exe="/usr/bin/bash",
        basename="bash",
        cmdline=["bash", "-i"],
        cwd="/tmp/work",
        parent={"pid": 100, "exe": "/usr/bin/claude", "basename": "claude"},
        evidence={
            "schema": 2,
            "kind": "interactive-shell",
            "child_pids": [200],
            "parent_pid": 100,
        },
    )
    data.update(overrides)
    return Alert.new(**data)


def _allow_expire(**overrides) -> Alert:
    data = dict(
        rule="R-ALLOW-EXPIRE",
        severity="medium",
        summary="24h approval expired and the pattern recurred",
        pids=[],
        exe="",
        basename="claude",
        cmdline=[],
        cwd="/tmp/work",
        evidence={
            "schema": 2,
            "fingerprint": "deadbeef" * 8,
            "original_rule": "R-BYPASS",
            "expired_scope": "24h",
        },
    )
    data.update(overrides)
    return Alert.new(**data)


def _new_agent_scan(**overrides) -> Alert:
    report = "/tmp/skillspector-report.md"
    root = "/home/tav/.claude/skills/new-skill"
    data = dict(
        rule="R-NEW-AGENT",
        severity="medium",
        summary="new skill root appeared",
        pids=[],
        exe="",
        basename="",
        cmdline=[],
        cwd="",
        paths=[root],
        evidence={
            "schema": 2,
            "path": root,
            "report": report,
            "scan": {
                "tool": "skillspector",
                "version": "0.4.0",
                "risk_score": 8.5,
                "verdict": "review",
                "counts": {"high": 1, "medium": 2},
                "top": [
                    {
                        "title": "eval in installer",
                        "file": "skill.md",
                        "line": 12,
                        "body": "SECRET-BODY-MUST-NOT-APPEAR",
                    }
                ],
            },
        },
    )
    data.update(overrides)
    return Alert.new(**data)


def _legacy_v1(**overrides) -> Alert:
    data = dict(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with --yolo",
        pids=[9],
        exe="/x/claude",
        basename="claude",
        cmdline=["claude", "--yolo"],
        cwd="/tmp/work",
        evidence={"flag": "--yolo", "flags": ["--yolo"]},
    )
    data.update(overrides)
    return Alert.new(**data)


def _joined(alert: Alert, **kwargs) -> str:
    parts: list[str] = []
    for section in render_sections(alert, **kwargs):
        parts.append(section.title)
        parts.extend(section.lines)
    return "\n".join(parts)


def _section(alert: Alert, title: str, **kwargs):
    for section in render_sections(alert, **kwargs):
        if section.title == title:
            return section
    raise AssertionError(f"missing section {title!r}")


def test_sections_in_order(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    sections = render_sections(_bypass_sampler())
    assert tuple(s.title for s in sections) == SECTION_ORDER


def test_rbypass_sampler_cites_proc_and_flag_index(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _bypass_sampler()
    text = _joined(alert)
    assert "flag[1]" in text
    assert "--yolo" in text
    assert "/proc/4242/cmdline at detection" in text
    assert "4242:7" in text
    assert "starttime" in text
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    assert "ps -o pid,lstart,args -p 4242" in verify
    assert "/proc/4242/cmdline" in verify
    assert f'"id":"{alert.id}"' in verify
    limits = "\n".join(_section(alert, "Limits").lines)
    assert "sampler sees a process up to" in limits
    assert "kill re-checks the start time" in limits


def test_rbypass_launch_cites_launch_record(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _bypass_launch()
    text = _joined(alert)
    assert "launches.jsonl record ts=2026-09-05T12:00:00+00:00" in text
    assert "launch_ts" in text
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    assert '"pid":4242' in verify
    assert "launches.jsonl" in verify


def test_rhook_write_facts_verify_and_limits(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _hook_write()
    text = _joined(alert)
    assert "/tmp/hooks/settings.json" in text
    assert "abc123def" in text
    assert "unknown" in text
    assert "inotify event on the parent dir" in text
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    assert "stat -c '%s %y %a'" in verify
    assert "sha256sum" in verify
    assert "compare with abc123def" in verify
    assert "watchlist.json" in verify
    limits = "\n".join(_section(alert, "Limits").lines)
    assert "writer unknown: inotify reports no PID (writer attribution is W6-04)" in limits


def test_rself_foreign_write_journal_query(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _self_foreign()
    text = _joined(alert)
    assert "foreign-write" in text
    assert "size_before" in text
    assert "100" in text
    assert "140" in text
    logs = "\n".join(_section(alert, "Where the logs are").lines)
    assert "journalctl --user -t sentinel" in logs
    assert f"SENTINEL_ID={alert.id}" in logs
    assert "journalctl --user -u sentinel.service --since" in logs


def test_rchild_shell_renders_chain_and_kill_target(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _child_shell()
    text = _joined(alert)
    assert "interactive-shell" in text
    assert "claude" in text
    assert "100" in text
    assert "200" in text
    assert "bash -i" in text or "bash', '-i" in text
    assert "/proc tree at detection" in text
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    assert "ps -o pid,ppid,lstart,args -p 100,200" in verify
    assert "/proc/200/stat" in verify
    actions = "\n".join(_section(alert, "Actions").lines)
    assert "kill [--session]" in actions
    limits = "\n".join(_section(alert, "Limits").lines)
    assert "interactive-shell detection is argv-based" in limits


def test_rallow_expire_shows_fingerprint_and_original_rule(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _allow_expire()
    text = _joined(alert)
    fp = "deadbeef" * 8
    assert fp in text
    assert "R-BYPASS" in text
    assert "24h" in text
    assert "allowlist.json entry removed" in text
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    assert "grep -c" in verify
    assert fp in verify
    assert "expect 0" in verify
    assert "sentinel-action list" in verify


def test_rnew_agent_scan_shows_score_verdict_report_no_bodies(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _new_agent_scan()
    text = _joined(alert)
    assert "skillspector" in text
    assert "0.4.0" in text
    assert "8.5" in text
    assert "review" in text
    assert "eval in installer" in text
    assert "skill.md" in text
    assert "12" in text
    assert "/tmp/skillspector-report.md" in text
    assert "SECRET-BODY-MUST-NOT-APPEAR" not in text
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    assert "sed -n 1,40p" in verify
    assert "/tmp/skillspector-report.md" in verify
    assert "skillspector scan" in verify
    assert "--no-llm" in verify
    limits = "\n".join(_section(alert, "Limits").lines)
    assert "static scan only unless the LLM stage was requested" in limits


def test_legacy_alert_renders_with_limits_note(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _legacy_v1()
    sections = render_sections(alert)
    assert tuple(s.title for s in sections) == SECTION_ORDER
    limits = "\n".join(_section(alert, "Limits").lines)
    assert "recorded before evidence v2; some facts were not captured" in limits
    text = format_detail(alert)
    assert alert.id in text
    assert alert.rule in text


def test_verify_commands_are_quoted(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    path = "/tmp/a b'c"
    alert = _hook_write(
        paths=[path],
        hashes={path: "ffff"},
        evidence={"schema": 2, "path": path},
    )
    verify = "\n".join(_section(alert, "Verify it yourself").lines)
    quoted = shlex.quote(path)
    assert quoted in verify
    # Unquoted path with space+quote must not appear as a raw token.
    assert path not in verify


def test_where_logs_uses_xdg_state_home_and_line_number(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _bypass_sampler()
    logs = "\n".join(_section(alert, "Where the logs are", line_no=4).lines)
    state = tmp_path / "state" / "sentinel"
    assert str(state) in logs
    assert "alerts.jsonl" in logs
    assert "this alert: line 4" in logs
    assert "launches.jsonl" in logs
    assert "watchlist.json" in logs
    text = format_detail(alert, line_no=4)
    assert "this alert: line 4" in text
    assert str(state) in text


def test_actions_section_matches_menu(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    alert = _bypass_sampler()
    actions = _section(alert, "Actions")
    assert actions.lines == action_lines(alert)
    joined = "\n".join(actions.lines)
    assert f"sentinel-action {alert.id} approve --scope session|24h|this-repo|forever" in joined
    assert f"sentinel-action {alert.id} open" in joined
    assert f"sentinel-action {alert.id} open --logs" in joined
    assert f"sentinel-action {alert.id} summarize" in joined
    assert f"sentinel-action {alert.id} dismiss" in joined
    assert f"sentinel-action {alert.id} kill [--session]" in joined
    write = _hook_write()
    write_actions = "\n".join(action_lines(write))
    assert "kill" not in write_actions
