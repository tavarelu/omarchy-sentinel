from unittest.mock import MagicMock

from sentinel.investigate import format_detail, page_detail
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
