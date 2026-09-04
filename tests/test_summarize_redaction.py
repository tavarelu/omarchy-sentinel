import ast
from pathlib import Path

from sentinel.models import Alert


FORBIDDEN_BUNDLE_KEYS = frozenset(
    {
        "cmdline",
        "transcript",
        "transcripts",
        "token",
        "tokens",
        "auth",
        "env",
        "body",
        "bodies",
        "content",
        "file_body",
        "file_bodies",
        "api_key",
        "summary",
        "evidence",
        "exe",
        "pids",
        "id",
        "ts",
    }
)

ALLOWED_BUNDLE_KEYS = frozenset(
    {
        "rule",
        "severity",
        "basename",
        "flags",
        "cwd",
        "parent_basename",
        "paths",
        "hashes",
        "writer_pid",
    }
)


def _alert(**overrides) -> Alert:
    data = dict(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with bypassPermissions — secret transcript",
        pids=[100, 101],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd="/home/tav/Work/scratch",
        evidence={
            "flag": "--dangerously-skip-permissions",
            "flags": ["--dangerously-skip-permissions"],
            "token": "sk-secret-should-never-leave",
            "env": {"API_KEY": "leak"},
            "body": "file body contents",
            "transcript": "user said hello",
        },
        parent={"pid": 1200, "exe": "/usr/bin/foot"},
        paths=["/home/tav/.claude/settings.json"],
        writer_pid=9,
        hashes={"/home/tav/.claude/settings.json": "sha256:abc"},
    )
    data.update(overrides)
    return Alert.new(**data)


def test_build_redacted_bundle_only_allowed_keys():
    from sentinel.summarize import build_redacted_bundle

    bundle = build_redacted_bundle(_alert())
    assert set(bundle.keys()) <= ALLOWED_BUNDLE_KEYS
    assert set(bundle.keys()) & FORBIDDEN_BUNDLE_KEYS == set()
    assert bundle["rule"] == "R-BYPASS"
    assert bundle["severity"] == "high"
    assert bundle["basename"] == "claude"
    assert bundle["flags"] == ["--dangerously-skip-permissions"]
    assert bundle["cwd"] == "/home/tav/Work/scratch"
    assert bundle["parent_basename"] == "foot"
    assert bundle["paths"] == ["settings.json"] or bundle["paths"] == [
        "/home/tav/.claude/settings.json"
    ]
    assert bundle["hashes"] == {"/home/tav/.claude/settings.json": "sha256:abc"}
    assert bundle["writer_pid"] == 9
    blob = str(bundle)
    assert "sk-secret" not in blob
    assert "file body" not in blob
    assert "user said hello" not in blob
    assert "API_KEY" not in blob
    assert "--dangerously-skip-permissions" in blob or "flags" in bundle


def test_build_redacted_bundle_omits_none_parent_and_empty():
    from sentinel.summarize import build_redacted_bundle

    alert = _alert(parent=None, paths=None, hashes=None, writer_pid=None, evidence={})
    alert.cmdline = ["claude"]
    bundle = build_redacted_bundle(alert)
    assert "cmdline" not in bundle
    assert bundle.get("parent_basename") in (None, "")
    assert bundle.get("writer_pid") is None


def test_summarize_uses_injectable_http_and_returns_text(monkeypatch, tmp_path):
    from sentinel.summarize import summarize

    monkeypatch.setenv("SENTINEL_API_KEY", "test-key")
    seen: dict = {}

    def fake_http(bundle, *, api_key: str):
        seen["bundle"] = bundle
        seen["api_key"] = api_key
        assert "cmdline" not in bundle
        assert "token" not in bundle
        return "plain-language digest"

    out = summarize(_alert(), http_post=fake_http)
    assert out == "plain-language digest"
    assert seen["api_key"] == "test-key"
    assert set(seen["bundle"].keys()) <= ALLOWED_BUNDLE_KEYS


def test_summarize_failure_returns_none(monkeypatch):
    from sentinel.summarize import summarize

    monkeypatch.setenv("SENTINEL_API_KEY", "test-key")

    def boom(bundle, *, api_key: str):
        raise RuntimeError("network down")

    assert summarize(_alert(), http_post=boom) is None


def test_summarize_missing_api_key_returns_none(monkeypatch, tmp_path):
    from sentinel.summarize import summarize

    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert summarize(_alert(), http_post=lambda *a, **k: "x") is None


def test_api_key_from_config_file_mode_0600(monkeypatch, tmp_path):
    from sentinel.summarize import resolve_api_key, summarize

    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    key_path = tmp_path / "config" / "sentinel" / "api_key"
    key_path.parent.mkdir(parents=True)
    key_path.write_text("file-key\n", encoding="utf-8")
    key_path.chmod(0o600)
    assert resolve_api_key() == "file-key"

    def fake_http(bundle, *, api_key: str):
        assert api_key == "file-key"
        return "ok"

    assert summarize(_alert(), http_post=fake_http) == "ok"


def test_env_api_key_preferred_over_file(monkeypatch, tmp_path):
    from sentinel.summarize import resolve_api_key

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    key_path = tmp_path / "config" / "sentinel" / "api_key"
    key_path.parent.mkdir(parents=True)
    key_path.write_text("file-key\n", encoding="utf-8")
    key_path.chmod(0o600)
    monkeypatch.setenv("SENTINEL_API_KEY", "env-key")
    assert resolve_api_key() == "env-key"


def test_daemon_does_not_import_summarize_or_cloud_sdk():
    root = Path(__file__).resolve().parents[1] / "src" / "sentinel"
    daemon_src = (root / "daemon.py").read_text(encoding="utf-8")
    tree = ast.parse(daemon_src)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
                if node.module.startswith("sentinel."):
                    imported.add(node.module)
    assert "sentinel.summarize" not in imported
    assert "summarize" not in imported
    for banned in ("openai", "anthropic", "httpx", "requests", "groq"):
        assert banned not in imported
        assert banned not in daemon_src


def test_action_summarize_cli_success(monkeypatch, tmp_path, capsys):
    from sentinel.cli import action_main
    from sentinel.store import append_alert

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("SENTINEL_API_KEY", "k")
    alert = _alert()
    append_alert(alert)
    monkeypatch.setattr(
        "sentinel.summarize.summarize",
        lambda alert, **k: "cloud digest here",
    )
    assert action_main([alert.id, "summarize"]) == 0
    out = capsys.readouterr().out
    assert "cloud digest here" in out
    assert "sk-secret" not in out


def test_action_summarize_cli_failure_prints_local_detail(monkeypatch, tmp_path, capsys):
    from sentinel.cli import action_main
    from sentinel.store import append_alert

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    monkeypatch.setattr("sentinel.summarize.summarize", lambda alert, **k: None)
    assert action_main(["summarize", alert.id]) == 0
    out = capsys.readouterr().out
    assert alert.rule in out
    assert alert.cwd in out
    assert alert.basename in out


def test_menu_lists_summarize(monkeypatch, tmp_path, capsys):
    from sentinel.cli import action_main
    from sentinel.store import append_alert

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    alert = _alert()
    append_alert(alert)
    assert action_main([alert.id, "menu"]) == 0
    out = capsys.readouterr().out.lower()
    assert "summarize" in out
