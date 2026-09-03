from pathlib import Path

from sentinel.scout import scout, write_watchlist

FIXTURES = Path(__file__).parent / "fixtures" / "fake_home"


def test_scout_classifies_settings_hooks_auth_without_reading(monkeypatch):
    def boom(self, *args, **kwargs):
        raise AssertionError("Path.read_text must not be called")

    monkeypatch.setattr(Path, "read_text", boom)

    result = scout(FIXTURES)
    kinds = {entry["kind"] for entry in result["paths"]}

    assert "settings" in kinds
    assert "hooks" in kinds
    assert "auth" in kinds

    settings = next(e for e in result["paths"] if e["kind"] == "settings")
    assert settings["path"].endswith(".claude/settings.json")
    assert "size" in settings and "mtime" in settings

    hooks = next(e for e in result["paths"] if e["kind"] == "hooks")
    assert "hooks" in hooks["path"]

    auth = next(e for e in result["paths"] if e["kind"] == "auth")
    assert auth["path"].endswith(".codex/auth.json")


def test_scout_skips_missing_seeds_quietly():
    result = scout(FIXTURES, seeds=[".claude", ".missing-agent", ".codex"])
    paths = [e["path"] for e in result["paths"]]
    assert any(p.endswith(".claude/settings.json") for p in paths)
    assert any(p.endswith(".codex/auth.json") for p in paths)
    assert not any("missing-agent" in p for p in paths)


def test_write_watchlist_under_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    result = scout(FIXTURES)
    out = write_watchlist(result)
    assert out == tmp_path / "sentinel" / "watchlist.json"
    assert out.is_file()
    data = out.read_text(encoding="utf-8")
    assert "settings" in data
    assert "hooks" in data
    assert "auth" in data
