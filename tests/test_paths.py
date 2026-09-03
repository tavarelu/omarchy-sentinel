from pathlib import Path
from sentinel.paths import state_dir, config_dir

def test_state_dir_under_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert state_dir() == tmp_path / "state" / "sentinel"
    assert config_dir() == tmp_path / "config" / "sentinel"
