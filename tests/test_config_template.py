from pathlib import Path
import tomllib

from sentinel.notify import NotifyPolicy, load_policy

ROOT = Path(__file__).resolve().parents[1]


def test_config_template_parses_and_matches_code_defaults():
    path = ROOT / "packaging" / "config.toml"
    with path.open("rb") as f:
        data = tomllib.load(f)
    assert "notify" in data and "kill" in data
    assert load_policy(path) == NotifyPolicy()
