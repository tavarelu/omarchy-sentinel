from datetime import timedelta
from pathlib import Path
import tomllib

from sentinel.action import load_pause_max
from sentinel.notify import NotifyPolicy, load_policy

ROOT = Path(__file__).resolve().parents[1]


def test_config_template_parses_and_matches_code_defaults():
    path = ROOT / "packaging" / "config.toml"
    with path.open("rb") as f:
        data = tomllib.load(f)
    assert "notify" in data and "kill" in data
    assert load_policy(path) == NotifyPolicy()


def test_config_template_documents_pause_max_matching_default():
    path = ROOT / "packaging" / "config.toml"
    with path.open("rb") as f:
        data = tomllib.load(f)
    assert data["notify"].get("pause_max") == "24h"
    assert load_pause_max(path) == timedelta(hours=24)
