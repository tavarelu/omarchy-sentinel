# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import os


def config_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "sentinel"


def state_dir() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "sentinel"


def default_config_path() -> Path:
    return config_dir() / "config.toml"
