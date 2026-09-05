"""Every test runs against a throwaway XDG tree.

Invariant: the suite never reads or writes the live ~/.config/sentinel or
~/.local/state/sentinel. Tests that need specific paths still override these.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    yield
