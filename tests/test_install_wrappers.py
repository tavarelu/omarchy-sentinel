"""Subprocess wrapper around scripts/install-wrappers.sh (bash, not Python).

pytest does not collect .sh files directly, so this drives the script the
same way the packet's Acceptance block does: real subprocess invocations
against a temp SENTINEL_BIN_DIR and a synthetic PATH, never the real HOME
or ~/.local/bin (Forbidden: never run install-*.sh without --dry-run or a
temp SENTINEL_BIN_DIR).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "install-wrappers.sh"


def _make_stub(path: Path) -> None:
    path.write_text("#!/usr/bin/env bash\necho fake\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run(bin_dir: Path, path: str, home: Path, *names: str) -> subprocess.CompletedProcess:
    # A hermetic, rc-file-free HOME: `bash -lc` (what a real toast click and
    # this installer's own verification step both run through) sources
    # login shell profile files, and this machine's ~/.local/bin/env
    # prepends its own PATH spelling whenever HOME has one to source. A
    # fresh tmp_path HOME has none, so the injected PATH is not reordered —
    # verified directly against this script rather than assumed.
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["SENTINEL_BIN_DIR"] = str(bin_dir)
    env["PATH"] = path
    return subprocess.run(
        ["bash", str(SCRIPT), *names],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_shadowed_shim_exits_1_and_prints_both_fixes(tmp_path):
    fakemise = tmp_path / "fakemise"
    fakemise.mkdir()
    _make_stub(fakemise / "claude")
    bin_dir = tmp_path / "sb"
    home = tmp_path / "home"
    home.mkdir()
    real_path = f"{fakemise}:{bin_dir}:/usr/bin:/bin"

    result = _run(bin_dir, real_path, home, "claude")

    assert result.returncode == 1, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "$BIN_DIR" in combined and "before the mise entries" in combined
    assert "SENTINEL_BIN_DIR" in combined
    # ~/.local/share/mise/shims must never be offered as a fix (packet: "is
    # NOT acceptable") — it appears only inside that explicit refusal line.
    assert "mise/shims is NOT acceptable" in combined


def test_bin_dir_first_exits_0_and_prints_verified(tmp_path):
    fakemise = tmp_path / "fakemise"
    fakemise.mkdir()
    _make_stub(fakemise / "claude")
    bin_dir = tmp_path / "sb"
    home = tmp_path / "home"
    home.mkdir()
    real_path = f"{bin_dir}:{fakemise}:/usr/bin:/bin"

    result = _run(bin_dir, real_path, home, "claude")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "shadowed" not in (result.stdout + result.stderr)
    assert "verified" in result.stdout


def test_shellcheck_clean_if_available(tmp_path):
    if shutil.which("shellcheck") is None:
        import pytest

        pytest.skip("shellcheck is not installed on this machine (UNVERIFIED, not FAIL)")
    result = subprocess.run(
        ["shellcheck", str(SCRIPT), str(REPO_ROOT / "scripts" / "install-cli.sh")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
