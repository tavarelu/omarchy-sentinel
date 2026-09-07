"""Subprocess wrapper around scripts/install-cli.sh (bash, not Python).

Never touches the real HOME or ~/.local/bin — every invocation points
SENTINEL_VENV and SENTINEL_BIN_DIR at tmp_path fixtures.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "install-cli.sh"
CLIS = ("sentinel", "sentinel-action", "sentinel-scout")


def _fake_venv(tmp_path: Path) -> Path:
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    for name in CLIS:
        target = venv / "bin" / name
        target.write_text("#!/usr/bin/env bash\necho fake\n")
        target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return venv


def _run(venv: Path, bin_dir: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["SENTINEL_VENV"] = str(venv)
    env["SENTINEL_BIN_DIR"] = str(bin_dir)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_dry_run_is_the_default_and_creates_nothing(tmp_path):
    venv = _fake_venv(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run(venv, bin_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "would link" in result.stdout
    assert not bin_dir.exists() or list(bin_dir.iterdir()) == []


def test_apply_symlinks_all_three_clis(tmp_path):
    venv = _fake_venv(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run(venv, bin_dir, "--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    for name in CLIS:
        link = bin_dir / name
        assert link.is_symlink()
        assert Path(os.readlink(link)) == venv / "bin" / name


def test_idempotent_over_existing_correct_symlink(tmp_path):
    venv = _fake_venv(tmp_path)
    bin_dir = tmp_path / "bin"
    _run(venv, bin_dir, "--apply")
    before = {n: os.readlink(bin_dir / n) for n in CLIS}
    result = _run(venv, bin_dir, "--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "already linked" in result.stdout
    assert not any(".sentinel-bak." in p.name for p in bin_dir.iterdir())
    after = {n: os.readlink(bin_dir / n) for n in CLIS}
    assert before == after


def test_backs_up_non_symlink_file(tmp_path):
    venv = _fake_venv(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    plain = bin_dir / "sentinel"
    plain.write_text("not a symlink")
    result = _run(venv, bin_dir, "--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    backups = [p for p in bin_dir.iterdir() if ".sentinel-bak." in p.name]
    assert len(backups) == 1
    assert backups[0].read_text() == "not a symlink"
    assert (bin_dir / "sentinel").is_symlink()


def test_shellcheck_clean_if_available():
    if shutil.which("shellcheck") is None:
        import pytest

        pytest.skip("shellcheck is not installed on this machine (UNVERIFIED, not FAIL)")
    result = subprocess.run(
        ["shellcheck", str(SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
