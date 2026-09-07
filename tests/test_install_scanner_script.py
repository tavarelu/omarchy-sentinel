# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-scanner.sh"


def _text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_install_scanner_never_uses_sudo():
    # Check actual shell commands, not the script's own prose comments
    # (which legitimately say "never uses sudo").
    code_lines = [
        line
        for line in _text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert not any("sudo" in line for line in code_lines)


def test_install_scanner_pins_the_venv_path_and_tag():
    text = _text()
    assert "tav.sentinel/scanner" in text
    assert "git+https://github.com/NVIDIA/skillspector.git@v2.9.6" in text


def test_install_scanner_requires_explicit_yes():
    text = _text()
    lines = text.splitlines()
    yes_check = next(i for i, line in enumerate(lines) if '"${1:-}" != "--yes"' in line)
    pip_install = next(
        i
        for i, line in enumerate(lines)
        if line.strip().startswith('"$VENV_DIR/bin/pip" install "$PACKAGE"')
    )
    assert yes_check < pip_install


def test_install_scanner_never_executed_from_python_source():
    """Forbidden: 'never invoked automatically by any other code path.'

    Mentioning the script's path in a printed instruction (e.g. the
    missing-scanner message telling the user how to install it) is fine and
    required by REQ13; what must never happen is Python code *running* it.
    """
    for path in (ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "install-scanner.sh" not in line:
                continue
            assert "subprocess" not in line and "os.system" not in line and "Popen" not in line, (
                path,
                line,
            )


def test_install_scanner_is_executable():
    import os
    import stat

    mode = SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR
