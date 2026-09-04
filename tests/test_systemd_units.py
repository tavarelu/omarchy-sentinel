from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT_DIR = ROOT / "track-b" / "systemd"
INSTALL = ROOT / "scripts" / "install-systemd.sh"


def _read(name: str) -> str:
    return (UNIT_DIR / name).read_text(encoding="utf-8")


def _active_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_sentinel_service_start_limit_and_on_failure():
    text = _read("sentinel.service")
    lines = _active_lines(text)
    assert "Restart=on-failure" in lines
    assert "RestartSec=5" in lines
    assert "MemoryMax=256M" in lines
    assert any(line.startswith("StartLimitBurst=") for line in lines)
    assert any(line.startswith("StartLimitIntervalSec=") for line in lines)
    assert "OnFailure=sentinel-unstable.service" in lines
    assert not any("enable --now sentinel.service" in line for line in lines)


def test_sentinel_unstable_oneshot_toasts_without_taking_down_track_a():
    text = _read("sentinel-unstable.service")
    lines = _active_lines(text)
    assert "Type=oneshot" in lines
    assert "Sentinel unstable" in text
    assert not any(line.startswith("WantedBy=") for line in lines)
    assert not any(line.startswith("Conflicts=") for line in lines)
    joined = "\n".join(lines).lower()
    assert "sentinel-health" not in joined
    assert "mask" not in joined


def test_install_systemd_copies_unstable_and_does_not_enable_daemon():
    text = INSTALL.read_text(encoding="utf-8")
    assert "sentinel-unstable.service" in text
    live_enables = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("echo"):
            continue
        if "enable --now sentinel.service" in stripped:
            live_enables.append(stripped)
        if "enable --now sentinel-unstable.service" in stripped:
            live_enables.append(stripped)
    assert live_enables == []
    assert "enable --now sentinel-inventory.timer" in text
