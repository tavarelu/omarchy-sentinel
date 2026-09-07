from __future__ import annotations

import socket
import subprocess

import pytest

from sentinel import journal
from sentinel.models import Alert


def _alert(**overrides) -> Alert:
    data = dict(
        rule="R-SELF",
        severity="high",
        summary="sentinel state written by an unknown process",
        pids=[],
        exe="",
        basename="",
        cmdline=[],
        cwd="/home/tav/Work/scratch",
        evidence={"event": "foreign-write", "path": "/p"},
    )
    data.update(overrides)
    return Alert.new(**data)


@pytest.fixture
def journal_sock(tmp_path, monkeypatch):
    sock_path = tmp_path / "journal.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(str(sock_path))
    sock.settimeout(2.0)
    monkeypatch.setattr(journal, "JOURNAL_SOCKET_PATH", sock_path)
    yield sock
    sock.close()


def _decode(datagram: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in datagram.decode("utf-8").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


def test_mirror_alert_sends_five_fields_over_native_socket(journal_sock):
    alert = _alert()
    journal.mirror_alert(alert)
    data, _addr = journal_sock.recvfrom(65536)
    fields = _decode(data)
    assert fields["SENTINEL_RULE"] == alert.rule
    assert fields["SENTINEL_ID"] == alert.id
    assert fields["SENTINEL_SEVERITY"] == alert.severity
    assert fields["SENTINEL_SUMMARY"] == alert.summary
    assert fields["SENTINEL_LOCATION"] == alert.cwd


def test_mirror_alert_location_falls_back_to_first_path(journal_sock):
    alert = _alert(cwd="", paths=["/a/b"])
    journal.mirror_alert(alert)
    data, _addr = journal_sock.recvfrom(65536)
    fields = _decode(data)
    assert fields["SENTINEL_LOCATION"] == "/a/b"


def test_mirror_alert_never_leaks_body_fields(journal_sock):
    alert = _alert(
        cmdline=["claude", "--token", "sekret123"],
        evidence={"event": "foreign-write", "path": "/p", "raw_snippet": "do not leak me"},
    )
    journal.mirror_alert(alert)
    data, _addr = journal_sock.recvfrom(65536)
    assert b"sekret123" not in data
    assert b"raw_snippet" not in data
    assert b"do not leak me" not in data


def test_mirror_alert_falls_back_to_logger_when_socket_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_SOCKET_PATH", tmp_path / "no-such-socket")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))

        class R:
            returncode = 0

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    alert = _alert()
    journal.mirror_alert(alert)
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "logger"
    assert "-t" in argv and "sentinel" in argv
    joined = " ".join(argv)
    assert alert.rule in joined
    assert alert.id in joined


def test_mirror_alert_swallows_logger_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_SOCKET_PATH", tmp_path / "no-such-socket")

    def boom(*a, **k):
        raise OSError("no logger")

    monkeypatch.setattr(subprocess, "run", boom)
    journal.mirror_alert(_alert())  # must not raise
