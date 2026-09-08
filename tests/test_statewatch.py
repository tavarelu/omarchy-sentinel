from __future__ import annotations

import json
import os
import socket

import pytest

from sentinel import statewatch
from sentinel.statewatch import StateLedger


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


def test_check_never_recorded_path_is_foreign(tmp_path):
    p = tmp_path / "f.json"
    p.write_text("hello")
    ledger = StateLedger()
    assert ledger.check(p) == "foreign"


def test_record_then_check_same_content_is_unchanged(tmp_path):
    p = tmp_path / "f.json"
    p.write_text("v1")
    ledger = StateLedger()
    ledger.record(p)
    assert ledger.check(p) == "unchanged"


def test_record_after_daemon_write_is_recognized_as_ours_then_unchanged(tmp_path):
    p = tmp_path / "f.json"
    p.write_text("v1")
    ledger = StateLedger()
    ledger.record(p)
    p.write_text("v2")
    ledger.record(p)
    assert ledger.check(p) == "unchanged"


def test_check_detects_foreign_write_after_baseline(tmp_path):
    p = tmp_path / "f.json"
    p.write_text("v1")
    ledger = StateLedger()
    ledger.record(p)
    p.write_text("v2")  # external overwrite, no record/announce
    assert ledger.check(p) == "foreign"


def test_announce_before_and_after_matches_actual_write_is_ours(tmp_path):
    p = tmp_path / "f.json"
    content = "expected content"
    digest = statewatch.sha256_bytes(content.encode())
    ledger = StateLedger()
    ledger.announce(p, digest)
    p.write_text(content)
    ledger.announce(p, digest)
    assert ledger.check(p) == "ours"


def test_announce_with_wrong_hash_is_foreign(tmp_path):
    p = tmp_path / "f.json"
    ledger = StateLedger()
    ledger.announce(p, statewatch.sha256_bytes(b"expected"))
    p.write_text("actual")
    assert ledger.check(p) == "foreign"


def test_cli_announce_reaches_daemon_over_control_socket(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    from sentinel.daemon import Daemon

    d = Daemon({"inotify": False, "notify": lambda a: None})
    p = statewatch.state_dir() / "allowlist.json"
    content = '{"entries":{}}'
    digest = statewatch.sha256_bytes(content.encode())
    statewatch.announce_write(p, digest)
    p.write_text(content)
    statewatch.announce_write(p, digest)
    d._drain_control_socket()
    assert d._ledger.check(p) == "ours"
    d.handle_write(p)
    from sentinel.store import iter_alerts

    assert list(iter_alerts()) == []


def test_control_socket_falls_back_to_nonce_file_when_daemon_down(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    p = statewatch.state_dir() / "allowlist.json"
    statewatch.announce_write(p, "a" * 64)  # no daemon listening
    nonce = statewatch.cli_writes_nonce_path()
    assert nonce.exists()
    line = json.loads(nonce.read_text().splitlines()[0])
    assert line["path"] == str(p)
    assert line["sha256"] == "a" * 64


def test_daemon_consumes_nonce_file_at_startup(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    state = statewatch.state_dir()
    state.mkdir(parents=True, exist_ok=True)
    p1 = state / "allowlist.json"
    p1.write_text('{"entries":{}}')
    p2 = state / "watchlist.json"
    p2.write_text('{"paths":[]}')
    nonce = statewatch.cli_writes_nonce_path()
    nonce.write_text(
        "\n".join(
            json.dumps({"path": str(p), "sha256": statewatch.sha256_file(p)})
            for p in (p1, p2)
        )
        + "\n"
    )
    ledger = StateLedger()
    statewatch.consume_cli_writes(ledger)
    assert ledger.check(p1) == "ours"
    assert ledger.check(p2) == "ours"
    assert not nonce.exists()


def test_malformed_datagram_is_dropped_and_counted(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    sock = statewatch.create_control_socket()
    assert sock is not None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"not json", str(statewatch.control_socket_path()))
            sender.sendto(
                json.dumps({"path": "/x"}).encode(), str(statewatch.control_socket_path())
            )
        ledger = StateLedger()
        statewatch.drain_control_socket(sock, ledger)
        assert ledger.dropped == 2
    finally:
        sock.close()


def test_datagram_with_extra_or_wrong_keys_is_dropped(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    sock = statewatch.create_control_socket()
    assert sock is not None
    try:
        target = statewatch.state_dir() / "allowlist.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"entries":{}}')  # something on disk to classify
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.sendto(
                json.dumps({"path": str(target), "sha256": "a" * 64, "pause": True}).encode(),
                str(statewatch.control_socket_path()),
            )
            sender.sendto(
                json.dumps({"action": "dismiss", "alert_id": "x"}).encode(),
                str(statewatch.control_socket_path()),
            )
        ledger = StateLedger()
        statewatch.drain_control_socket(sock, ledger)
        assert ledger.dropped == 2
        assert ledger.check(target) == "foreign"  # never applied as an announcement
    finally:
        sock.close()


def test_sender_pid_reaches_journal_record(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    sock = statewatch.create_control_socket()
    assert sock is not None
    try:
        recorded: list[dict] = []
        monkeypatch.setattr(statewatch, "mirror_event", lambda fields: recorded.append(fields))
        target = statewatch.state_dir() / "allowlist.json"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.sendto(
                json.dumps({"path": str(target), "sha256": "a" * 64}).encode(),
                str(statewatch.control_socket_path()),
            )
        ledger = StateLedger()
        statewatch.drain_control_socket(sock, ledger)
        assert len(recorded) == 1
        assert recorded[0]["SENTINEL_EVENT"] == "cli-announce"
        assert recorded[0]["SENTINEL_SENDER_PID"] == str(os.getpid())
    finally:
        sock.close()


def test_path_outside_state_dir_is_rejected(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    outside = tmp_path / "elsewhere" / "secret.txt"
    outside.parent.mkdir(parents=True)
    outside.write_text("not sentinel's")
    digest = statewatch.sha256_file(outside)
    sock = statewatch.create_control_socket()
    assert sock is not None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.sendto(
                json.dumps({"path": str(outside), "sha256": digest}).encode(),
                str(statewatch.control_socket_path()),
            )
        ledger = StateLedger()
        statewatch.drain_control_socket(sock, ledger)
        assert ledger.dropped == 1
        # No entry was applied that would make an arbitrary path classify 'ours'.
        assert ledger.check(outside) == "foreign"
    finally:
        sock.close()


def test_is_ignored_state_file():
    from sentinel.statewatch import is_ignored_state_file

    for name in (
        "alerts.lock",
        "alerts.jsonl.1",
        "control.sock",
        ".cli-writes",
        "alerts.jsonl.tmp",
        "allowlist.json.tmp",
        "allowlist-session.json.tmp",
        "watchlist.json.tmp",
        "pause_until.tmp",
        "health.json.tmp",
    ):
        assert is_ignored_state_file(name) is True

    for name in (
        "alerts.jsonl",
        "allowlist.json",
        "allowlist-session.json",
        "pause_until",
        "watchlist.json",
        "notify-prefs.json",
        "health.json",
    ):
        assert is_ignored_state_file(name) is False

