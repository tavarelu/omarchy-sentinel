from datetime import datetime, timedelta, timezone

from sentinel.allowlist import approve, clear_session, fingerprint, is_allowed


def test_this_repo_scope_matches_prefix_only(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    from sentinel.allowlist import fingerprint, approve, is_allowed
    fp = fingerprint("R-BYPASS", "claude", frozenset(["--dangerously-skip-permissions"]), "/home/tav/Work/scratch")
    approve(fp, "this-repo", "/home/tav/Work/scratch")
    assert is_allowed(fp, "/home/tav/Work/scratch/pkg") is True
    assert is_allowed(fp, "/home/tav/Work/prod") is False


def test_24h_scope_expires(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    clear_session()
    fp = fingerprint(
        "R-BYPASS",
        "claude",
        frozenset(["--dangerously-skip-permissions"]),
        "/home/tav/Work/scratch",
    )
    approve(fp, "24h", "/home/tav/Work/scratch")
    assert is_allowed(fp, "/home/tav/Work/scratch") is True
    expired = datetime.now(timezone.utc) + timedelta(hours=25)
    assert is_allowed(fp, "/home/tav/Work/scratch", now=expired) is False


def test_session_cleared_by_clear_session(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    clear_session()
    fp = fingerprint("R-BYPASS", "claude", frozenset(["--yolo"]), "/home/tav/Work/scratch")
    approve(fp, "session", "/home/tav/Work/scratch")
    assert is_allowed(fp, "/home/tav/Work/scratch") is True
    clear_session()
    assert is_allowed(fp, "/home/tav/Work/scratch") is False
