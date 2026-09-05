from __future__ import annotations

from sentinel.procinfo import instance_key, read_ppid, read_starttime


def _stat(root, pid, comm, ppid=1, starttime=777):
    d = root / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    # fields: pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt
    # majflt cmajflt utime stime cutime cstime priority nice threads itreal starttime ...
    tail = f"S {ppid} 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 {starttime} 1000 2000 18446744073709551615"
    (d / "stat").write_text(f"{pid} ({comm}) {tail}\n")


def test_starttime_and_ppid_with_awkward_comm(tmp_path):
    _stat(tmp_path, 42, "my proc (x) y", ppid=7, starttime=6315339)
    assert read_starttime(42, tmp_path) == 6315339
    assert read_ppid(42, tmp_path) == 7


def test_missing_or_malformed(tmp_path):
    assert read_starttime(99, tmp_path) is None
    (tmp_path / "5").mkdir()
    (tmp_path / "5" / "stat").write_text("garbage\n")
    assert read_starttime(5, tmp_path) is None
    assert read_ppid(5, tmp_path) is None


def test_instance_key_distinguishes_recycled_pid():
    assert instance_key(4242, 100) != instance_key(4242, 200)
    assert instance_key(4242, None) == "4242:?"


def test_real_proc_self_has_stable_starttime():
    import os

    a = read_starttime(os.getpid())
    b = read_starttime(os.getpid())
    assert a is not None and a == b
