from sentinel.models import Alert
from sentinel.store import append_alert, iter_alerts, update_alert_status

def test_append_and_read_alert(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    a = Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary="claude started with bypassPermissions",
        pids=[1234],
        exe="/usr/bin/claude",
        basename="claude",
        cmdline=["claude", "--dangerously-skip-permissions"],
        cwd="/home/tav/Work/scratch",
        evidence={"flag": "bypassPermissions"},
    )
    append_alert(a)
    rows = list(iter_alerts())
    assert len(rows) == 1
    assert rows[0].rule == "R-BYPASS"
    assert rows[0].status == "open"
    update_alert_status(a.id, "approved")
    assert list(iter_alerts())[0].status == "approved"
