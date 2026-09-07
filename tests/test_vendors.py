from __future__ import annotations

from sentinel.rules import evaluate_process, extract_bypass_flags
from sentinel.vendors import VENDORS, redact_argv


def test_every_vendor_has_basenames():
    assert VENDORS, "vendor table must not be empty"
    for vendor in VENDORS:
        assert vendor.basenames, f"{vendor.name} has no basenames"
        assert all(isinstance(b, str) and b for b in vendor.basenames)


# ---------------------------------------------------------------- vendor table


def test_extract_bypass_flags_always_approve():
    # grok --help (this machine, 2026-09-07): "--always-approve  Auto-approve
    # all tool executions".
    assert extract_bypass_flags(["grok", "--always-approve"])


def test_extract_bypass_flags_permission_mode_dontask():
    flags = extract_bypass_flags(["grok", "--permission-mode", "dontAsk"])
    assert flags == ["--permission-mode=dontAsk"]


def test_extract_bypass_flags_codex_dangerous_bypass():
    assert extract_bypass_flags(
        ["codex", "--dangerously-bypass-approvals-and-sandbox"]
    )


def test_extract_bypass_flags_gemini_yolo():
    assert extract_bypass_flags(["gemini", "--yolo"])


def test_extract_bypass_flags_claude_plan_mode_not_bypass():
    # Negative control: --permission-mode is only flagged for bypass-meaning
    # values (bypassPermissions, dontAsk), not every value it accepts.
    assert extract_bypass_flags(["claude", "--permission-mode", "plan"]) == []


def test_extract_bypass_flags_is_vendor_scoped_or_not():
    # extract_bypass_flags unions every vendor's argv_bypass regardless of
    # cmdline[0] (mirrors today's global DEFAULT_BYPASS_FLAGS behavior) — a
    # codex flag run under grok's argv[0] still detects.
    assert extract_bypass_flags(
        ["grok", "--dangerously-bypass-approvals-and-sandbox"]
    )


def test_extract_bypass_flags_permission_mode_bypasspermissions_reports_pair():
    flags = extract_bypass_flags(["claude", "--permission-mode", "bypassPermissions"])
    assert flags == ["--permission-mode=bypassPermissions"]
    # And it is not double-counted via the bare DEFAULT_BYPASS_FLAGS token.
    assert flags.count("bypassPermissions") == 0


def test_extract_bypass_flags_still_detects_existing_bare_tokens():
    for flag in ("bypassPermissions", "--yolo", "trust-all", "--trust-all"):
        assert extract_bypass_flags(["codex", flag]) == [flag]


# -------------------------------------------------------------------- redact_argv


def test_redact_argv_api_key_flag_value_pair():
    out, redacted = redact_argv(["claude", "--api-key", "sk-test-123"])
    assert out == ["claude", "--api-key", "<redacted>"]
    assert redacted is True


def test_redact_argv_embedded_equals_form():
    out, redacted = redact_argv(["claude", "--token=sk-test-123"])
    assert out == ["claude", "--token=<redacted>"]
    assert redacted is True


def test_redact_argv_bare_secret_token():
    out, redacted = redact_argv(["claude", "sk-ant-api03-abcdEXAMPLE"])
    assert redacted is True
    assert "sk-ant-api03-abcdEXAMPLE" not in out
    assert "<redacted>" in out


def test_redact_argv_no_secret_no_change():
    assert redact_argv(["claude", "--yolo", "do", "stuff"]) == (
        ["claude", "--yolo", "do", "stuff"],
        False,
    )


def test_redact_argv_false_positive_guard():
    # "--author" contains "auth" only as a substring, not as its own
    # component — must not be treated as a secret-bearing flag.
    out, redacted = redact_argv(["claude", "--author", "Jane"])
    assert out == ["claude", "--author", "Jane"]
    assert redacted is False


def test_redact_argv_is_vendor_independent():
    # Signature check: no vendor/basename parameter (W3-04 reuses this for
    # child-process argv without knowing the vendor).
    redact_argv(["anything", "--secret", "x"])


# --------------------------------------------------- wired into evaluate_process


def test_evaluate_process_redacts_secret_and_sets_evidence_flag():
    alert = evaluate_process(
        ["claude", "--api-key", "sk-test", "--yolo"],
        "/usr/bin/claude",
        "/tmp",
    )
    assert alert is not None
    assert alert.evidence.get("redacted") is True
    assert "sk-test" not in alert.cmdline
    import json

    assert "sk-test" not in json.dumps(alert.evidence)


def test_evaluate_process_no_secret_no_redacted_flag():
    alert = evaluate_process(["claude", "--yolo"], "/usr/bin/claude", "/tmp")
    assert alert is not None
    assert not alert.evidence.get("redacted")
