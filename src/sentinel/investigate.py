# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinel.models import Alert
from sentinel.paths import state_dir as xdg_state_dir

# Keys that look like token / auth / body secrets (not path *values*).
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(token|auth|password|secret|credential|refresh|api_?key|body)s?$",
    re.IGNORECASE,
)
_SENSITIVE_SUBSTR_RE = re.compile(
    r"(access_token|refresh_token|auth_body|file_body|id_token|"
    r"api_key|apikey|passwd|password|secret|credential)",
    re.IGNORECASE,
)

# Matches daemon.SAMPLER_MAX without importing the daemon module.
_SAMPLER_MAX_S = 5

SECTION_ORDER = (
    "What fired",
    "Evidence",
    "Verify it yourself",
    "Limits",
    "Where the logs are",
    "Actions",
)

RULE_TEXT: dict[str, str] = {
    "R-BYPASS": "a known agent binary started with a permission-bypass switch",
    "R-HOOK-WRITE": (
        "a file under a watched agent hooks, settings, mcp or auth root was "
        "written, and Sentinel could not attribute the writer"
    ),
    "R-SELF": "Sentinel's own config or state was changed, or a watched root vanished",
    "R-CHILD-SHELL": "an agent spawned a surprise shell or network helper",
    "R-ALLOW-EXPIRE": "a 24 h approval expired and the pattern recurred",
    "R-NEW-AGENT": (
        "a new skill, plugin or MCP root appeared (scan result attached when available)"
    ),
}

_SELF_EVENT_KINDS = frozenset(
    {"IN_DELETE_SELF", "IN_MOVE_SELF", "foreign-write", "alert-log-truncated"}
)


@dataclass(frozen=True)
class Section:
    title: str
    lines: list[str]


def _is_sensitive_key(key: str) -> bool:
    norm = str(key).replace("-", "_")
    if _SENSITIVE_KEY_RE.search(norm):
        return True
    if _SENSITIVE_SUBSTR_RE.search(norm):
        return True
    lower = norm.lower()
    return lower in {"token", "auth", "body", "refresh"}


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Drop keys named like token/auth/body; recurse into nested dicts/lists."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive_key(key):
            continue
        out[key] = _redact_value(value)
    return out


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def _q(value: Any) -> str:
    return shlex.quote(str(value))


def _render_value(value: Any) -> str:
    value = _redact_value(value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, list):
        return json.dumps(value)
    return str(value)


def _fact(label: str, value: Any, source: str) -> str | None:
    """One evidence line; skip None so missing v2 fields stay silent."""
    if value is None:
        return None
    return f"  {label}: {_render_value(value)}    [{source}]"


def _facts(*items: str | None) -> list[str]:
    return [item for item in items if item is not None]


def _legacy_limit(alert: Alert) -> list[str]:
    if (alert.evidence or {}).get("schema") != 2:
        return ["recorded before evidence v2; some facts were not captured"]
    return []


def _what_fired(alert: Alert) -> list[str]:
    text = RULE_TEXT.get(alert.rule)
    lines: list[str] = []
    if text:
        lines.append(f"{alert.rule}: {text}")
    if alert.summary:
        lines.append(alert.summary)
    return lines


def _alert_path(alert: Alert) -> str | None:
    if alert.paths:
        return alert.paths[0]
    ev = alert.evidence or {}
    path = ev.get("path")
    return str(path) if path else None


def _first_pid(alert: Alert) -> int | None:
    if alert.pids:
        return int(alert.pids[0])
    return None


def _bypass_citation(alert: Alert) -> str:
    ev = alert.evidence or {}
    pid = _first_pid(alert)
    if ev.get("source") == "launches":
        ts = ev.get("launch_ts")
        return f"launches.jsonl record ts={ts}"
    if pid is not None:
        return f"/proc/{pid}/cmdline at detection"
    return "/proc/cmdline at detection"


def _flag_facts(alert: Alert, source: str) -> list[str]:
    ev = alert.evidence or {}
    flags = ev.get("flags")
    if not isinstance(flags, list) or not flags:
        flag = ev.get("flag")
        flags = [flag] if flag else []
    out: list[str] = []
    for flag in flags:
        idx: int | None
        try:
            idx = alert.cmdline.index(flag)
        except ValueError:
            idx = None
        label = f"flag[{idx}]" if idx is not None else "flag"
        line = _fact(label, flag, source)
        if line:
            out.append(line)
    return out


def _parent_fact(alert: Alert, source: str) -> str | None:
    if not alert.parent:
        return None
    parent = (
        redact_mapping(alert.parent)
        if isinstance(alert.parent, dict)
        else alert.parent
    )
    return _fact("parent", parent, source)


def _render_bypass(alert: Alert, root: Path) -> tuple[list[str], list[str], list[str], list[str]]:
    ev = alert.evidence or {}
    source = _bypass_citation(alert)
    pid = _first_pid(alert)
    facts = _flag_facts(alert, source) + _facts(
        _fact("pid", pid, source),
        _fact("exe", alert.exe or None, source),
        _fact("cwd", alert.cwd or None, source),
        _fact("starttime", ev.get("starttime"), source),
        _fact("instance", ev.get("instance"), source),
        _fact("source", ev.get("source"), source),
        _fact("launch_ts", ev.get("launch_ts"), source),
        _parent_fact(alert, source),
    )
    verify: list[str] = []
    if pid is not None:
        verify.append(f"ps -o pid,lstart,args -p {_q(pid)}")
        verify.append(f"tr '\\0' ' ' < {_q(f'/proc/{pid}/cmdline')}; echo")
    verify.append(f"grep -n {_q(f'\"id\":\"{alert.id}\"')} {_q(str(root / 'alerts.jsonl'))}")
    if ev.get("source") == "launches" and pid is not None:
        verify.append(f"grep -n {_q(f'\"pid\":{pid}')} {_q(str(root / 'launches.jsonl'))}")
    limits: list[str] = []
    if ev.get("source") != "launches":
        limits.append(
            f"the sampler sees a process up to {_SAMPLER_MAX_S} s after start; "
            "kill re-checks the start time"
        )
    limits.extend(_legacy_limit(alert))
    return _what_fired(alert), facts, verify, limits


def _write_verify(alert: Alert, root: Path) -> list[str]:
    path = _alert_path(alert)
    if not path:
        return []
    cmds = [f"stat -c '%s %y %a' {_q(path)}"]
    digest = (alert.hashes or {}).get(path)
    if digest:
        cmds.append(f"sha256sum {_q(path)}  # compare with {digest}")
    else:
        cmds.append(f"sha256sum {_q(path)}")
    pattern = f'"path": "{path}"'
    cmds.append(f"grep -n -F {_q(pattern)} {_q(str(root / 'watchlist.json'))}")
    return cmds


def _write_facts(alert: Alert, ev: dict[str, Any]) -> list[str]:
    path = _alert_path(alert)
    citation = "inotify event on the parent dir"
    digest = (alert.hashes or {}).get(path) if path else None
    writer: Any = alert.writer_pid if alert.writer_pid is not None else "unknown"
    return _facts(
        _fact("path", path, citation),
        _fact("hash", digest, citation),
        _fact("writer_pid", writer, citation),
        _fact("event", ev.get("event"), citation),
    )


def _writer_unknown_limit() -> list[str]:
    return ["writer unknown: inotify reports no PID (writer attribution is W6-04)"]


def _render_hook_write(
    alert: Alert, root: Path
) -> tuple[list[str], list[str], list[str], list[str]]:
    ev = alert.evidence or {}
    facts = _write_facts(alert, ev)
    limits = _writer_unknown_limit() + _legacy_limit(alert)
    return _what_fired(alert), facts, _write_verify(alert, root), limits


def _render_self_event(
    alert: Alert, root: Path, ev: dict[str, Any]
) -> tuple[list[str], list[str], list[str], list[str]]:
    citation = "inotify event on the parent dir"
    path = ev.get("path") or _alert_path(alert)
    facts = _facts(
        _fact("event", ev.get("event"), citation),
        _fact("path", path, citation),
        _fact("size_before", ev.get("size_before"), citation),
        _fact("size_after", ev.get("size_after"), citation),
    )
    limits = _legacy_limit(alert)
    event = ev.get("event")
    if event == "foreign-write":
        limits = _writer_unknown_limit() + limits
    return _what_fired(alert), facts, _write_verify(alert, root), limits


def _render_self(
    alert: Alert, root: Path
) -> tuple[list[str], list[str], list[str], list[str]]:
    ev = alert.evidence or {}
    event = ev.get("event")
    if event in _SELF_EVENT_KINDS:
        return _render_self_event(alert, root, ev)
    facts = _write_facts(alert, ev)
    limits = _writer_unknown_limit() + _legacy_limit(alert)
    return _what_fired(alert), facts, _write_verify(alert, root), limits


def _render_child_shell(
    alert: Alert, root: Path
) -> tuple[list[str], list[str], list[str], list[str]]:
    ev = alert.evidence or {}
    source = "/proc tree at detection"
    parent = alert.parent if isinstance(alert.parent, dict) else {}
    parent = redact_mapping(parent) if parent else {}
    parent_pid = parent.get("pid", ev.get("parent_pid"))
    parent_base = parent.get("basename")
    child_pids = ev.get("child_pids") or []
    cmdline = " ".join(alert.cmdline) if alert.cmdline else None
    facts = _facts(
        _fact("kind", ev.get("kind"), source),
        _fact("parent_basename", parent_base, source),
        _fact("parent_pid", parent_pid, source),
        _fact("child_pids", child_pids or None, source),
        _fact("cmdline", cmdline, source),
    )
    pids: list[str] = []
    if parent_pid is not None:
        pids.append(str(int(parent_pid)))
    for child in child_pids:
        pids.append(str(int(child)))
    verify: list[str] = []
    if pids:
        verify.append(f"ps -o pid,ppid,lstart,args -p {','.join(pids)}")
    for child in child_pids:
        verify.append(f"awk '{{print $4}}' {_q(f'/proc/{int(child)}/stat')}")
    limits = ["interactive-shell detection is argv-based"] + _legacy_limit(alert)
    return _what_fired(alert), facts, verify, limits


def _render_allow_expire(
    alert: Alert, root: Path
) -> tuple[list[str], list[str], list[str], list[str]]:
    ev = alert.evidence or {}
    source = "allowlist.json entry removed"
    fp = ev.get("fingerprint")
    facts = _facts(
        _fact("fingerprint", fp, source),
        _fact("original_rule", ev.get("original_rule"), source),
        _fact("expired_scope", ev.get("expired_scope"), source),
    )
    verify: list[str] = []
    if fp:
        verify.append(f"grep -c {_q(fp)} {_q(str(root / 'allowlist.json'))}  # expect 0")
    verify.append("sentinel-action list")
    return _what_fired(alert), facts, verify, _legacy_limit(alert)


def _render_new_agent(
    alert: Alert, root: Path
) -> tuple[list[str], list[str], list[str], list[str]]:
    ev = alert.evidence or {}
    scan = ev.get("scan") if isinstance(ev.get("scan"), dict) else {}
    scan = redact_mapping(scan)
    source = "scan result"
    report = ev.get("report") or scan.get("report")
    facts = _facts(
        _fact("tool", scan.get("tool"), source),
        _fact("version", scan.get("version"), source),
        _fact("risk_score", scan.get("risk_score"), source),
        _fact("verdict", scan.get("verdict"), source),
        _fact("counts", scan.get("counts"), source),
        _fact("report", report, source),
    )
    top = scan.get("top") if isinstance(scan.get("top"), list) else []
    for i, item in enumerate(top):
        if not isinstance(item, dict):
            continue
        item = redact_mapping(item)
        title = item.get("title")
        file = item.get("file")
        line = item.get("line")
        if title is None and file is None and line is None:
            continue
        shown = f"{title} ({file}:{line})"
        line_fact = _fact(f"top[{i}]", shown, source)
        if line_fact:
            facts.append(line_fact)
    skill_root = ev.get("root") or ev.get("path") or _alert_path(alert) or alert.cwd or None
    verify: list[str] = []
    if report:
        verify.append(f"sed -n 1,40p {_q(report)}")
    if skill_root:
        verify.append(f"skillspector scan {_q(skill_root)} --no-llm")
    limits = [
        "static scan only unless the LLM stage was requested",
    ] + _legacy_limit(alert)
    return _what_fired(alert), facts, verify, limits


def _render_generic(
    alert: Alert, root: Path
) -> tuple[list[str], list[str], list[str], list[str]]:
    source = "alert record"
    ev = redact_mapping(alert.evidence or {})
    facts = _facts(
        _fact("exe", alert.exe or None, source),
        _fact("cwd", alert.cwd or None, source),
        _fact("pids", alert.pids or None, source),
        _fact("path", _alert_path(alert), source),
        _fact("writer_pid", alert.writer_pid, source),
        _parent_fact(alert, source),
        _fact("evidence", ev or None, source),
    )
    verify = [f"grep -n {_q(f'\"id\":\"{alert.id}\"')} {_q(str(root / 'alerts.jsonl'))}"]
    return _what_fired(alert), facts, verify, _legacy_limit(alert)


_RENDERERS: dict[
    str, Callable[[Alert, Path], tuple[list[str], list[str], list[str], list[str]]]
] = {
    "R-BYPASS": _render_bypass,
    "R-HOOK-WRITE": _render_hook_write,
    "R-SELF": _render_self,
    "R-CHILD-SHELL": _render_child_shell,
    "R-ALLOW-EXPIRE": _render_allow_expire,
    "R-NEW-AGENT": _render_new_agent,
}


def action_lines(alert: Alert) -> list[str]:
    """Commands the user can run for this alert; kill only when PIDs exist."""
    aid = alert.id
    lines = [
        f"sentinel-action {aid} approve --scope session|24h|this-repo|forever",
        f"sentinel-action {aid} dismiss",
        f"sentinel-action {aid} open",
        f"sentinel-action {aid} open --logs",
        f"sentinel-action {aid} summarize",
        f"sentinel-action {aid} investigate",
    ]
    if alert.pids:
        lines.append(f"sentinel-action {aid} kill [--session]")
    return lines


def _journal_since(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - timedelta(seconds=60)).isoformat()


def _log_lines(alert: Alert, root: Path, line_no: int | None) -> list[str]:
    alerts = root / "alerts.jsonl"
    if line_no is not None:
        alerts_line = f"{alerts} (this alert: line {line_no})"
    else:
        alerts_line = str(alerts)
    return [
        f"state dir: {root}",
        alerts_line,
        str(root / "launches.jsonl"),
        str(root / "watchlist.json"),
        f"journalctl --user -t sentinel SENTINEL_ID={_q(alert.id)} -o verbose",
        (
            "journalctl --user -u sentinel.service --since "
            f"{_q(_journal_since(alert.ts))}"
        ),
    ]


def render_sections(
    alert: Alert,
    *,
    line_no: int | None = None,
    state_dir: Path | str | None = None,
) -> list[Section]:
    """Build the six investigate sections; never include file bodies."""
    root = Path(state_dir) if state_dir is not None else xdg_state_dir()
    renderer = _RENDERERS.get(alert.rule, _render_generic)
    what, facts, verify, limits = renderer(alert, root)
    by_title = {
        "What fired": what,
        "Evidence": facts,
        "Verify it yourself": verify,
        "Limits": limits,
        "Where the logs are": _log_lines(alert, root, line_no),
        "Actions": action_lines(alert),
    }
    return [Section(title=title, lines=list(by_title[title])) for title in SECTION_ORDER]


def format_detail(alert: Alert, *, line_no: int | None = None) -> str:
    lines = [
        f"id:       {alert.id}",
        f"ts:       {alert.ts}",
        f"rule:     {alert.rule}",
        f"severity: {alert.severity}",
        f"status:   {alert.status}",
        f"summary:  {alert.summary}",
        f"exe:      {alert.exe}",
        f"basename: {alert.basename}",
        f"cmdline:  {' '.join(alert.cmdline)}",
        f"cwd:      {alert.cwd}",
        f"pids:     {', '.join(str(p) for p in alert.pids)}",
    ]
    if alert.parent:
        parent = (
            redact_mapping(alert.parent)
            if isinstance(alert.parent, dict)
            else alert.parent
        )
        lines.append(f"parent:   {parent}")
    if alert.paths:
        lines.append("paths:")
        for path in alert.paths:
            lines.append(f"  {path}")
    if alert.hashes:
        lines.append("hashes:")
        for path, digest in alert.hashes.items():
            lines.append(f"  {path}: {digest}")
    if alert.writer_pid is not None:
        lines.append(f"writer_pid: {alert.writer_pid}")
    if alert.evidence:
        lines.append(f"evidence: {redact_mapping(alert.evidence)}")
    chunks = ["\n".join(lines)]
    for section in render_sections(alert, line_no=line_no):
        chunks.append(section.title)
        chunks.extend(section.lines)
    return "\n".join(chunks) + "\n"


def _pager_argv() -> list[str]:
    raw = os.environ.get("PAGER") or "less"
    parts = shlex.split(raw)
    return parts or ["less"]


def page_detail(alert: Alert, *, line_no: int | None = None) -> None:
    """Show local alert detail via $PAGER or less; print if not a tty."""
    text = format_detail(alert, line_no=line_no)
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        print(text, end="")
        return
    argv = _pager_argv()
    try:
        subprocess.run(argv, input=text, text=True, check=False)
    except OSError:
        print(text, end="")
