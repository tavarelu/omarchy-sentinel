# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel.allowlist import SCOPES, approve, fingerprint
from sentinel.fsutil import write_private_atomic
from sentinel.keys import alert_flag_set, approval_prefix
from sentinel.investigate import page_detail
from sentinel.kill import (
    confirm_kill as kill_confirm,
    cwd_is_precious as cwd_matches_precious,
    execute_kill,
    plan_kill,
)
from sentinel.models import Alert
from sentinel.paths import default_config_path, state_dir
from sentinel.store import iter_alerts, update_alert_status

PAUSE_FILENAME = "pause_until"
COMMANDS = frozenset(
    {
        "approve",
        "kill",
        "investigate",
        "summarize",
        "dismiss",
        "menu",
        "list",
        "status",
        "pause",
    }
)
_DURATION_RE = re.compile(r"^(\d+)([smhd])$", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def pause_until_path() -> Path:
    return state_dir() / PAUSE_FILENAME


def parse_duration(text: str) -> timedelta:
    match = _DURATION_RE.fullmatch(text.strip())
    if not match:
        raise ValueError(f"invalid duration: {text!r} (use Ns/Nm/Nh/Nd)")
    n = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "s":
        return timedelta(seconds=n)
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "h":
        return timedelta(hours=n)
    return timedelta(days=n)


def write_pause(duration: timedelta, now: datetime | None = None) -> datetime:
    when = now if now is not None else _now()
    until = when + duration
    write_private_atomic(pause_until_path(), until.isoformat() + "\n")
    return until


def read_pause_until() -> datetime | None:
    path = pause_until_path()
    if not path.is_file():
        return None
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def is_paused(now: datetime | None = None) -> bool:
    """True while state_dir()/pause_until is in the future. Notify should skip."""
    until = read_pause_until()
    if until is None:
        return False
    when = now if now is not None else _now()
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when < until


def load_precious_worktrees() -> list[str]:
    path = default_config_path()
    if not path.is_file():
        return []
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    for section in (data.get("kill"), data):
        if not isinstance(section, dict):
            continue
        raw = section.get("precious_worktrees")
        if isinstance(raw, list):
            return [str(x) for x in raw]
    return []


def cwd_is_precious(cwd: str, prefixes: list[str] | None = None) -> bool:
    roots = load_precious_worktrees() if prefixes is None else prefixes
    return cwd_matches_precious(cwd, roots)


def get_alert(alert_id: str) -> Alert:
    for alert in iter_alerts():
        if alert.id == alert_id:
            return alert
    raise KeyError(alert_id)


def resolve_child_pids(alert: Alert) -> list[int]:
    ev = alert.evidence or {}
    if "child_pids" in ev:
        return [int(p) for p in ev["child_pids"]]
    if "child_pid" in ev:
        return [int(ev["child_pid"])]
    if len(alert.pids) == 1:
        return list(alert.pids)
    return []


def confirm_kill(*, yes: bool, session: bool, precious: bool) -> bool:
    # --yes is only enough for child kill. Supervisor kill in a precious
    # worktree always needs an interactive tty (spec §11 / Task 13).
    return kill_confirm(yes=yes, session=session, precious=precious)


def cmd_approve(alert_id: str, scope: str) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    if scope not in SCOPES:
        print(f"invalid scope: {scope}", file=sys.stderr)
        return 1
    prefix = approval_prefix(alert, scope)
    fp = fingerprint(alert.rule, alert.basename, alert_flag_set(alert), prefix)
    approve(fp, scope, prefix)  # type: ignore[arg-type]
    update_alert_status(alert.id, "approved")
    print(f"approved {alert.id} scope={scope} prefix={prefix or '(any)'}")
    return 0


def cmd_dismiss(alert_id: str) -> int:
    try:
        get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    update_alert_status(alert_id, "dismissed")
    print(f"dismissed {alert_id}")
    return 0


def cmd_investigate(alert_id: str) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    page_detail(alert)
    update_alert_status(alert.id, "investigated")
    return 0


def cmd_summarize(alert_id: str) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    from sentinel.investigate import format_detail
    from sentinel.summarize import summarize

    text = summarize(alert)
    if text is None:
        print(format_detail(alert), end="")
    else:
        print(text)
    return 0


def cmd_menu(alert_id: str) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    print(f"Alert {alert.id} [{alert.status}] {alert.severity} {alert.rule}")
    print(f"  {alert.summary}")
    print("Actions:")
    print("  approve")
    print("  kill")
    print("  investigate")
    print("  summarize")
    print("  dismiss")
    print(f"  sentinel-action {alert.id} approve --scope session|24h|this-repo|forever")
    print(f"  sentinel-action {alert.id} kill [--session] [--yes]")
    print(f"  sentinel-action {alert.id} investigate")
    print(f"  sentinel-action {alert.id} summarize")
    print(f"  sentinel-action {alert.id} dismiss")
    return 0


def cmd_list() -> int:
    rows = [alert for alert in iter_alerts() if alert.status == "open"]
    if not rows:
        print("no open alerts")
        return 0
    for alert in rows:
        print(
            f"{alert.id}  {alert.status}  {alert.severity}  {alert.rule}  {alert.summary}"
        )
    return 0


def cmd_status() -> int:
    alerts = list(iter_alerts())
    open_n = sum(1 for alert in alerts if alert.status == "open")
    print(f"open: {open_n}")
    print(f"total: {len(alerts)}")
    until = read_pause_until()
    when = _now()
    if until is not None and when < until:
        print(f"paused until: {until.isoformat()}")
    else:
        print("paused: no")
    return 0


def cmd_pause(duration: str) -> int:
    try:
        delta = parse_duration(duration)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    until = write_pause(delta, now=_now())
    print(f"paused until {until.isoformat()}")
    return 0


STALE_AFTER = timedelta(minutes=10)


def expected_starttimes(alert: Alert) -> dict[int, int]:
    """pid -> starttime recorded at detection, for every pid the alert names."""
    ev = alert.evidence or {}
    out: dict[int, int] = {}
    table = ev.get("starttimes")
    if isinstance(table, dict):
        for k, v in table.items():
            try:
                out[int(k)] = int(v)
            except (TypeError, ValueError):
                continue
    single = ev.get("starttime")
    if single is not None and alert.pids:
        for pid in alert.pids:
            out.setdefault(int(pid), int(single))
    return out


def alert_is_stale(alert: Alert, now: datetime | None = None) -> bool:
    try:
        ts = datetime.fromisoformat(alert.ts)
    except ValueError:
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    when = now if now is not None else _now()
    return when - ts > STALE_AFTER


def cmd_kill(alert_id: str, *, session: bool, yes: bool, force_stale: bool = False) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    expected = expected_starttimes(alert)
    if alert.pids and not expected and alert_is_stale(alert) and not force_stale:
        print(
            "refusing: this alert recorded no process start time and is older than "
            "10 minutes, so its PIDs may belong to other processes now. "
            "Re-run with --force-stale to kill anyway.",
            file=sys.stderr,
        )
        return 1
    precious = cwd_is_precious(alert.cwd)
    if not confirm_kill(yes=yes, session=session, precious=precious):
        return 1
    mode = "session" if session else "child"
    try:
        plan = plan_kill(
            alert.pids,
            child_pids=resolve_child_pids(alert),
            mode=mode,
            expected_starttime=expected,
        )
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("killing pids: " + (", ".join(str(p) for p in plan) if plan else "(none)"))
    execute_kill(plan)
    update_alert_status(alert.id, "killed")
    print(f"killed {alert.id}")
    return 0


def _normalize_argv(argv: list[str]) -> list[str]:
    """Accept both `sentinel-action <id> kill` and `sentinel-action kill <id>`."""
    if not argv:
        return argv
    if argv[0] in COMMANDS:
        return argv
    if len(argv) >= 2 and argv[1] in COMMANDS:
        return [argv[1], argv[0], *argv[2:]]
    return argv


def action_main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="sentinel-action")
    sub = parser.add_subparsers(dest="command")

    approve_p = sub.add_parser("approve", help="Allowlist the alert fingerprint")
    approve_p.add_argument("alert_id")
    approve_p.add_argument(
        "--scope",
        choices=sorted(SCOPES),
        default="session",
        help="Approval scope (session / 24h / this-repo / forever)",
    )

    kill_p = sub.add_parser("kill", help="Narrow-kill target PIDs")
    kill_p.add_argument("alert_id")
    kill_p.add_argument(
        "--session",
        action="store_true",
        help="Kill the agent supervisor (not just the alerting child)",
    )
    kill_p.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirm; child kill only (precious session still needs a tty)",
    )
    kill_p.add_argument(
        "--force-stale",
        action="store_true",
        help="Kill even if the alert is old and recorded no process start time",
    )

    inv_p = sub.add_parser("investigate", help="Local alert detail via $PAGER or less")
    inv_p.add_argument("alert_id")

    sum_p = sub.add_parser(
        "summarize",
        help="Opt-in redacted cloud digest (falls back to local detail)",
    )
    sum_p.add_argument("alert_id")

    dis_p = sub.add_parser(
        "dismiss",
        help="Close without allowlisting; final for that process instance (one alert per instance)",
    )
    dis_p.add_argument("alert_id")

    menu_p = sub.add_parser("menu", help="Show per-alert actions")
    menu_p.add_argument("alert_id")

    sub.add_parser("list", help="List open alerts")
    sub.add_parser("status", help="Show open count and pause state")

    pause_p = sub.add_parser("pause", help="Suppress notifications for a duration")
    pause_p.add_argument("duration", nargs="?", default="1h")

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(_normalize_argv(argv))
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "approve":
        return cmd_approve(args.alert_id, args.scope)
    if args.command == "kill":
        return cmd_kill(args.alert_id, session=args.session, yes=args.yes, force_stale=args.force_stale)
    if args.command == "investigate":
        return cmd_investigate(args.alert_id)
    if args.command == "summarize":
        return cmd_summarize(args.alert_id)
    if args.command == "dismiss":
        return cmd_dismiss(args.alert_id)
    if args.command == "menu":
        return cmd_menu(args.alert_id)
    if args.command == "list":
        return cmd_list()
    if args.command == "status":
        return cmd_status()
    if args.command == "pause":
        return cmd_pause(args.duration)
    parser.print_help()
    return 0
