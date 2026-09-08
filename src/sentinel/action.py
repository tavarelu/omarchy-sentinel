# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel.allowlist import (
    SCOPES,
    allowlist_path,
    approve_many,
    fingerprint,
    session_path,
)
from sentinel.fsutil import write_private_atomic
from sentinel.keys import alert_flag_set, approval_prefix
from sentinel.investigate import action_lines, page_detail
from sentinel.kill import (
    confirm_kill as kill_confirm,
    cwd_is_precious as cwd_matches_precious,
    execute_kill,
    plan_kill,
)
from sentinel.models import Alert
from sentinel.paths import default_config_path, state_dir
from sentinel.statewatch import announce_write, sha256_file
from sentinel.store import (
    alerts_path,
    find_alert,
    iter_alerts,
    update_alert_status,
    update_alert_statuses,
)

PAUSE_FILENAME = "pause_until"
DEFAULT_PAUSE_MAX = timedelta(hours=24)
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
        "notify",
        "open",
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


def _announce(path: Path) -> None:
    """Tell the daemon this file's just-written content is ours (best-effort;
    an announce failure must never break the CLI action itself)."""
    digest = sha256_file(path)
    if digest is None:
        return
    try:
        announce_write(path, digest)
    except Exception:
        return


def write_pause(duration: timedelta, now: datetime | None = None) -> datetime:
    when = now if now is not None else _now()
    until = when + duration
    text = until.isoformat() + "\n"
    path = pause_until_path()
    digest = hashlib.sha256(text.encode()).hexdigest()
    try:
        announce_write(path, digest)  # pre-write announce (R7)
    except Exception:
        pass
    write_private_atomic(path, text)
    try:
        announce_write(path, digest)  # post-write announce (R7)
    except Exception:
        pass
    return until


def load_pause_max(config_path: Path | None = None) -> timedelta:
    """[notify].pause_max (default 24h). Kept independent of notify.load_policy
    so the config-template round-trip test (which asserts load_policy(path) ==
    NotifyPolicy()) is undisturbed by this key."""
    path = config_path if config_path is not None else default_config_path()
    if not Path(path).is_file():
        return DEFAULT_PAUSE_MAX
    try:
        with Path(path).open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return DEFAULT_PAUSE_MAX
    section = data.get("notify")
    if not isinstance(section, dict):
        return DEFAULT_PAUSE_MAX
    raw = section.get("pause_max")
    if not isinstance(raw, str):
        return DEFAULT_PAUSE_MAX
    try:
        return parse_duration(raw)
    except ValueError:
        return DEFAULT_PAUSE_MAX


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
    """True while state_dir()/pause_until is in the future and within
    pause_max of `now` (W3-07): a pause further out than the cap is not a
    pause -- one file write must not silence Sentinel indefinitely."""
    until = read_pause_until()
    if until is None:
        return False
    when = now if now is not None else _now()
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    if until - when > load_pause_max():
        return False
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
    found = find_alert(alert_id)
    if found is None:
        raise KeyError(alert_id)
    return found[1]


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


def _announce_allowlist() -> None:
    """approve() may write allowlist.json, allowlist-session.json, or both."""
    _announce(allowlist_path())
    _announce(session_path())


def _set_status(alert_id: str, status: str) -> None:
    """update_alert_status rewrites alerts.jsonl whole; announce the result so
    the daemon's ledger sees this as our own write, not tamper."""
    update_alert_status(alert_id, status)
    _announce(alerts_path())


def _set_status_many(alert_ids: Sequence[str], status: str) -> list[str]:
    """Same, for a bulk action: one rewrite and one announcement for all of them."""
    changed = update_alert_statuses(alert_ids, status)
    _announce(alerts_path())
    return changed


def open_alert_ids() -> list[str]:
    """Ids of every alert still awaiting a decision, in log order."""
    return [a.id for a in iter_alerts() if a.status == "open"]


def _resolve_targets(
    alert_ids: str | Sequence[str],
    all_open: bool,
) -> list[str] | None:
    """Work out which alerts a command applies to.

    --all means "every alert still open", which is what the panel's bulk
    buttons act on; otherwise the explicit ids win. Returns None when the
    caller gave nothing to act on, so each command can report its own error.

    A bare id string is accepted alongside a list: `str` is itself a
    Sequence[str], so taking one by mistake would otherwise iterate it one
    character at a time and report every letter as an unknown alert.
    """
    if all_open:
        return open_alert_ids()
    if isinstance(alert_ids, str):
        alert_ids = [alert_ids]
    return [str(i) for i in alert_ids] or None


def cmd_approve(
    alert_ids: str | Sequence[str],
    scope: str,
    *,
    all_open: bool = False,
) -> int:
    if scope not in SCOPES:
        print(f"invalid scope: {scope}", file=sys.stderr)
        return 1
    targets = _resolve_targets(alert_ids, all_open)
    if targets is None:
        print("approve: no alert id given (pass ids or --all)", file=sys.stderr)
        return 2
    if not targets:
        print("nothing to approve: no open alerts")
        return 0

    # Resolve every fingerprint first so one unknown id fails the whole batch
    # before anything is written, rather than half-applying it.
    pending: list[tuple[str, str, str]] = []
    for alert_id in targets:
        try:
            alert = get_alert(alert_id)
        except KeyError:
            print(f"unknown alert: {alert_id}", file=sys.stderr)
            return 1
        prefix = approval_prefix(alert, scope)
        fp = fingerprint(alert.rule, alert.basename, alert_flag_set(alert), prefix)
        pending.append((fp, prefix, alert.id))

    approve_many([(fp, scope, prefix) for fp, prefix, _ in pending])  # type: ignore[arg-type]
    _announce_allowlist()
    changed = _set_status_many([a for _, _, a in pending], "approved")
    if len(pending) == 1:
        fp, prefix, alert_id = pending[0]
        print(f"approved {alert_id} scope={scope} prefix={prefix or '(any)'}")
    else:
        print(f"approved {len(changed)} alerts scope={scope}")
    return 0


def cmd_dismiss(alert_ids: str | Sequence[str], *, all_open: bool = False) -> int:
    targets = _resolve_targets(alert_ids, all_open)
    if targets is None:
        print("dismiss: no alert id given (pass ids or --all)", file=sys.stderr)
        return 2
    if not targets:
        print("nothing to dismiss: no open alerts")
        return 0
    for alert_id in targets:
        try:
            get_alert(alert_id)
        except KeyError:
            print(f"unknown alert: {alert_id}", file=sys.stderr)
            return 1
    changed = _set_status_many(targets, "dismissed")
    if len(targets) == 1:
        print(f"dismissed {targets[0]}")
    else:
        print(f"dismissed {len(changed)} alerts")
    return 0


def cmd_investigate(alert_id: str) -> int:
    found = find_alert(alert_id)
    if found is None:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    line_no, alert = found
    page_detail(alert, line_no=line_no)
    _set_status(alert.id, "investigated")
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


MENU_PROMPT_LINES: tuple[str, ...] = (
    "1 approve session",
    "2 approve 24h",
    "3 approve this-repo",
    "4 approve forever",
    "5 kill child",
    "6 kill session",
    "7 investigate",
    "8 summarize",
    "9 dismiss",
    "0 nothing",
)


def cmd_menu(
    alert_id: str,
    *,
    isatty: bool | None = None,
    prompt: Callable[[str], str] | None = None,
) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    print(f"Alert {alert.id} [{alert.status}] {alert.severity} {alert.rule}")
    print(f"  {alert.summary}")
    tty = sys.stdin.isatty() if isatty is None else isatty
    if not tty:
        print("Actions:")
        for line in action_lines(alert):
            print(line)
        return 0
    ask = input if prompt is None else prompt
    for line in MENU_PROMPT_LINES:
        print(line)
    choice = ask("> ").strip()
    return _dispatch_menu_choice(alert.id, choice)


def _dispatch_menu_choice(alert_id: str, choice: str) -> int:
    """Route a numbered menu choice to the existing cmd_* functions.

    Kill (5/6) still goes through cmd_kill -> confirm_kill: selecting a menu
    number is never sufficient consent to kill on its own (no silent
    auto-kill, AGENTS.md invariant 4).
    """
    if choice == "1":
        return cmd_approve([alert_id], "session")
    if choice == "2":
        return cmd_approve([alert_id], "24h")
    if choice == "3":
        return cmd_approve([alert_id], "this-repo")
    if choice == "4":
        return cmd_approve([alert_id], "forever")
    if choice == "5":
        return cmd_kill(alert_id, session=False, yes=False)
    if choice == "6":
        return cmd_kill(alert_id, session=True, yes=False)
    if choice == "7":
        return cmd_investigate(alert_id)
    if choice == "8":
        return cmd_summarize(alert_id)
    if choice == "9":
        return cmd_dismiss([alert_id])
    if choice == "0":
        return 0
    print(f"nothing done: unrecognized choice {choice!r}", file=sys.stderr)
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
    cap = load_pause_max()
    if delta > cap:
        print(
            f"refusing: {duration} exceeds the configured pause cap of {cap}",
            file=sys.stderr,
        )
        return 2
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


def _parse_severity_flag(text: str) -> tuple[str, bool]:
    name, sep, value = text.partition("=")
    name = name.strip().lower()
    value = value.strip().lower()
    if not sep or name not in ("high", "medium", "low") or value not in ("on", "off"):
        raise ValueError(f"invalid --severity {text!r} (use high|medium|low=on|off)")
    return name, value == "on"


def cmd_notify(severities: list[str], *, reset: bool = False, as_json: bool = False) -> int:
    from sentinel.notify import SEVERITIES, STICKY_EVENTS, effective_policy, load_policy, load_prefs, prefs_path, write_prefs

    if reset:
        try:
            prefs_path().unlink()
        except FileNotFoundError:
            pass
    if severities:
        try:
            flags = dict(_parse_severity_flag(s) for s in severities)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        write_prefs(flags)
        _announce(prefs_path())
    policy = load_policy()
    prefs = load_prefs() or {}
    eff = effective_policy(policy, prefs)
    if as_json:
        out = {name: getattr(eff, name).enabled for name in SEVERITIES}
        out["source"] = {name: ("prefs" if name in prefs else "config") for name in SEVERITIES}
        out["prefs_path"] = str(prefs_path())
        print(json.dumps(out, sort_keys=True))
        return 0
    for name in SEVERITIES:
        sp = getattr(eff, name)
        source = "prefs" if name in prefs else "config"
        print(f"{name:7s} {'on ' if sp.enabled else 'off'}  ({sp.urgency}, {sp.timeout_ms // 1000} s)   source: {source}")
    print(f"sticky  R-SELF {', '.join(sorted(STICKY_EVENTS))}  (critical, never expires)")
    b = eff.burst
    print(f"burst   {b.threshold} toasts / {int(b.window_sec)} s → summary; resets after {int(b.quiet_sec)} s quiet")
    print(f"prefs   {prefs_path()}")
    return 0


def open_target(alert: Alert, *, logs: bool = False) -> tuple[str, Path]:
    """Pick a nautilus target: the file, its parent, cwd, or the state dir."""
    if logs:
        return ("dir", state_dir())
    if alert.paths:
        path = Path(alert.paths[0])
        if not path.is_absolute():
            raise ValueError("relative path")
        if path.is_file():
            return ("select", path)
        return ("dir", path.parent)
    cwd = alert.cwd
    if cwd:
        path = Path(cwd)
        if not path.is_absolute():
            raise ValueError("relative path")
        return ("dir", path)
    raise ValueError("missing location")


def open_argv(mode: str, path: Path) -> list[str]:
    if mode == "select":
        return ["uwsm-app", "--", "nautilus", "--select", path.as_uri()]
    return ["uwsm-app", "--", "nautilus", "--new-window", str(path)]


def launch_detached(argv: list[str], *, popen: type[subprocess.Popen] = subprocess.Popen) -> None:
    """Start nautilus out-of-process; do not inherit stdio or the session."""
    popen(
        argv,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def cmd_open(alert_id: str, *, logs: bool = False) -> int:
    try:
        alert = get_alert(alert_id)
    except KeyError:
        print(f"unknown alert: {alert_id}", file=sys.stderr)
        return 1
    try:
        mode, path = open_target(alert, logs=logs)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if shutil.which("nautilus") is None:
        print(str(path))
        return 1
    print(f"opening {path}")
    launch_detached(open_argv(mode, path))
    return 0


def no_target_reason(alert: Alert) -> str:
    """Explain why a kill has no PID to act on, so the panel and the CLI agree.

    Filesystem rules are raised from inotify, which reports the path that
    changed but never the process that changed it, so those alerts carry no
    pids and can never be killed. Process rules come from the launch ledger
    and do carry a pid, so an empty plan there means the process is simply
    gone (exited, or its pid was recycled and the start time no longer
    matches).
    """
    if not alert.pids:
        return (
            f"refusing: alert {alert.id} records no process id, so there is nothing "
            f"to kill. Rule {alert.rule} is raised from a filesystem event, which "
            "identifies the file that was written but not the writer. Use "
            "`investigate` to see the evidence, `approve` to allowlist the "
            "fingerprint, or `dismiss` to close the alert."
        )
    return (
        f"no live target: every process recorded on alert {alert.id} has already "
        "exited or had its pid recycled. Leaving the alert open; use `dismiss` to "
        "close it."
    )


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
    mode = "session" if session else "child"
    # Build the plan *before* asking for consent. A kill with no target must
    # never prompt, never run, and never mark the alert "killed": reporting a
    # kill that did not happen is the worst failure mode a watchdog has.
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
    if not plan:
        print(no_target_reason(alert), file=sys.stderr)
        return 1
    precious = cwd_is_precious(alert.cwd)
    if not confirm_kill(yes=yes, session=session, precious=precious):
        return 1
    print("killing pids: " + ", ".join(str(p) for p in plan))
    execute_kill(plan)
    _set_status(alert.id, "killed")
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
    approve_p.add_argument("alert_id", nargs="*", help="One or more alert ids")
    approve_p.add_argument(
        "--all",
        dest="all_open",
        action="store_true",
        help="Apply to every alert still open",
    )
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
    dis_p.add_argument("alert_id", nargs="*", help="One or more alert ids")
    dis_p.add_argument(
        "--all",
        dest="all_open",
        action="store_true",
        help="Apply to every alert still open",
    )

    menu_p = sub.add_parser("menu", help="Show per-alert actions")
    menu_p.add_argument("alert_id")

    sub.add_parser("list", help="List open alerts")
    sub.add_parser("status", help="Show open count and pause state")

    pause_p = sub.add_parser("pause", help="Suppress notifications for a duration")
    pause_p.add_argument("duration", nargs="?", default="1h")

    notify_p = sub.add_parser("notify", help="Show or change which severities toast (shared with the panel)")
    notify_p.add_argument("--severity", action="append", default=[], metavar="SEV=on|off")
    notify_p.add_argument("--reset", action="store_true", help="Remove runtime preferences; config defaults apply")
    notify_p.add_argument("--json", action="store_true", help="Machine-readable output")

    open_p = sub.add_parser("open", help="Reveal the alerted file or open its directory")
    open_p.add_argument("alert_id")
    open_p.add_argument(
        "--logs",
        action="store_true",
        help="Open the Sentinel state directory",
    )

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(_normalize_argv(argv))
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "approve":
        return cmd_approve(args.alert_id, args.scope, all_open=args.all_open)
    if args.command == "kill":
        return cmd_kill(args.alert_id, session=args.session, yes=args.yes, force_stale=args.force_stale)
    if args.command == "investigate":
        return cmd_investigate(args.alert_id)
    if args.command == "summarize":
        return cmd_summarize(args.alert_id)
    if args.command == "dismiss":
        return cmd_dismiss(args.alert_id, all_open=args.all_open)
    if args.command == "menu":
        return cmd_menu(args.alert_id)
    if args.command == "list":
        return cmd_list()
    if args.command == "status":
        return cmd_status()
    if args.command == "pause":
        return cmd_pause(args.duration)
    if args.command == "notify":
        return cmd_notify(args.severity, reset=args.reset, as_json=args.json)
    if args.command == "open":
        return cmd_open(args.alert_id, logs=args.logs)
    parser.print_help()
    return 0
