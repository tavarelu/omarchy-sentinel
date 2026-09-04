from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.models import Alert

DEFAULT_BYPASS_FLAGS: frozenset[str] = frozenset(
    {
        "--dangerously-skip-permissions",
        "bypassPermissions",
        "--yolo",
        "trust-all",
        "--trust-all",
    }
)

DEFAULT_EDITOR_ALLOWLIST: frozenset[str] = frozenset(
    {
        "nano",
        "vim",
        "nvim",
        "vi",
        "emacs",
        "emacsclient",
        "code",
        "code-oss",
        "codium",
        "kate",
        "gedit",
        "helix",
        "hx",
        "micro",
        "subl",
        "sublime_text",
    }
)

DEFAULT_AGENT_BASENAMES: frozenset[str] = frozenset(
    {
        "claude",
        "codex",
        "cursor",
        "cursor-agent",
        "grok",
    }
)

SHELL_BASENAMES: frozenset[str] = frozenset(
    {"bash", "sh", "dash", "zsh", "fish", "ksh"}
)

NET_HELPER_BASENAMES: frozenset[str] = frozenset(
    {"curl", "wget", "nc", "ncat", "netcat", "socat"}
)

# curl|bash / wget|sh (and sudo variants) inside a shell -c string or argv blob.
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^;\n]*\|\s*(?:sudo\s+)?(?:bash|sh|dash|zsh|fish|ksh)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProcSnapshot:
    """One synthetic /proc row for R-CHILD-SHELL tree evaluation."""

    pid: int
    ppid: int
    cmdline: tuple[str, ...]
    exe: str = ""
    cwd: str = ""
    comm: str = ""

    def __init__(
        self,
        pid: int,
        ppid: int,
        cmdline: Sequence[str] | None = None,
        exe: str = "",
        cwd: str = "",
        comm: str = "",
    ) -> None:
        object.__setattr__(self, "pid", int(pid))
        object.__setattr__(self, "ppid", int(ppid))
        object.__setattr__(self, "cmdline", tuple(cmdline or ()))
        object.__setattr__(self, "exe", exe or "")
        object.__setattr__(self, "cwd", cwd or "")
        object.__setattr__(self, "comm", comm or "")


def _basename(exe: str | None) -> str:
    if not exe:
        return ""
    return Path(exe).name


def _normalize_token(token: str) -> str:
    # Strip --flag=value → --flag for matching extras with values.
    if token.startswith("-") and "=" in token:
        return token.split("=", 1)[0]
    return token


def extract_bypass_flags(
    cmdline: list[str],
    extra_bypass_flags: Iterable[str] | None = None,
) -> list[str]:
    known = set(DEFAULT_BYPASS_FLAGS)
    if extra_bypass_flags:
        known.update(extra_bypass_flags)
    found: list[str] = []
    for raw in cmdline:
        token = _normalize_token(raw)
        if token in known or raw in known:
            found.append(raw if raw in known else token)
    return found


def evaluate_process(
    cmdline: list[str],
    exe: str,
    cwd: str,
    *,
    extra_bypass_flags: Iterable[str] | None = None,
) -> Alert | None:
    flags = extract_bypass_flags(cmdline, extra_bypass_flags)
    if not flags:
        return None
    flag = flags[0]
    basename = _basename(exe) or (cmdline[0] if cmdline else "")
    return Alert.new(
        rule="R-BYPASS",
        severity="high",
        summary=f"{basename} started with {flag}",
        pids=[],
        exe=exe,
        basename=basename,
        cmdline=list(cmdline),
        cwd=cwd,
        evidence={"flag": flag, "flags": flags},
    )


def _path_under(path: Path, roots: Sequence[Path]) -> bool:
    resolved = path.resolve()
    for root in roots:
        root_r = Path(root).resolve()
        if resolved == root_r:
            return True
        try:
            resolved.relative_to(root_r)
            return True
        except ValueError:
            continue
    return False


def _is_editor(
    writer_exe: str | None,
    editor_allowlist: frozenset[str] | set[str],
) -> bool:
    return _basename(writer_exe) in editor_allowlist


def _is_sentinel_writer(
    writer_exe: str | None,
    writer_cmdline: Sequence[str] | None = None,
) -> bool:
    """True when the writer is Sentinel itself (skip R-SELF)."""
    base = _basename(writer_exe).lower()
    if base.startswith("sentinel"):
        return True
    # python -m sentinel… / python …/sentinel/…
    if base.startswith("python"):
        tokens = [t.lower() for t in (writer_cmdline or ())]
        for i, tok in enumerate(tokens):
            if tok in ("-m", "--module") and i + 1 < len(tokens):
                if tokens[i + 1] == "sentinel" or tokens[i + 1].startswith(
                    "sentinel."
                ):
                    return True
            if "sentinel" in tok.replace("\\", "/").split("/"):
                return True
    return False


def evaluate_write(
    path: Path,
    writer_pid: int | None,
    writer_exe: str | None,
    *,
    self_paths: Sequence[Path] | None = None,
    watch_paths: Sequence[Path] | None = None,
    editor_allowlist: frozenset[str] | set[str] | None = None,
    writer_cmdline: Sequence[str] | None = None,
) -> Alert | None:
    path = Path(path)
    editors = (
        DEFAULT_EDITOR_ALLOWLIST
        if editor_allowlist is None
        else frozenset(editor_allowlist)
    )
    writer_base = _basename(writer_exe)
    paths = [str(path.resolve())]

    if self_paths and _path_under(path, self_paths):
        if _is_sentinel_writer(writer_exe, writer_cmdline):
            return None
        return Alert.new(
            rule="R-SELF",
            severity="high",
            summary=f"write to sentinel path by {writer_base or 'unknown'}",
            pids=[writer_pid] if writer_pid is not None else [],
            exe=writer_exe or "",
            basename=writer_base,
            cmdline=list(writer_cmdline) if writer_cmdline is not None else [],
            cwd="",
            evidence={"path": paths[0]},
            paths=paths,
            writer_pid=writer_pid,
        )

    if watch_paths and _path_under(path, watch_paths):
        if _is_editor(writer_exe, editors):
            return None
        return Alert.new(
            rule="R-HOOK-WRITE",
            severity="high",
            summary=f"write to watched path by {writer_base or 'unknown'}",
            pids=[writer_pid] if writer_pid is not None else [],
            exe=writer_exe or "",
            basename=writer_base,
            cmdline=[],
            cwd="",
            evidence={"path": paths[0]},
            paths=paths,
            writer_pid=writer_pid,
        )

    return None


def _as_proc(item: ProcSnapshot | Mapping[str, Any]) -> ProcSnapshot:
    if isinstance(item, ProcSnapshot):
        return item
    return ProcSnapshot(
        pid=int(item["pid"]),
        ppid=int(item["ppid"]),
        cmdline=list(item.get("cmdline") or []),
        exe=str(item.get("exe") or ""),
        cwd=str(item.get("cwd") or ""),
        comm=str(item.get("comm") or ""),
    )


def _proc_basename(proc: ProcSnapshot) -> str:
    return (
        _basename(proc.exe)
        or _basename(proc.comm)
        or _basename(proc.cmdline[0] if proc.cmdline else "")
    )


def _is_agent(proc: ProcSnapshot, agent_basenames: frozenset[str] | set[str]) -> bool:
    return _proc_basename(proc) in agent_basenames


def _is_shell(proc: ProcSnapshot) -> bool:
    return _proc_basename(proc) in SHELL_BASENAMES


def _is_net_helper(proc: ProcSnapshot) -> bool:
    return _proc_basename(proc) in NET_HELPER_BASENAMES


def _shell_c_argument(cmdline: Sequence[str]) -> str | None:
    """Return the command string after -c / clustered -c flags, if any."""
    args = list(cmdline[1:])
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("-c", "--command"):
            return args[i + 1] if i + 1 < len(args) else ""
        if tok.startswith("-") and not tok.startswith("--"):
            if "c" in tok[1:]:
                return args[i + 1] if i + 1 < len(args) else ""
        i += 1
    return None


def _is_pipe_to_shell(proc: ProcSnapshot) -> bool:
    if not _is_shell(proc):
        return False
    command = _shell_c_argument(proc.cmdline)
    blob = command if command is not None else " ".join(proc.cmdline)
    return _PIPE_TO_SHELL_RE.search(blob) is not None


def _is_interactive_shell(proc: ProcSnapshot) -> bool:
    if not _is_shell(proc):
        return False
    if _shell_c_argument(proc.cmdline) is not None:
        return False
    args = list(proc.cmdline[1:])
    for tok in args:
        if tok in ("-i", "--interactive"):
            return True
        if tok.startswith("-") and not tok.startswith("--") and "i" in tok[1:]:
            return True
        if tok.startswith("-"):
            continue
        # Non-option arg is a script path, not an interactive shell.
        return False
    return True


def _child_kind(proc: ProcSnapshot) -> str | None:
    if _is_pipe_to_shell(proc):
        return "curl|bash"
    if _is_interactive_shell(proc):
        return "interactive-shell"
    if _is_net_helper(proc):
        return "net-helper"
    return None


def _agent_ancestor(
    proc: ProcSnapshot,
    by_pid: dict[int, ProcSnapshot],
    agent_basenames: frozenset[str] | set[str],
) -> ProcSnapshot | None:
    seen: set[int] = set()
    current = by_pid.get(proc.ppid)
    while current is not None and current.pid not in seen:
        seen.add(current.pid)
        if _is_agent(current, agent_basenames):
            return current
        current = by_pid.get(current.ppid)
    return None


def evaluate_child_shell(
    procs: Sequence[ProcSnapshot | Mapping[str, Any]],
    *,
    agent_basenames: Iterable[str] | None = None,
) -> list[Alert]:
    """Alert when an agent parent spawns a surprise shell or net helper."""
    snapshots = [_as_proc(p) for p in procs]
    agents = (
        frozenset(DEFAULT_AGENT_BASENAMES)
        if agent_basenames is None
        else frozenset(agent_basenames)
    )
    by_pid = {p.pid: p for p in snapshots}
    alerts: list[Alert] = []
    seen_children: set[int] = set()
    for proc in snapshots:
        if proc.pid in seen_children:
            continue
        if _is_agent(proc, agents):
            continue
        kind = _child_kind(proc)
        if kind is None:
            continue
        parent = _agent_ancestor(proc, by_pid, agents)
        if parent is None:
            continue
        seen_children.add(proc.pid)
        child_base = _proc_basename(proc)
        parent_base = _proc_basename(parent)
        if kind == "curl|bash":
            summary = f"{parent_base} spawned curl|bash ({child_base})"
        elif kind == "interactive-shell":
            summary = f"{parent_base} spawned interactive {child_base}"
        else:
            summary = f"{parent_base} spawned net helper {child_base}"
        alerts.append(
            Alert.new(
                rule="R-CHILD-SHELL",
                severity="high",
                summary=summary,
                pids=[parent.pid, proc.pid],
                exe=proc.exe or (proc.cmdline[0] if proc.cmdline else ""),
                basename=child_base,
                cmdline=list(proc.cmdline),
                cwd=proc.cwd,
                parent={
                    "pid": parent.pid,
                    "exe": parent.exe or (parent.cmdline[0] if parent.cmdline else ""),
                    "basename": parent_base,
                },
                evidence={
                    "kind": kind,
                    "child_pids": [proc.pid],
                    "parent_pid": parent.pid,
                },
            )
        )
    return alerts
