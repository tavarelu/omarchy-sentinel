from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

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
