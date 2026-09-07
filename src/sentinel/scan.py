# SPDX-License-Identifier: Apache-2.0
"""SkillSpector scanner integration: parse, sanitize, sandbox, tree-hash.

Nothing here is imported by sentinel.daemon or sentinel.cli's module-level
imports (Forbidden: "the daemon must never import scan.py's runner; the
scanner runs only through the sentinel-scan entry point"). This module is
also the *only* place in Sentinel that opens files under a scanned root
(tree_hash) or shells out to a third-party scanner (run_scan) -- everywhere
else works from paths and hashes only, matching invariant 2.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.fsutil import ensure_private_dir, write_private_atomic
from sentinel.paths import state_dir

# -- tree_hash tuning knobs (module attributes so tests can monkeypatch them
#    without materializing thousands of real files) -----------------------
MAX_FILES = 5000
MAX_DEPTH = 12
HASH_MAX_BYTES = 1 * 1024 * 1024  # 1 MiB
_CHUNK_SIZE = 64 * 1024  # 64 KiB, per REQ21: stream, never read whole

# -- sanitization ------------------------------------------------------------
MAX_FIELD_BYTES = 1024  # 1 KiB
TRUNCATION_MARKER = "...[truncated]"

# -- runner defaults ----------------------------------------------------------
DEFAULT_TIMEOUT_S = 120.0
SCANNER_VENV = Path.home() / ".local" / "share" / "tav.sentinel" / "scanner"
SCANNER_BIN_NAME = "skillspector"
INSTALL_INSTRUCTIONS = (
    "SkillSpector is not installed; run scripts/install-scanner.sh --yes to install it."
)

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_RECOMMENDATION_TO_SEVERITY = {"SAFE": "low", "CAUTION": "medium", "DO_NOT_INSTALL": "high"}


class ScannerNotInstalled(RuntimeError):
    """Raised by run_scan when no skillspector binary can be resolved."""


# ---------------------------------------------------------------------------
# ScanResult / parse_report / severity_for
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """Metadata-only record of one scan. Never carries file bodies.

    root/tree_hash/report_path/sandbox are filled in by the runner (run_scan),
    not by parse_report: parse_report only ever sees the scanner's own JSON,
    which knows nothing about the local filesystem path it was pointed at,
    the tree hash sentinel computed separately, where sentinel chose to write
    the sanitized report, or which sandbox sentinel used to run it.
    """

    tool: str = ""
    version: str = ""
    root: str | None = None
    tree_hash: str | None = None
    score: float | None = None
    severity: str | None = None
    recommendation: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    top: list[dict[str, Any]] = field(default_factory=list)
    report_path: str | None = None
    ok: bool = True
    error: str | None = None
    sandbox: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def severity_for(recommendation: str) -> str:
    """Map SkillSpector's own recommendation to Sentinel's severity bucket.

    Fails closed: an unrecognized recommendation raises rather than silently
    returning "low" -- under-classifying an unknown verdict from a third-party
    scanner would be a real regression against the threat model.
    """
    try:
        return _RECOMMENDATION_TO_SEVERITY[recommendation]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"unknown recommendation: {recommendation!r}") from exc


def _issue_sort_key(issue: dict[str, Any]) -> tuple:
    severity = issue.get("severity") if isinstance(issue, dict) else None
    rank = _SEVERITY_RANK.get(severity, 99)
    confidence = issue.get("confidence") if isinstance(issue, dict) else None
    if not isinstance(confidence, (int, float)):
        confidence = 0
    location = issue.get("location") if isinstance(issue, dict) else None
    location = location if isinstance(location, dict) else {}
    file_ = location.get("file") or ""
    line = location.get("start_line")
    if not isinstance(line, int):
        line = 0
    return (rank, -confidence, file_, line)


def parse_report(data: dict[str, Any]) -> ScanResult:
    """Parse SkillSpector's JSON into a ScanResult. Never raises.

    Reads only the keys named in the packet's Context claim 2 (top-level
    skill, risk_assessment.{score,severity,recommendation}, components,
    issues, suppressed_count, suppressed, metadata, execution_successful,
    analysis_completeness; per-issue category, severity, confidence,
    location.{file,start_line,end_line}, finding, explanation, remediation,
    code_snippet) -- and of those, only score/recommendation/metadata feed
    ScanResult's fields. code_snippet, finding, explanation, remediation are
    never copied into the result: top[].title is built from `pattern` (a
    short human-readable label), never `finding` (which is raw source code
    in every observed fixture -- see Deviations in the packet report).
    """
    try:
        if not isinstance(data, dict):
            raise TypeError("scanner report is not a JSON object")
        metadata = data.get("metadata") or {}
        version = metadata.get("skillspector_version", "") if isinstance(metadata, dict) else ""

        risk = data["risk_assessment"]
        score = risk["score"]
        recommendation = risk["recommendation"]
        severity = severity_for(recommendation)

        issues = data.get("issues", [])
        if not isinstance(issues, list):
            raise TypeError("issues must be a list")

        counts: dict[str, int] = {}
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            sev = issue.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        ranked = sorted((i for i in issues if isinstance(i, dict)), key=_issue_sort_key)
        top: list[dict[str, Any]] = []
        for issue in ranked[:3]:
            location = issue.get("location")
            location = location if isinstance(location, dict) else {}
            top.append(
                {
                    "title": issue.get("pattern") or "",
                    "file": location.get("file"),
                    "line": location.get("start_line"),
                }
            )

        return ScanResult(
            tool="skillspector",
            version=version,
            score=score,
            severity=severity,
            recommendation=recommendation,
            counts=counts,
            top=top,
            ok=True,
            error=None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return ScanResult(ok=False, error=f"malformed scanner report: {exc}")


# ---------------------------------------------------------------------------
# Sanitization: code_snippet stripped, oversized strings truncated, before
# anything touches disk. Pure function -- no I/O -- so the write path always
# has a sanitized dict in hand before it opens a file.
# ---------------------------------------------------------------------------


def _truncate(value: str, limit: int = MAX_FIELD_BYTES) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore") + TRUNCATION_MARKER


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _truncate(value)
    if isinstance(value, dict):
        return {k: _sanitize_value(v) for k, v in value.items() if k != "code_snippet"}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


def _sanitize_entry(entry: Any) -> Any:
    if not isinstance(entry, dict):
        return entry
    return {k: _sanitize_value(v) for k, v in entry.items() if k != "code_snippet"}


def sanitize_report(data: dict[str, Any]) -> dict[str, Any]:
    """Strip code_snippet and truncate oversized strings in issues/suppressed.

    Recurses into nested dicts/lists within each entry so a renamed or
    relocated code_snippet-shaped field cannot slip a file body through --
    the sanitizer removes the key by name at every depth, not just the top
    level of each issue.
    """
    sanitized = dict(data)
    sanitized["issues"] = [_sanitize_entry(e) for e in data.get("issues", []) or []]
    sanitized["suppressed"] = [_sanitize_entry(e) for e in data.get("suppressed", []) or []]
    return sanitized


# ---------------------------------------------------------------------------
# tree_hash: the only place Sentinel itself opens files under a scanned root.
# ---------------------------------------------------------------------------


def _looks_like_auth(name: str) -> bool:
    """Same filename heuristic as scout.classify_kind's 'auth' bucket.

    Not duplicated by import (scan.py stays decoupled from scout.py) but by
    the same substring rule, so a real (non-symlink) file named e.g.
    credentials.json or .auth_token inside a scanned skill is never opened
    by tree_hash -- it is recorded as path+size only, the same fallback
    already used for oversized files. This is defense the packet text does
    not itself specify; see Deviations in the report.
    """
    lowered = name.lower()
    return "auth" in lowered or "credential" in lowered


@dataclass(frozen=True)
class TreeHashResult:
    digest: str
    files_hashed: int
    skipped: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    truncated: bool = False


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(root: Path) -> TreeHashResult:
    """Stable sha256 over sorted relative paths + content hashes.

    mtime-independent by construction (mtime is never read). A symlink
    contributes only its target path string (os.readlink), the target is
    never opened. Files over HASH_MAX_BYTES and files whose name matches the
    auth heuristic contribute only path+size and are counted in `skipped`.
    The walk stops at MAX_FILES total entries or MAX_DEPTH directories and
    sets `truncated` when it does. No scanned-root file content is retained;
    only digests survive this function.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    entries: list[tuple[str, str, str | None, int | None]] = []
    skipped: list[tuple[str, int]] = []
    state = {"truncated": False, "count": 0}

    def walk(dir_path: Path, rel_prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            state["truncated"] = True
            return
        try:
            with os.scandir(dir_path) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError:
            return
        for entry in children:
            if state["count"] >= MAX_FILES:
                state["truncated"] = True
                return
            rel = f"{rel_prefix}{entry.name}"
            try:
                is_symlink = entry.is_symlink()
            except OSError:
                continue
            if is_symlink:
                try:
                    target = os.readlink(entry.path)
                except OSError:
                    target = ""
                entries.append((rel, "symlink", target, None))
                state["count"] += 1
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                walk(Path(entry.path), rel + "/", depth + 1)
                continue
            try:
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                continue
            if not is_file:
                continue
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if size > HASH_MAX_BYTES or _looks_like_auth(entry.name):
                skipped.append((rel, size))
                entries.append((rel, "skipped", None, size))
                state["count"] += 1
                continue
            try:
                digest = _sha256_file(entry.path)
            except OSError:
                continue
            entries.append((rel, "file", digest, size))
            state["count"] += 1

    walk(root, "", 0)
    entries.sort(key=lambda e: e[0])

    overall = hashlib.sha256()
    for rel, kind, content, size in entries:
        overall.update(rel.encode("utf-8"))
        overall.update(b"\0")
        overall.update(kind.encode("utf-8"))
        overall.update(b"\0")
        if content is not None:
            overall.update(content.encode("utf-8"))
        if size is not None:
            overall.update(str(size).encode("utf-8"))
        overall.update(b"\n")

    return TreeHashResult(
        digest=overall.hexdigest(),
        files_hashed=sum(1 for e in entries if e[1] == "file"),
        skipped=tuple(skipped),
        truncated=state["truncated"],
    )


# ---------------------------------------------------------------------------
# Sandbox argv builder
# ---------------------------------------------------------------------------


def _forbidden_for_unit_property(path_str: str) -> bool:
    """True if path_str would be misparsed by systemd's ReadOnlyPaths= grammar.

    ReadOnlyPaths= takes a whitespace-separated list of absolute paths, with
    leading '-' (ignore-if-missing) and '+' (rebase to RootDirectory=)
    grammar-significant (systemd.exec(5); confirmed on this machine, systemd
    261 -- ':' is NOT special here, that syntax belongs only to BindPaths=).
    """
    return any(c.isspace() for c in path_str) or path_str.startswith(("-", "+"))


def build_sandbox_argv(
    inner_argv: list[str],
    *,
    root: Path,
    timeout: float,
    osv_lookup: bool = False,
) -> tuple[list[str], str]:
    """Wrap inner_argv for the sandbox; returns (full_argv, sandbox_name).

    sandbox_name is one of "systemd-run", "unshare", "none" -- "none" means
    neither tool was available and inner_argv is returned unsandboxed so the
    caller can still run the scanner, but must record sandbox="none" on the
    result (REQ16) so the panel can say so.
    """
    resolved_root = str(Path(root).resolve())
    if _forbidden_for_unit_property(resolved_root):
        raise ValueError(
            f"root is not safe to pass to systemd's ReadOnlyPaths=: {resolved_root!r}"
        )
    runtime_max = max(1, int(timeout))

    systemd_run = shutil.which("systemd-run")
    if systemd_run:
        argv = [
            systemd_run,
            "--user",
            "--wait",
            "--collect",
            "--pipe",
        ]
        if not osv_lookup:
            argv += ["-p", "PrivateNetwork=yes"]
        argv += [
            "-p", "MemoryMax=1G",
            "-p", f"RuntimeMaxSec={runtime_max}",
            "-p", "ProtectSystem=strict",
            "-p", f"ReadOnlyPaths={resolved_root}",
            "--",
            *inner_argv,
        ]
        return argv, "systemd-run"

    unshare = shutil.which("unshare")
    if unshare:
        return [unshare, "-rn", *inner_argv], "unshare"

    return list(inner_argv), "none"


# ---------------------------------------------------------------------------
# Runner: resolve the scanner, sandbox+invoke it, sanitize, write, return.
# ---------------------------------------------------------------------------


def resolve_scanner_binary() -> Path | None:
    venv_bin = SCANNER_VENV / "bin" / SCANNER_BIN_NAME
    if venv_bin.exists():
        return venv_bin
    which = shutil.which(SCANNER_BIN_NAME)
    return Path(which) if which else None


def scan_report_path(tree_digest: str) -> Path:
    return state_dir() / "scans" / f"{tree_digest}.json"


def run_scan(
    root: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    osv_lookup: bool = False,
) -> ScanResult:
    """Run the scanner over root inside a sandbox and return a filled ScanResult.

    Raises ScannerNotInstalled if no skillspector binary can be resolved (the
    caller prints the one-line install instruction and exits non-zero -- this
    function itself never prints). Raises NotADirectoryError if root is not a
    directory. Never raises on a malformed/timed-out scanner run; that comes
    back as ScanResult(ok=False, error=...).
    """
    root = Path(root).resolve()
    th = tree_hash(root)  # raises NotADirectoryError if root is bad

    binary = resolve_scanner_binary()
    if binary is None:
        raise ScannerNotInstalled(INSTALL_INSTRUCTIONS)

    inner_argv = [str(binary), "scan", "--no-llm", "--format", "json", str(root)]
    argv, sandbox_name = build_sandbox_argv(
        inner_argv, root=root, timeout=timeout, osv_lookup=osv_lookup
    )

    try:
        proc = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ScanResult(
            root=str(root),
            tree_hash=th.digest,
            sandbox=sandbox_name,
            ok=False,
            error=f"scanner invocation failed: {exc}",
        )

    try:
        raw = json.loads(proc.stdout or "")
    except json.JSONDecodeError as exc:
        return ScanResult(
            root=str(root),
            tree_hash=th.digest,
            sandbox=sandbox_name,
            ok=False,
            error=f"scanner produced invalid JSON: {exc}",
        )

    parsed = parse_report(raw)
    report_path: str | None = None
    if isinstance(raw, dict):
        sanitized = sanitize_report(raw)
        dest = scan_report_path(th.digest)
        ensure_private_dir(dest.parent)
        write_private_atomic(dest, json.dumps(sanitized, indent=2, sort_keys=True) + "\n")
        report_path = str(dest)

    return dataclasses.replace(
        parsed,
        root=str(root),
        tree_hash=th.digest,
        report_path=report_path,
        sandbox=sandbox_name,
    )
