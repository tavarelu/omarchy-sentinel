# SPDX-License-Identifier: Apache-2.0
"""Per-vendor bypass knowledge and argv redaction (W3-05).

This module is the single source of truth for which agent binaries Sentinel
knows about, which argv switches on each one mean "skip the permission
prompt", and which config-file keys mean the same thing when set outside
argv. ``rules.extract_bypass_flags`` folds this table's ``argv_bypass``
entries into its own detection (W3-03 extends the table further; W3-04
reuses ``redact_argv`` for child-process argv).

Nothing here reads a vendor config file's body — ``config_bypass`` entries
are declarative metadata (path + key path + values that would mean bypass)
for a hash-and-diff check to consult later; this module itself never opens
one. See docs/collab/reports/W3-05-report.md, Deviations, for why the
scout-side hash-and-diff rule (R-BYPASS-CONFIG) is not wired up yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# A bare token ("--yolo") or a value-taking pair: the flag name plus the set
# of values that mean bypass ("--permission-mode", {"bypassPermissions"}).
ArgvBypassToken = str
ArgvBypassPair = tuple[str, frozenset[str]]
ArgvBypassEntry = ArgvBypassToken | ArgvBypassPair


@dataclass(frozen=True)
class ConfigBypass:
    """One config-file key whose value can mean bypass, without reading it.

    ``path`` is relative to $HOME. ``key_path`` is a dotted TOML/JSON key
    path (for example ``("ui", "permission_mode")``). ``bypass_values`` are
    the values that would mean bypass *if* Sentinel were allowed to read
    them — it is not: the spec (AGENTS.md invariant 2 / PROTOCOL.md sec.9
    invariant 2) forbids reading file bodies, so a config-bypass check may
    only hash this file and compare with the last known hash. This dataclass
    exists to document what changed conceptually, not to be read by code
    that opens the file.
    """

    path: str
    key_path: tuple[str, ...]
    bypass_values: frozenset[str]


@dataclass(frozen=True)
class Vendor:
    """One agent binary Sentinel recognizes.

    ``basenames`` must be non-empty (tests/test_vendors.py asserts this for
    every entry). ``argv_bypass`` and ``config_bypass`` may be empty/None
    when fact-check could not confirm real values on this machine (marked
    UNVERIFIED in the packet report) — an empty set costs nothing; a
    fabricated flag name would be worse than a false negative.
    """

    name: str
    basenames: frozenset[str]
    argv_bypass: frozenset[ArgvBypassEntry] = field(default_factory=frozenset)
    config_bypass: ConfigBypass | None = None


# ---------------------------------------------------------------------------
# Vendor table. Sourced from `<vendor> --help` run on this machine
# 2026-09-07 (see docs/collab/reports/W3-05-report.md, Fact-check claim 1)
# except where marked UNVERIFIED below.
# ---------------------------------------------------------------------------

VENDORS: tuple[Vendor, ...] = (
    Vendor(
        name="claude",
        basenames=frozenset({"claude"}),
        argv_bypass=frozenset(
            {
                "--dangerously-skip-permissions",
                (
                    "--permission-mode",
                    frozenset({"bypassPermissions", "dontAsk"}),
                ),
            }
        ),
        # `--allow-dangerously-skip-permissions` merely *enables the option*
        # (it still prompts unless the session also passes
        # --dangerously-skip-permissions); it is not itself a bypass and is
        # deliberately not listed here.
        config_bypass=None,  # no known config-file bypass toggle; UNVERIFIED
    ),
    Vendor(
        name="codex",
        basenames=frozenset({"codex"}),
        argv_bypass=frozenset(
            {
                "--dangerously-bypass-approvals-and-sandbox",
                ("--ask-for-approval", frozenset({"never"})),
                ("-a", frozenset({"never"})),
                ("--sandbox", frozenset({"danger-full-access"})),
                ("-s", frozenset({"danger-full-access"})),
            }
        ),
        # Packet context claim 2: "Codex approval_policy and sandbox_mode in
        # ~/.codex/config.toml". Exact bypass values UNVERIFIED (fact-check
        # could not confirm this file's real content without reading its
        # body, which is forbidden) — key path recorded for a future scout
        # check to hash against, values left as a documented placeholder.
        config_bypass=ConfigBypass(
            path=".codex/config.toml",
            key_path=("approval_policy",),
            bypass_values=frozenset({"never"}),
        ),
    ),
    Vendor(
        name="grok",
        basenames=frozenset({"grok"}),
        argv_bypass=frozenset(
            {
                "--always-approve",
                (
                    "--permission-mode",
                    frozenset({"bypassPermissions", "dontAsk"}),
                ),
            }
        ),
        # Packet context claim 2, confirmed on this machine 2026-09-06/07:
        # ~/.grok/config.toml has `permission_mode = "always-approve"` under
        # [ui].
        config_bypass=ConfigBypass(
            path=".grok/config.toml",
            key_path=("ui", "permission_mode"),
            bypass_values=frozenset({"always-approve"}),
        ),
    ),
    Vendor(
        name="gemini",
        basenames=frozenset({"gemini"}),
        argv_bypass=frozenset(
            {
                "--yolo",
                "-y",
                ("--approval-mode", frozenset({"yolo"})),
            }
        ),
        # Packet context claim 2: "Gemini --approval-mode yolo and
        # settings." Settings-file key path UNVERIFIED; left unset rather
        # than guessed.
        config_bypass=None,
    ),
    Vendor(
        name="cursor",
        # `cursor-agent` and `cursor` are both absent on this machine
        # (fact-check claim 1: UNVERIFIED, `which` finds neither). Basenames
        # are still recorded — REQ-1 only requires basenames be non-empty —
        # but argv_bypass is deliberately left empty rather than guessed;
        # a fabricated flag name is worse than a false negative.
        basenames=frozenset({"cursor-agent", "cursor"}),
        argv_bypass=frozenset(),
        config_bypass=None,
    ),
)


def vendor_basenames() -> frozenset[str]:
    """All recognized agent basenames across every vendor entry."""
    out: set[str] = set()
    for vendor in VENDORS:
        out.update(vendor.basenames)
    return frozenset(out)


def bare_bypass_tokens() -> frozenset[str]:
    """All bare (non-value-taking) bypass tokens, unioned across vendors."""
    out: set[str] = set()
    for vendor in VENDORS:
        for entry in vendor.argv_bypass:
            if isinstance(entry, str):
                out.add(entry)
    return frozenset(out)


def paired_bypass_flags() -> dict[str, frozenset[str]]:
    """flag -> the union of values across vendors that mean bypass for it."""
    out: dict[str, set[str]] = {}
    for vendor in VENDORS:
        for entry in vendor.argv_bypass:
            if isinstance(entry, tuple):
                flag, values = entry
                out.setdefault(flag, set()).update(values)
    return {flag: frozenset(values) for flag, values in out.items()}


# ---------------------------------------------------------------------------
# S4 redaction (packet Non-goals, security-review-mandated). Pure and
# vendor-independent so W3-04 can reuse it for child-process argv without
# knowing which vendor spawned it.
# ---------------------------------------------------------------------------

REDACTED = "<redacted>"

# Whole flag-name *components* (split on - and _) that mean "this flag's
# value is a secret". Component-based, not substring: "--author" must not
# match "auth" (only "author" as a whole word would), so the match is done
# on split components in _flag_is_sensitive, not via this regex directly.
_SENSITIVE_WORDS = frozenset({"auth", "token", "secret", "password", "apikey"})

# A bare (non-flag) token shaped like a live secret: a common `sk-...`
# style prefix, or a long opaque alphanumeric/dash/underscore blob. Applied
# only to tokens that do not start with "-" (flag values are handled by
# _flag_is_sensitive instead).
_BARE_SECRET_RE = re.compile(r"^(sk-[A-Za-z0-9_-]{4,}|[A-Za-z0-9_-]{24,})$")


def _flag_is_sensitive(flag: str) -> bool:
    """True when ``flag``'s own name (not a substring of it) names a secret.

    Component-based on -/_ separators so "--api-key" and "--auth_token"
    match while "--author" (contains "auth" only as a substring) does not.
    """
    body = flag.lstrip("-").lower()
    if not body:
        return False
    components = [c for c in re.split(r"[-_]+", body) if c]
    if not components:
        return False
    if any(c in _SENSITIVE_WORDS for c in components):
        return True
    for i in range(len(components) - 1):
        if components[i] == "api" and components[i + 1] == "key":
            return True
    return False


def redact_argv(argv: list[str]) -> tuple[list[str], bool]:
    """Replace secret-shaped argv values with ``<redacted>``.

    Protects invariant AGENTS.md sec. "Security invariants" #5 / #2 (no
    secrets in the repo, no file bodies/secrets in alerts or logs): argv
    reaching an alert or launches.jsonl must never carry a live credential.
    Pure and vendor-independent per the packet ("W3-04 reuses it ... must
    not depend on the vendor of the process").

    Returns the (possibly modified) argv and whether anything was redacted.
    """
    out = list(argv)
    redacted = False
    i = 0
    n = len(out)
    while i < n:
        token = out[i]
        if token.startswith("-"):
            name, sep, _value = token.partition("=")
            if sep:
                if _flag_is_sensitive(name):
                    out[i] = f"{name}={REDACTED}"
                    redacted = True
            elif _flag_is_sensitive(token) and i + 1 < n and not out[i + 1].startswith("-"):
                out[i + 1] = REDACTED
                redacted = True
                i += 1
        elif _BARE_SECRET_RE.match(token):
            out[i] = REDACTED
            redacted = True
        i += 1
    return out, redacted
