# W6-01a Scanner core: ScanResult, the runner, and its sandbox

Depends on: W3-02 (merged)   Parallel-safe with: W3-05, W3-06, UX-02b

## Goal
Sentinel can run SkillSpector over a directory that just appeared, parse the result into a small typed record,
and surface a verdict, without the daemon ever importing the scanner or reaching the network itself.

## Context (verified)
1. SkillSpector is not on PyPI. It installs from `git+https://github.com/NVIDIA/skillspector.git@<tag>`; the
   tag pinned for this repository's own self-scan is `v2.9.6` (see
   `docs/collab/reviews/SKILLSPECTOR-SELF-SCAN.md`). `--no-llm` is the default mode and needs no API key.
2. Its JSON output has top-level keys `skill`, `risk_assessment` (`score`, `severity`, `recommendation`),
   `components`, `issues`, `suppressed_count`, `suppressed`, `metadata`, `execution_successful`,
   `analysis_completeness`. Each issue carries `category`, `severity`, `confidence`, `location`
   (`{file, start_line, end_line}`), `finding`, `explanation`, `remediation`, `code_snippet`.
3. `risk_assessment.recommendation` is one of `SAFE`, `CAUTION`, `DO_NOT_INSTALL`; the plan's mapping is
   allow / review / block, and Sentinel must use the tool's own verdict rather than deriving one.
4. A baseline file suppresses findings by exact fingerprint and by glob rules (`id`, `path`, `message`);
   `docs/SUPPRESSION.md` in the tool describes the format. This repository ships `.skillspector-baseline.yaml`.
5. The daemon runs as the user and makes no network calls; anything that does must be a separate process.

## Changes
- **`src/sentinel/scan.py`**: `@dataclass(frozen=True) ScanResult(tool, version, root, tree_hash, score,
  severity, recommendation, counts, top, report_path, ok, error)`; `parse_report(data) -> ScanResult` that
  reads only the keys in claim 2 and never carries `code_snippet` or any file body into the result;
  `top` is at most three `{title, file, line}` entries built from `finding` plus `location`.
  `severity_for(recommendation)` maps SAFE -> low, CAUTION -> medium, DO_NOT_INSTALL -> high.
- **`sentinel-scan` entry point** (`cli.scan_main`): `sentinel-scan <root> [--json] [--timeout N]`. It runs
  the installed scanner as an argv array with a timeout, writes a *sanitized* report under
  `state_dir()/scans/<tree_hash>.json` with mode 0600 inside a 0700 directory, and prints the parsed
  `ScanResult`. Sanitized means: `code_snippet` is removed from every entry of `issues` and `suppressed`
  before anything touches disk (in the committed self-scan JSON those are the only fields carrying file
  bodies; `components` carries path, lines, size, type and executable only), and any other string field over
  1 KiB inside an issue is truncated with a marker. The raw scanner output never lands on disk (squad
  finding: it is third-party output containing file bodies, which breaks the metadata-only invariant).
  If the scanner is not installed it exits non-zero with a one-line instruction and no traceback.
- **Sandbox**: the runner invokes the scanner as a transient user *service*, never a scope (a scope cannot
  apply sandboxing properties): `systemd-run --user --wait --collect --pipe -p PrivateNetwork=yes
  -p MemoryMax=1G -p RuntimeMaxSec=<timeout> -p ProtectSystem=strict -p ReadOnlyPaths=<root> -- <argv>`,
  with `PrivateNetwork` dropped only when OSV lookups are enabled (D-006 is open; default off, so network
  off). Verified on the Owner's machine 2026-09-06: `systemd-run --user -p PrivateNetwork=yes --wait
  --collect true` exits 0 unprivileged (systemd 261), and so does `unshare -rn true`, which is the fallback
  when `systemd-run` is unavailable. If neither works the runner still runs but records `sandbox="none"` in
  the result so the panel can say so.
- **`scripts/install-scanner.sh`**: creates `~/.local/share/tav.sentinel/scanner` as its own venv, installs
  the pinned tag, prints what it will do and requires `--yes` to proceed. Never called automatically.
- **`tree_hash(root)`**: a stable sha256 over the sorted relative paths and their content hashes, so a
  re-scan can be keyed and the allowlist can pin a specific tree. The root is agent-controlled, so: resolve
  the root once and refuse it if it is not a directory; walk with `os.scandir` without following symlinks (a
  symlink contributes its target *string*, never the target's content); hash only regular files, streamed
  through sha256 in 64 KiB chunks, never read whole; files over `hash_max_bytes` (1 MiB) contribute
  path and size only and are counted in `skipped`; stop at 5000 files or depth 12 and set `truncated`; retain
  no content, only digests. This is the only place Sentinel itself opens files under the scanned root.

## Tests
`tests/test_scan.py`: parses a recorded fixture report into a `ScanResult` (fixture committed under
`tests/fixtures/`); a malformed or truncated report yields `ok=False` with an error rather than raising;
`code_snippet` never appears in the parsed result; the recommendation mapping; `tree_hash` is stable across
mtime changes and differs when a byte changes; the runner builds an argv array (never a shell string) and
honours the timeout; a missing scanner exits non-zero with the instruction line; the file written under
`state_dir()/scans/` is read back and contains no `code_snippet` key at any depth; `tree_hash` over a fixture
holding a symlink to `/etc/hostname` never opens the target (assert with a monkeypatched `open`) and a
1.5 MiB file is counted in `skipped` without being read.

## Acceptance
```
.venv/bin/pytest -q
grep -rn "shell=True" src/sentinel/scan.py    # no output
```

## Fact-check
Claims 1 to 5. For 1 and 2 run the installed scanner from its own venv
(`~/.local/share/tav.sentinel/scanner/bin/skillspector --version`, then `scan --no-llm --format json` over a
small directory) and compare the keys with `docs/collab/reviews/skillspector-self.json`; for 3 quote the
tool's README mapping; for 4 quote `docs/SUPPRESSION.md` at the pinned tag; for 5 show that
`grep -rn "urllib\|http\|socket" src/sentinel/daemon.py` finds nothing network-bound. Re-run the two
sandbox commands from Changes on the machine you run on. Mark each CONFIRMED / REFUTED / UNVERIFIED.

## Non-goals
- LLM-assisted scanning (`SKILLSPECTOR_PROVIDER`) and OSV lookups (D-006); both stay off and are never set
  in the daemon's environment.
- SkillSpector's MCP server mode (unauthenticated HTTP transport; excluded from v1).
- Triggering scans from the daemon on directory creation (W6-01b) and the panel's risk bar wiring (W6-01c).
- Baseline management for scanned skills; only this repository's own baseline exists.

## Forbidden
Importing SkillSpector into the daemon or the CLI; any network call from `sentinel` or the daemon; storing
file bodies or code snippets in alerts or state; installing anything automatically; `sudo`; editing
tests/joint/.

## Report
`docs/collab/reports/W6-01a-report.md`
