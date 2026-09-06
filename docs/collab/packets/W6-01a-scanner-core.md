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
  the installed scanner as an argv array with a timeout, writes the raw report under
  `state_dir()/scans/<tree_hash>.json` with mode 0600, and prints the parsed `ScanResult`.
  If the scanner is not installed it exits non-zero with a one-line instruction and no traceback.
- **Sandbox**: the runner invokes the scanner through `systemd-run --user --scope` with
  `PrivateNetwork=yes` unless OSV lookups are enabled (D-006 is open; default off, so network off),
  `MemoryMax`, `RuntimeMaxSec`, and a read-only bind of the scanned root. If `systemd-run` is unavailable the
  runner still works, but records `sandbox="none"` in the result so the panel can say so.
- **`scripts/install-scanner.sh`**: creates `~/.local/share/tav.sentinel/scanner` as its own venv, installs
  the pinned tag, prints what it will do and requires `--yes` to proceed. Never called automatically.
- **`tree_hash(root)`**: a stable sha256 over the sorted relative paths and their content hashes, skipping
  anything over the size cap, so a re-scan can be keyed and the allowlist can pin a specific tree.

## Tests
`tests/test_scan.py`: parses a recorded fixture report into a `ScanResult` (fixture committed under
`tests/fixtures/`); a malformed or truncated report yields `ok=False` with an error rather than raising;
`code_snippet` never appears in the parsed result; the recommendation mapping; `tree_hash` is stable across
mtime changes and differs when a byte changes; the runner builds an argv array (never a shell string) and
honours the timeout; a missing scanner exits non-zero with the instruction line.

## Acceptance
```
.venv/bin/pytest -q
grep -rn "shell=True" src/sentinel/scan.py    # no output
```

## Forbidden
Importing SkillSpector into the daemon or the CLI; any network call from `sentinel` or the daemon; storing
file bodies or code snippets in alerts or state; installing anything automatically; `sudo`; editing
tests/joint/.
