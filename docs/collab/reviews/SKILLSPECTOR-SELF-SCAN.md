# SkillSpector self-scan (gate G1, step 2)

Date: 2026-09-06. Tool: SkillSpector 2.9.6, pinned by tag from
`git+https://github.com/NVIDIA/skillspector.git@v2.9.6`, installed into its own venv outside this repo.
It is not on PyPI. Mode: `--no-llm` (the default), heuristic filtering, no provider key set anywhere.

Target: a clean `git archive HEAD` export, not the working tree. Scanning the working tree is wrong twice
over — it walks `.venv/` and every `.worktrees/grok-*` copy, which multiplied 57 findings into 271 — and
the marketplace only ever sees an export.

```
skillspector scan <export> --no-llm --format json -o docs/collab/reviews/skillspector-self.json
  -> risk_assessment: score 100, CRITICAL, DO_NOT_INSTALL; 57 issues
skillspector scan <export> --no-llm --baseline .skillspector-baseline.yaml -o ...-baselined.json
  -> risk_assessment: score 0, LOW, SAFE; 0 issues, 57 suppressed
```

Per the gate's mapping (SAFE allow, CAUTION review, DO_NOT_INSTALL block), the raw result blocks the merge.
Every one of the 57 findings was read before anything was suppressed; what follows is that review.

## What the raw verdict is made of

| Where | Count | What the scanner matched | Verdict |
|-------|-------|--------------------------|---------|
| `docs/**`, `*.md` | 24 | Prose describing the attacks Sentinel exists to detect: `curl \| bash`, `credentials.json`, `systemctl --user enable`, `~/.claude/settings.json` | False positive. A threat model that names its threats is not an implementation of them. |
| `tests/**` | 11 | Hostile argv, secret-shaped values and watched paths in fixtures | False positive by construction: several of those fixtures exist to prove the values are redacted. |
| `scripts/install-*.sh`, `track-b/**` | 9 | `systemctl --user enable`, `chmod 755/644` | True but intended: installing a per-user unit is the product. The mode bits are on unit files and scripts; state files are written 0600 inside 0700 dirs by `sentinel.fsutil`, which the scanner does not model. |
| `scripts/collab/**` | 1 | `curl` in the Grok driver's connectivity preflight | Developer tooling, never installed by the plugin, and the request sends no data (`-o /dev/null`). |
| `LICENSE`, `pyproject.toml` | 4 | Apache-2.0 text; dependency metadata | Noise. The package is stdlib-only. |
| `src/**` | 11 | `subprocess.run` (5), `getattr` (2), the literal `"sudo "` (1), the Summarize network path (3) | See below. |

## The source findings, one by one

- **`action.py` `getattr` x2** — attribute names come from the fixed `SEVERITIES` tuple, never from user or
  alert data. False positive.
- **`health.py` `subprocess.run` x4, `notify.py` x1, `investigate.py` x1** — every call passes an argv array
  with a timeout and no shell. `notify.run` carries the 5 s timeout added for finding S7. This is the
  project's standing rule, asserted in tests: argv arrays only, never a shell string.
- **`rules.py` `"sudo "`** — a literal in the list of argv patterns Sentinel looks for in a *monitored*
  agent's command line. The scanner flagged the detector as the threat.
- **`summarize.py`: CRITICAL "tainted flow", `os.environ` to `urllib.request.urlopen`, plus the endpoint
  literal** — **a true positive, and intentional.** Summarize is an opt-in, click-triggered oneshot that
  posts a redacted metadata bundle; the daemon imports no cloud SDK and makes no network call. This is our
  own finding **S10** in `SECURITY-REVIEW-2026-09-05.md`, and the fix is scheduled: **W5-06** moves the
  endpoint out of the environment into config behind a provider allowlist and shows the bundle before it is
  sent. It is suppressed here with that reasoning recorded in the baseline entry itself, not hidden.

## The baseline

`.skillspector-baseline.yaml` is committed at the repo root. Two deliberate choices:

1. **`src/` is suppressed per finding, by fingerprint — never by glob.** Any *new* finding in the daemon or
   the CLI therefore shows up on the next scan instead of being pre-forgiven.
2. Everything else (docs, tests, install scripts, dev tooling, licence, metadata) is suppressed by
   drift-tolerant path globs, each carrying its own reason, so ordinary edits do not churn the file.

Re-run the gate with:

```
skillspector scan <export> --no-llm --baseline .skillspector-baseline.yaml --format json
```

A finding that is not in the baseline blocks the merge until it is read and either fixed or justified here.

## Still open

- `/security-review` needs an `origin` remote and has never run; do it with the first push (publishing step).
- W5-06 closes S10 for real. Until then the CRITICAL is suppressed but not fixed, and this document is the
  record of that.
