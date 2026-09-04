# W3-01 Allowlist and Approve correctness
Depends on: none          Parallel-safe with: W3-02, W3-03, W3-05

## Goal
Approve suppresses exactly what the user approved, for every rule, with the four scopes meaning what the spec says: `session` until daemon restart, `24h` wall clock, `this-repo` the git repository (or the cwd tree when not in a repo), `forever` anywhere until revoked. Today Approve is a no-op for write-rule alerts and `forever` behaves like `this-repo`.

## Context
1. `cmd_approve` keys the fingerprint on `alert.cwd` (`src/sentinel/action.py:168`), which is the empty string for R-HOOK-WRITE and R-SELF alerts.
2. The daemon derives the location from `alert.cwd or alert.paths[0]` (`src/sentinel/daemon.py:265`) and tests fingerprints for that path and every parent (`daemon.py:271-276`). It never tests the empty prefix when paths exist, so an approval keyed on `""` can never match a write alert.
3. Reproduction on 2026-09-04 (scratch XDG dirs): approve a real R-HOOK-WRITE alert with scope forever, then `_is_alert_allowed` on an identical alert returns `False`.
4. `forever` approval from `/home/tav/Work/scratch/sub` allows `/home/tav/Work/scratch/sub/deeper`, does not allow `/home/tav/Work/scratch`, does not allow `/home/tav/Other`. So forever is subtree-bound and this-repo does not reach the repo root when the alert came from a subdirectory.
5. `_entry_allows` (`src/sentinel/allowlist.py:66`) only checks cwd for `this-repo`; the cwd restriction for the other scopes comes from the fingerprint itself embedding `cwd_prefix`.
6. `R-ALLOW-EXPIRE` (spec section 8, low severity) is not implemented anywhere: `grep -rn "R-ALLOW-EXPIRE" src/` is empty.

## Changes
- New module `src/sentinel/keys.py` with:
  - `alert_location(alert) -> str`: `alert.cwd` if non-empty, else `alert.paths[0]` if any, else `""`. Used by BOTH `action.py` and `daemon.py`. Delete the two private copies.
  - `alert_flag_set(alert) -> frozenset[str]`: single implementation replacing `_flag_set` in `action.py`, `daemon.py`, and `_flag_list` in `summarize.py`.
  - `repo_root(path) -> str`: nearest ancestor containing `.git` (file or dir), else the path itself. No subprocess.
  - `approval_prefix(alert, scope) -> str`: `""` for `session`, `24h`, `forever`; `repo_root(alert_location(alert))` for `this-repo`, except write rules (R-HOOK-WRITE, R-SELF) where `this-repo` means the exact path in `alert_location`.
- `allowlist.approve(fp, scope, cwd_prefix)` unchanged in signature; `cmd_approve` computes `prefix = approval_prefix(alert, scope)` and uses `fingerprint(rule, basename, flags, prefix)` and `approve(fp, scope, prefix)`.
- `daemon._is_alert_allowed`: candidates are `[""] + [location, *parents]`; for each, `fingerprint(rule, basename, flags, candidate)` then `is_allowed(fp, location)`. Load the persisted allowlist once per call (pass the loaded dict into a new `is_allowed_in(entries, fp, cwd, now)`; keep `is_allowed` as a thin wrapper).
- `allowlist._entry_allows`: `this-repo` uses `_cwd_matches_prefix(cwd, prefix)` as today; `24h` expiry as today; on an expired `24h` entry return `False` and surface `expired=True` so the daemon can emit one `R-ALLOW-EXPIRE` low alert (summary `"<basename> approval expired; pattern recurred"`, evidence `{"expired_scope": "24h", "fingerprint": fp}`) instead of the original high alert, then delete the expired entry.
- `sentinel-action <id> approve` prints the effective prefix and scope so the user sees what was approved.

## Tests
- `tests/test_keys.py`: `alert_location` for process and write alerts; `repo_root` with a temp git dir (create `.git` as a directory) and without; `approval_prefix` for all four scopes and both rule families.
- `tests/test_action.py::test_approve_write_alert_suppresses_daemon`: build an R-HOOK-WRITE alert via `evaluate_write`, `cmd_approve(id, "forever")`, assert `_is_alert_allowed` is `True` for a fresh identical alert.
- `tests/test_daemon_coalesce.py::test_forever_scope_is_global`: approve from `/a/b/c`, assert allowed at `/a/b/c/d`, `/a/b`, `/x/y`.
- `tests/test_daemon_coalesce.py::test_this_repo_scope_reaches_repo_root`: temp repo root with `.git`, alert from `root/sub`, approve `this-repo`, assert allowed at `root` and `root/other`, not allowed at `root/../sibling`.
- `tests/test_allowlist.py::test_24h_expiry_emits_allow_expire`: freeze `now`, approve 24h, advance 25h, assert daemon emits one `R-ALLOW-EXPIRE` with severity `low` and the persisted entry is removed.
- `tests/test_summarize_redaction.py` still green after `_flag_list` removal.

## Acceptance
```
.venv/bin/pytest -q                     # all green, count reported in the report
.venv/bin/python - <<'PY'
import os, sys, tempfile; d=tempfile.mkdtemp(); os.environ["XDG_STATE_HOME"]=d; os.environ["XDG_CONFIG_HOME"]=d
sys.path.insert(0,"src")
from pathlib import Path
from sentinel.rules import evaluate_write, evaluate_process
from sentinel.store import append_alert
from sentinel.action import cmd_approve
from sentinel.daemon import _is_alert_allowed
t=Path(d)/"settings.json"; t.write_text("{}")
a=evaluate_write(t,None,None,self_paths=[],watch_paths=[t]); append_alert(a); cmd_approve(a.id,"forever")
print("write-alert approved suppresses:", _is_alert_allowed(evaluate_write(t,None,None,self_paths=[],watch_paths=[t])))
p=evaluate_process(["claude","--yolo"],"/x/claude","/a/b/c"); append_alert(p); cmd_approve(p.id,"forever")
print("forever global:", all(_is_alert_allowed(evaluate_process(["claude","--yolo"],"/x/claude",c)) for c in ("/a/b/c/d","/a/b","/x/y")))
PY
# expected: both lines print True
```

## Fact-check
- Claims 1 through 6 above. For 3 and 4, rerun the reproduction in your worktree before changing code and paste the output.
- Verify that `Path.parents` of `/a/b/c` includes `/` and that the empty-prefix fingerprint is distinct from the `/` fingerprint (it is, by construction, but prove it with one assertion).

## Non-goals
- Kill, coalescing, sampler, scout. Those are W3-02 and W3-03.
- Revoke command (a later packet).

## Forbidden
- Changing the on-disk allowlist format without a migration note in the report.
- Reading any file body other than test fixtures.

## Report
`docs/collab/reports/W3-01-report.md`
