# W3-03 Scout v2: precise watchlist, project dirs, hot reload
Depends on: W3-05 (owns `src/sentinel/vendors.py`; this packet extends it)          Parallel-safe with: W3-07, UX-02b

## Goal
The daemon watches the files that actually control agents and nothing else, discovers project-level agent config, and picks up a refreshed watchlist without a restart. On the Chief's machine the watch root count drops from 134 to under 20 and a simulated plugin-marketplace refresh produces zero alerts.

## Context
1. `classify_kind` matches the substrings `hook` and `mcp` in ANY path component (`src/sentinel/scout.py:32-37`). Real scout output on 2026-09-04: 940 entries, 59 `hooks`, 48 `mcp`, 3 `auth`, 1 `settings`; 52 of the 54 resulting inotify directories are inside `~/.claude/plugins/marketplaces/claude-plugins-official/`, including `hookify/LICENSE` and `mcp-server-dev/README.md`.
2. Claude Code rewrites that marketplace directory on refresh (its mtime matched session start). Simulating one refresh through `Daemon.handle_write` produced 111 high alerts.
3. Files that matter and are NOT scouted: `~/.claude.json` (holds project trust and `mcpServers`), project-level `<repo>/.claude/settings.json` and `settings.local.json` (spec section 7 names project `.claude/`), `~/.grok/config.toml` (holds `permission_mode`, hooks, plugins), `~/.gemini/settings.json`, `~/.codex/config.toml`.
4. `DEFAULT_SEEDS` (`scout.py:12-20`) has no `.grok`, `.gemini`, or project roots.
5. The daemon ignores writes to `watchlist.json` (`src/sentinel/daemon.py:628` via `OPERATIONAL_NAMES`) and only reloads on overflow, watch loss, or start. The nightly `sentinel-inventory.timer` therefore has no effect on a running daemon.
6. `_path_under` calls `resolve()` on every root per event (`src/sentinel/rules.py:148-159`); measured 6.8 ms per ordinary write inside `~/.claude` with 134 roots. 157 files sit directly in watched directories, several written by Claude Code per turn.
7. `~/.claude/.credentials.json` is classified `auth` and watched; that is correct and must stay.
8. Live scout on 2026-09-06 (squad integration agent, read-only against the Owner's home): 1068 watchlist entries collapse to 134 inotify roots, 131 of them inside `~/.claude/plugins/marketplaces/`. That is the storm of 2026-09-05 (127 high alerts from one marketplace refresh) waiting to repeat.

## Changes
- **Vendor table.** Extend `src/sentinel/vendors.py` from W3-05 (never create a second table; if the file is absent, stop and report, because W3-05 has not merged) so each vendor entry also carries: `home` (relative to `$HOME`), `settings` (exact filenames), `hooks_dirs` (exact relative dirs), `mcp` (exact filenames), `auth` (exact filenames), `project_dirs` (relative names like `.claude`, `.codex`, `.cursor`, `.gemini`), `exclude` (relative dirs never scouted: `plugins/marketplaces`, `plugins/cache`, `projects`, `todos`, `shell-snapshots`, `statsig`, `debug`, `sessions`, `logs`). Seed it for Claude Code, Codex, Gemini CLI, Cursor, Grok Build. Unknown names default to `other` and are not watched.
- **Classification.** `classify_kind(path, vendor)` uses exact filename and exact directory matches from the vendor table. Substring matching is removed. A `hooks` kind requires the file to be inside a listed `hooks_dirs` entry. `~/.claude.json` and `~/.grok/config.toml` classify as `settings`.
- **Project discovery.** `scout(home, project_roots=None)`: for each root in `[scout] project_roots` (config, default `["~/Work"]`) walk to depth 3 looking for `project_dirs` names, skipping `.git`, `node_modules`, `.venv`, `.worktrees` bodies... but do descend into `.worktrees` one level. Also accept a list of extra cwds (the daemon passes the cwds of currently running agent processes it already reads in `sample_proc`) and scout their `project_dirs`.
- **Output.** `watchlist.json` gains `"version": 2` and each entry a `"vendor"`. Entries of kind `other` are not written at all (they were 829 of 940).
- **Hot reload.** In `_on_fs_event`, a write to `watchlist.json` triggers `_reload_watchlist()` debounced to 2 s: reload entries, diff against current roots, add or remove inotify watches, no alert. `sentinel-scout --refresh` writes atomically (tmp + `os.replace`).
- **Root resolution.** Resolve watch roots once at load into a `tuple[Path, ...]` of resolved paths; `_path_under` takes resolved roots and does not call `resolve()` on them again. Keep resolving the event path once.

## Tests
- `tests/test_scout.py`: fixture tree under a temp home mirroring the real layout (`.claude/settings.json`, `.claude/.credentials.json`, `.claude/plugins/marketplaces/x/plugins/hookify/LICENSE`, `.claude/plugins/marketplaces/x/plugins/y/hooks/hooks.json`, `.claude.json`, `.grok/config.toml`, `.gemini/settings.json`, `Work/proj/.claude/settings.local.json`, `Work/proj/.git/`). Assert: marketplace files are absent from the watchlist, `.claude.json` is `settings`, project settings found, `other` entries absent, `version == 2`.
- `tests/test_daemon_coalesce.py::test_watchlist_rewrite_reloads_without_alert`: write a new watchlist in the state dir; after debounce the daemon's roots change and no alert is emitted.
- `tests/test_rules.py::test_path_under_uses_preresolved_roots`.
- Performance test with a marker `slow`: 300 roots, 1000 events, under 500 ms total.

## Acceptance
```
.venv/bin/pytest -q
XDG_STATE_HOME=/tmp/s3 XDG_CONFIG_HOME=/tmp/s3 .venv/bin/sentinel-scout --refresh
.venv/bin/python - <<'PY'
import json,sys; sys.path.insert(0,"src")
from sentinel.daemon import watch_roots_from_entries
d=json.load(open("/tmp/s3/sentinel/watchlist.json")); print("version",d.get("version"),"entries",len(d["paths"]),"roots",len(watch_roots_from_entries(d["paths"])))
print("marketplace roots:", sum(1 for r in watch_roots_from_entries(d["paths"]) if "marketplaces" in str(r)))
PY
# expected on the Chief's machine: roots < 20, marketplace roots 0
```

## Fact-check
- Claims 1 through 7; rerun the scout into a temp XDG dir and paste the kind counts before changing code.
- Verify each vendor's real config filenames against the installed CLIs' documentation or `--help` where available (`claude`, `codex`, `gemini`, `grok` are installed via mise). Mark any filename you could not verify as UNVERIFIED in the vendor table comments.

## Non-goals
**Added by security review 2026-09-05 (S5):** auto-watch new directories only under hooks roots; track auto-added watch descriptors and drop them silently when they vanish; raise the lost-watch alert only for a configured root; rate-limit `refresh_watchlist` to once per 60 s. Regression test: create and remove `history.jsonl.lock` under a watched dir 20 times → zero alerts, one refresh at most.


- Content hashing and diffing (W6-03).
- The bypass-flag half of `vendors.py` (W3-05).

## Forbidden
- Reading the body of any scouted file. `~/.claude.json` contains an OAuth account block; you may stat it, never open it.
- Scouting `~/.ssh`, `~/.gnupg`, `~/.aws`, or anything outside the vendor table and project roots.

## Report
`docs/collab/reports/W3-03-report.md`
