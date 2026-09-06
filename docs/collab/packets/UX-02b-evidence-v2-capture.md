# UX-02b Evidence v2 capture

Depends on: UX-02a (merged), W3-02 (merged)   Parallel-safe with: W3-05, W6-01a
Blocked by (soft): W3-03 and W3-04 add fields this packet records; land after them if they are in flight.

## Goal
Alerts carry enough recorded fact that `investigate` can cite a source for every line without re-reading the
world, and the "recorded before evidence v2" limit stops appearing on fresh alerts. Nothing new is read from
a monitored file's contents.

## Context (verified)
1. `investigate.render_sections` already renders `evidence` keys when present and skips them when absent, and
   prints the limit line "recorded before evidence v2; some facts were not captured" whenever
   `evidence["schema"] != 2`. Adding fields is therefore purely additive for the renderer.
2. `daemon.mask_names(mask)` turns an inotify mask into its symbolic names; the write path already knows the
   mask at the moment it raises the alert.
3. `rules` currently answers "is this path under a watched root" as a boolean; the renderer wants the root
   and its kind, so the helper must return the matching root instead of a bool.
4. `Daemon._load_watch_paths` reads `watchlist.json` and knows each root's kind (hooks, settings, mcp, auth,
   self); nothing keeps that mapping after load today.
5. `Alert.hashes` already exists as `dict[str, str]` and `investigate` renders `hashes[path]` when present.
6. W3-02 added `evidence.starttime`, `evidence.instance`, `evidence.source` and `evidence.launch_ts`.

## Changes
**Write alerts** (`daemon.handle_write` and its rule call):
- `evidence["schema"] = 2`, `evidence["fs_event"]` = mask names, `evidence["watch_root"]` and
  `evidence["watch_kind"]`, `evidence["stat"] = {size, mtime_ns, mode, uid}` from a single `os.stat`.
- `alert.hashes[path] = "sha256:<hex>"` for kinds `hooks`, `settings`, `mcp` and `self` ONLY.
  `evidence["hash_skipped"]` is set to `"auth"`, `"too-large"` or `"gone"` instead, and the file is not opened.
  **An `auth` kind file is never opened for any reason.** Files over `hash_max_bytes` are not hashed.
- New config block `[investigate]`: `hash_on_write = true`, `hash_max_bytes = 1048576`, mirrored in
  `packaging/config.toml` and covered by `tests/test_config_template.py`.

**Process alerts** (`rules.evaluate_process`, sampler and launches paths):
- `evidence["source"]` (`sampler`|`launches`), `evidence["flag_indexes"]` from a new
  `rules.bypass_flag_positions(cmdline)`, `evidence["ppid"]`, `evidence["parent_basename"]`,
  and `evidence["launch_ts"]` where the launches record supplies one.

**Child-shell alerts**: `evidence["chain"]` (child and agent basenames with their pids) and
`evidence["matched"]` (the argv text that matched).

**Self-tamper alerts** (W3-07 addendum, only if that packet has landed): `size_before` and `size_after`.

## Tests
`tests/test_evidence_v2.py`: records every field named above; **never opens an auth-kind file** (assert with a
file whose read would raise); respects the size cap; handles a file deleted before the stat; sampler path
records ppid and flag indexes; launches path records `source="launches"`; child-shell records the chain.
Plus: an existing v1 row still renders (regression against `tests/test_investigate.py`'s legacy fixture), and
a fresh alert no longer shows the "recorded before evidence v2" limit.

## Acceptance
```
.venv/bin/pytest -q
grep -n "auth" src/sentinel/daemon.py    # the auth kind is excluded before any open() of a watched path
```

## Forbidden
Reading a monitored file's contents (a hash is computed by streaming, never stored or logged); opening an
`auth` kind file; network; new dependencies; changing kill or allowlist semantics; editing tests/joint/.
