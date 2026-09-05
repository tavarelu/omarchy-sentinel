# Security review: feature/omarchy-sentinel at fb12040 vs main

Reviewer: Chief (Claude). Method: manual review of every security-relevant surface in the 86-file branch diff: process signalling, file I/O and permissions, command execution and argv construction, shell installers, the Omarchy plugin, the cloud path, and state integrity against the project's own threat model. The built-in `/security-review` could not run because the repository has no `origin` remote yet; rerun it after the first push.

**Threat model being reviewed against** (spec section 2): runaway, over-privileged, or planted coding agents running *as the user*. That single fact drives the top findings: anything the user can do, the monitored agent can do.

## Findings, ranked

| ID | Severity | Finding | Where | Fix in |
|----|----------|---------|-------|--------|
| S1 | HIGH | **Tampering with Sentinel's own state is invisible.** An agent running as the user can write `allowlist.json` to approve itself (the fingerprint is a deterministic sha256 of public fields), rewrite `alerts.jsonl` to erase evidence, or write `pause_until` far in the future to mute every toast. The daemon deliberately ignores writes to all of these names, so R-SELF, which the spec assigns to "attacks on the monitor itself", cannot fire on them. | `src/sentinel/daemon.py:42-50`, `src/sentinel/action.py:91-99` | new W3-07 |
| S2 | HIGH | **Writer identity is name-based and spoofable.** Any writer whose basename starts with `sentinel` is trusted for self paths. Not exploitable today only because inotify never supplies a writer, but this check must not survive writer attribution (W6-04). | `src/sentinel/rules.py:175` | W6-04 |
| S3 | MEDIUM | **State and config are world-readable.** Directories 755, files 644 under umask 022. `alerts.jsonl` and `launches.jsonl` hold full agent command lines and project paths. | `src/sentinel/store.py:19`, `src/sentinel/paths.py` | W3-02 |
| S4 | MEDIUM | **Secrets can land in logs.** The wrapper records the full argv of every agent launch, and alerts store `cmdline`. Some agent CLIs accept keys and tokens as flags. | `src/sentinel/wrap_record.py:37`, `src/sentinel/rules.py:142` | W3-05 |
| S5 | MEDIUM | **The daemon can be made to thrash.** Every new directory under a watched directory gets a watch, and every lost watch triggers a full inventory and a medium alert. Claude Code's per-prompt lock directory already does this; an adversarial agent can loop `mkdir`/`rmdir` to keep the daemon rescanning and rewriting a 200 KB file. | `src/sentinel/daemon.py:646-655`, `handle_watch_lost` | W3-03 |
| S6 | MEDIUM | **Kill can hit a recycled PID.** Only the uid is checked; sticky alerts live for hours. | `src/sentinel/kill.py:131` | W3-02 |
| S7 | LOW | **Notify can block the daemon.** No timeout on the D-Bus call; a wedged notification server stalls inotify draining and the sampler. | `src/sentinel/notify.py:17` | W3-02 |
| S8 | LOW | **Non-atomic rewrite and no rotation of the alert log.** A daemon append during a CLI rewrite can lose rows. | `src/sentinel/store.py:52` | W3-02 |
| S9 | LOW | **Installers build units with `sed` using `\|` as the delimiter on user paths.** A path containing `\|` corrupts the unit silently. | `scripts/install-daemon.sh`, `scripts/install-track-a.sh:45` | W5-02 |
| S10 | LOW | **Cloud endpoint comes from the environment.** `SENTINEL_SUMMARIZE_URL` can redirect the redacted bundle; impact is metadata only, but the endpoint belongs in config with a provider allowlist, and the bundle should be shown before it is sent. | `src/sentinel/summarize.py:93-97` | W5-06 |
| S11 | INFO | **The plugin runs unsandboxed in omarchy-shell by platform design** and resolves `sentinel-action` from PATH. Prefer the installed venv's absolute path and check it is a regular user-owned file; document the class. | `BarWidget.qml` `cliArgv` | W5-03 |
| S12 | INFO | **A skill scanner parses hostile input.** When SkillSpector is integrated it must run in its own sandboxed unit with memory and time limits. | plan | W6-01a |

## S1 in detail, because it is the one that matters

A same-user attacker can ultimately do anything the user can. The achievable goal is **tamper evidence**, not prevention, and it is cheap:

1. **Mirror every alert to the journal.** `journald` is append-only for an unprivileged user. One line per alert via the journal socket gives an evidence copy the agent cannot erase. Also emit R-SELF when `alerts.jsonl` shrinks, the same way `consume_launches` already notices truncation.
2. **Detect writes the daemon did not make.** The daemon records size and mtime after each of its own writes; `sentinel-action` announces its writes to the daemon over a unix socket in the state dir (or a nonce file the daemon consumes). Any other change to `allowlist.json`, `allowlist-session.json`, `pause_until`, or `watchlist.json` is R-SELF high. This turns the blind spot into a tripwire.
3. **Cap pauses at read time** to 24 hours and alert on a longer one. Config gets `pause_max = "24h"`.
4. **Keep the self-approval window narrow.** Session-scope entries are already cleared at daemon start; approvals written while the daemon has an unexplained-write tripwire pending are ignored until the user confirms.

Containment, an optional bubblewrap launch profile per agent, is the real answer and stays in wave 6.

## What is being done right

- Runs as the user, never root; kill is confirm-gated, narrow, uid-checked, TERM then KILL, and refuses non-owned PIDs.
- Metadata only: no transcript, credential, MCP env, or settings bodies anywhere, and tests assert the cloud bundle's key set.
- The daemon imports no cloud SDK and makes no network call; Summarize is a separate oneshot behind a click, with the API key file required to be mode 0600.
- Argv arrays everywhere: the plugin, notify, and installers never build shell strings from alert data; Omarchy's notification path passes text as typed D-Bus arguments, so alert text can never become an option.
- Installers dry-run by default, back up what they replace, and never enable the daemon service; the wrapper never blocks an agent launch on a recorder failure.
- The test suite cannot touch live state (`tests/conftest.py`), and the plugin validates clean with no symlinks.
- Process: spec first, numbered claims with evidence, a second system fact-checking the first, sandboxed and budgeted Grok runs, and a live smoke before anything ships.

## Actions

- New packet W3-07 (self-defense) for S1; add S3, S6, S7, S8 to W3-02; S4 to W3-05; S5 to W3-03; S9 to W5-02; S10 to W5-06; S11 to W5-03; S12 is designed into W6-01a.
- Threat model document (W5-05) must state the same-user limit plainly.
