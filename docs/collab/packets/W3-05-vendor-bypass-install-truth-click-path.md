# W3-05 Vendor bypass table, install truth, a real click path
Depends on: none          Parallel-safe with: W3-01, W3-02, W3-03

## Goal
Sentinel recognizes the bypass switches of every agent installed on this machine, including switches set in config files rather than argv; the wrapper installer refuses to succeed silently when its shim is shadowed; the Sentinel CLIs are reachable from the desktop shell; and clicking a toast or a menu row opens a terminal where the user can actually choose Approve, Kill, Investigate, or Dismiss.

## Context
1. `DEFAULT_BYPASS_FLAGS` (`src/sentinel/rules.py:11-19`) is `--dangerously-skip-permissions`, `bypassPermissions`, `--yolo`, `trust-all`, `--trust-all`. Grok Build's `--help` on this machine lists `--always-approve` and `--permission-mode <default|acceptEdits|auto|dontAsk|bypassPermissions|plan>`; none of `--always-approve`, `dontAsk` are detected.
2. `~/.grok/config.toml` on this machine contains `permission_mode = "always-approve"` under `[ui]`. That is a bypass that never appears in argv. Same class: Codex `approval_policy` and `sandbox_mode` in `~/.codex/config.toml`, Gemini `--approval-mode yolo` and settings.
3. PATH order in the user's shell and in the running `omarchy-shell` process: `/usr/share/omarchy/bin`, then mise install dirs for claude, codex, gemini, gh, node, grok, then mise shims, then `/usr/local/bin`, `/usr/bin`, and only then `~/.local/bin` (position 12). `command -v claude` resolves to `~/.local/share/mise/installs/claude/latest/claude`. A shim placed in `~/.local/bin` by `scripts/install-wrappers.sh` (`BIN_DIR` at line 15) is never executed.
4. The existing `~/.local/bin/claude`, `codex`, `grok` are mise launcher scripts (`exec mise x ...`), not Sentinel shims.
5. `omarchy-notification-send` stores the `--exec` argv in the `omarchy-exec-argv` hint and `omarchy-shell` executes it directly on click, with no terminal. Omarchy's own hooks (`~/.config/omarchy/hooks/post-update.d/setup-fingerprint.hook`) use `--exec omarchy-launch-floating-terminal-with-presentation <cmd>` for exactly this case. `omarchy-launch-floating-terminal-with-presentation` exists at `/usr/bin` and runs `omarchy-show-logo; <cmd>; omarchy-show-done` in a floating terminal via `uwsm-app`.
6. `omarchy-shell`'s PATH contains no Sentinel venv; `sentinel-action` is not resolvable from a toast or a menu row. `build_argv` (`src/sentinel/notify.py:52-55`) emits `--exec sentinel-action <id> menu`; `packaging/omarchy-menu-sentinel.jsonc` actions are bare `sentinel-action list` etc.
7. `cmd_menu` (`src/sentinel/action.py:214-233`) prints a cheat sheet and exits; it never asks anything.
8. `tests/test_notify.py:45-47` pins the `--exec` tail as `["--exec","sentinel-action",<id>,"menu"]`.

## Changes
- **Vendor table.** In `src/sentinel/vendors.py` (shared with W3-03; extend if it exists) add per vendor: `basenames`, `argv_bypass` (exact tokens and `--flag value` pairs, for example `("--permission-mode", {"bypassPermissions", "dontAsk"})`), `config_bypass` (file, TOML/JSON key path, values that mean bypass). `extract_bypass_flags` consumes `argv_bypass` from all vendors plus config extras; value-taking flags report as `--permission-mode=bypassPermissions`.
- **Config-file bypass.** New rule `R-BYPASS-CONFIG` (severity medium) evaluated by the scout, not the daemon: when a vendor config file exists, hash it and compare with the last hash in `watchlist.json`; on change, emit one alert stating that the file changed, never its content. Reading the key value would require reading the body, which the spec forbids; state this limitation in the alert summary and README. (Ask the Chief if you think a narrow keyed read is acceptable; do not do it unilaterally.)
- **Install truth.** `scripts/install-wrappers.sh`: after writing each shim, run `bash -lc 'command -v <name>'` and compare to the shim path. On mismatch print the resolved path, the PATH position problem, and the two fixes (put `$BIN_DIR` before mise entries in the shell rc, or set `SENTINEL_BIN_DIR` to a dir that already precedes mise, for example `~/.local/share/mise/shims` is NOT acceptable), then exit 1. Never leave a silent shadowed shim.
- **CLI on PATH.** New `scripts/install-cli.sh`: symlink `sentinel`, `sentinel-action`, `sentinel-scout` from the venv into `~/.local/bin` (which IS on `omarchy-shell`'s PATH), with backup semantics like the wrapper installer. Dry-run by default.
- **Click path.** `notify.build_argv` emits `--exec omarchy-launch-floating-terminal-with-presentation sentinel-action <id> menu`. Menu actions in `packaging/omarchy-menu-sentinel.jsonc` become `omarchy-launch-floating-terminal-with-presentation sentinel-action list` (and `status`, `pause 1h`, `sentinel-scout --refresh`). Update `tests/test_notify.py` and add a test for the jsonc.
- **Interactive menu.** `cmd_menu` when stdin is a tty: show the alert detail, then a numbered prompt: `1 approve session`, `2 approve 24h`, `3 approve this-repo`, `4 approve forever`, `5 kill child`, `6 kill session`, `7 investigate`, `8 summarize`, `9 dismiss`, `0 nothing`. Dispatch to the existing `cmd_*` functions. Non-tty keeps the cheat sheet.

## Tests
- `tests/test_vendors.py`: every vendor entry has non-empty basenames; `extract_bypass_flags(["grok","--always-approve"])` and `["grok","--permission-mode","dontAsk"]` and `["codex","--dangerously-bypass-approvals-and-sandbox"]` and `["gemini","--yolo"]` detect; `["claude","--permission-mode","plan"]` does not.
- `tests/test_notify.py`: updated tail pin.
- `tests/test_menu_jsonc.py`: every action starts with `omarchy-launch-floating-terminal-with-presentation`.
- `tests/test_action.py::test_menu_interactive_dispatch`: inject `isatty=True` and a prompt returning `9`; alert becomes dismissed.
- `tests/test_install_wrappers.sh` (bash, run via pytest subprocess): with a fake PATH where a fake `mise` dir precedes `BIN_DIR`, the installer exits 1 and prints the fix; with `BIN_DIR` first it exits 0.

## Acceptance
```
.venv/bin/pytest -q
shellcheck scripts/install-wrappers.sh scripts/install-cli.sh
SENTINEL_BIN_DIR=/tmp/sb PATH=/tmp/fakemise:/tmp/sb:$PATH bash scripts/install-wrappers.sh claude; echo "exit=$?"   # expected exit=1 with the PATH fix printed (create /tmp/fakemise/claude as an executable stub first)
```

## Fact-check
- Claims 1 through 8. For claim 1 run `grok --help`, `claude --help`, `codex --help`, `gemini --help`, and `cursor-agent --help` if present, and paste the exact bypass-related flags into the report; this is the source of truth for the vendor table. Mark any vendor you could not run as UNVERIFIED.
- For claim 3 run `bash -lc 'echo $PATH; command -v claude'`.

## Non-goals
- Menu `provider` rows and the bar widget (W5-03).
- Installing anything on the live machine. The installers are changed, not run.

## Forbidden
- Running any `scripts/install-*.sh` without `--dry-run` or a temp `SENTINEL_BIN_DIR`.
- Reading vendor config bodies.

## Report
`docs/collab/reports/W3-05-report.md`
