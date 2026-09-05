# Sentinel for Omarchy

A watchdog for the AI coding agents on your machine. Sentinel stays silent while Claude Code, Codex, Gemini, Grok Build or Cursor do ordinary work, and asks you only when the shape of a session changes: an agent started with permission-skipping flags, something rewrote an agent's hooks or settings, an agent spawned an interactive shell or piped curl into bash, or something touched Sentinel itself. You answer from the bar or a notification: Approve with a scope, Kill the child, Investigate, or Dismiss.

It runs as you, never as root. It reads metadata only: paths, hashes, process names and command lines. It never opens transcripts, credentials or settings bodies, and it never calls a cloud model unless you click Summarize.

> Status: pre-release. The plugin and daemon are under active review; see `docs/collab/LEDGER.md` for what is verified. Do not install on a machine you cannot afford to be interrupted on until v0.1 is tagged.

## Install

```sh
omarchy plugin add https://github.com/<owner>/<repo>.git --enable
```

That adds the bar widget. Open it and click **Install daemon**, or run the same thing by hand:

```sh
~/.config/omarchy/plugins/tav.sentinel/scripts/install-daemon.sh          # dry-run, shows every step
~/.config/omarchy/plugins/tav.sentinel/scripts/install-daemon.sh --apply
```

The installer creates a Python venv under `~/.local/share/tav.sentinel/`, puts `sentinel`, `sentinel-action` and `sentinel-scout` in `~/.local/bin`, installs the systemd user units, runs one metadata inventory, and enables the nightly inventory timer. It deliberately does not start the daemon. When you are ready:

```sh
systemctl --user enable --now sentinel.service
```

Optional, and the most precise detection of bypass flags: wrap the agent launchers.

```sh
~/.config/omarchy/plugins/tav.sentinel/scripts/install-wrappers.sh claude codex
```

The wrapper installer backs up anything it replaces and refuses to finish if its shim would be shadowed by something earlier on your PATH.

## Usage

- The bar shows a shield and the number of open alerts. It turns urgent when a high-severity alert is open, and dims while notifications are paused.
- Left click opens the panel. Middle click pauses notifications for an hour. Right click lists alerts in a terminal.
- In the panel: **Approve** allows this pattern in the current repository, or writes to this file for write alerts; **Anywhere** allows it everywhere and never expires; **Kill** opens a terminal that confirms before signalling the child process; **Investigate** opens the evidence view; **Dismiss** closes the alert without allowlisting. The folder icon on a card opens the alerted path in the file manager; the folder icon in the header opens the log directory.
- **High / Medium / Low** chips filter the list and decide which severities toast. The setting is shared with the daemon through `sentinel-action notify` and persists. Tamper alerts always show.
- Keys: `j` `k` move, `a` `A` approve, `x` kill, `i` investigate, `d` dismiss, `o` open folder, `1` `2` `3` toggle severities, `p` pause, `r` refresh.
- Notifications carry the same actions: click one to open the alert in a floating terminal.
- Command line: `sentinel-action list`, `sentinel-action <id> approve --scope session|24h|this-repo|forever`, `sentinel-action <id> kill [--session]`, `sentinel-action <id> investigate`, `sentinel-action <id> dismiss`, `sentinel-action pause 1h`, `sentinel-scout --refresh`.

## Configure

- Plugin settings live in the bar's widget settings: the path to `sentinel-action` if it is not on PATH. Which severities show and toast is set from the panel chips or `sentinel-action notify --severity low=on`.
- Daemon settings live in `~/.config/sentinel/config.toml`: sampler interval, extra bypass flags, known agent names, and `precious_worktrees`, the directories where killing a whole agent session requires a second confirmation.
- Move the widget: `omarchy bar move tav.sentinel --section right`.

## Remove

```sh
systemctl --user disable --now sentinel.service sentinel-inventory.timer
omarchy plugin remove tav.sentinel
rm -rf ~/.local/share/tav.sentinel ~/.local/bin/sentinel ~/.local/bin/sentinel-action ~/.local/bin/sentinel-scout
rm -f ~/.config/systemd/user/sentinel*.service ~/.config/systemd/user/sentinel*.timer && systemctl --user daemon-reload
```

State stays in `~/.local/state/sentinel/` and config in `~/.config/sentinel/` until you delete them; both contain only metadata.

## Track A: T2 MacBook health

The same repo carries Omarchy hooks and a timer that check the fan daemon, wifi and disk after boot and after updates, and warn only after three consecutive failures. Install with `scripts/install-track-a.sh --dry-run` first. This half is specific to Apple T2 machines running Omarchy and is optional.

## Development

```sh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
omarchy plugin validate .         # run on a clean checkout; the validator refuses symlinks such as .venv
```

How this project is built, by a design agent and a developer agent under one human owner, is described in `docs/collab/PROTOCOL.md`. The plan to v1.0 is `docs/collab/ROADMAP.md`; publishing steps are in `docs/collab/PUBLISHING.md`.

## Security

Sentinel is a visibility and decision tool, not a sandbox. It cannot stop a process that has already escalated to root, and a skill or plugin that passed a scanner can still misbehave until Sentinel sees it act. Pair it with a pre-install scanner such as NVIDIA SkillSpector and, when you need containment, a sandbox. Report vulnerabilities privately; a SECURITY.md with the disclosure address ships with v0.1.
