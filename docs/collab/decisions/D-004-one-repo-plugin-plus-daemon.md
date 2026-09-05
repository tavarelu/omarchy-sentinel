# D-004: Ship as one repository that is both the Omarchy plugin and the daemon package?
Status: OPEN (Owner)
Drafted by: Chief, 2026-09-04, after reading plugins.omarchy.org/develop.html, publish.html, and the shell's plugin contract on this machine.

## What the marketplace requires
- A public GitHub repository with `manifest.json` at the root, `schemaVersion: 1`, an id that is not `omarchy.*`, `kinds`, and an entry point file per kind. README and license files. Optional preview image.
- `omarchy plugin add <git-url> --enable` clones the repo into `~/.config/omarchy/plugins/<id>/`, runs `omarchy plugin validate`, and enables it. No install hooks run. Symlinks anywhere in the repo are refused.
- Plugins are QML loaded into the long-running `omarchy-shell` process, unsandboxed, with the user's permissions. The marketplace validates the listing, not security.
- Submission is an issue form on `omacom/omarchy-plugin-marketplace`; automated checks run on the current commit, then a maintainer approves. Updates ship by pushing to the repo; users run `omarchy plugin update`.

## Options
1. **One repo.** `manifest.json`, `BarWidget.qml`, `Panel.qml` at the root; the Python package stays in `src/`, units in `track-b/`, scripts in `scripts/`. The panel shows "daemon not installed" and offers one button that runs `scripts/install-daemon.sh`, which creates a venv under `~/.local/share/<id>/venv`, installs the package from the plugin checkout, writes units with absolute paths, and symlinks the CLIs into `~/.local/bin`. One install command for users; one place to update.
2. **Two repos.** A plugin repo with QML only, and a separate package (AUR or PyPI) that the plugin README tells users to install first. Cleaner separation, two things to keep in sync, two install steps for users.
3. **Plugin only for now**, daemon later. Not viable: the widget has nothing to show without the daemon.

## Chief recommendation
Option 1. The marketplace does not care what else is in the repo, the plugin directory is a git checkout the panel can point a venv at, and a single `omarchy plugin add` line is what every listed plugin advertises. Keep the AUR package as a wave-5 extra for people who do not use the bar.

## Consequences if accepted
- Repo root gains `manifest.json`, `BarWidget.qml`, `Panel.qml`, `README.md` rewritten for end users, `LICENSE`.
- `.venv/` must never be committed and the installer must not create anything inside the plugin dir that the validator would refuse (no symlinks).
- The plugin id becomes the public name (D-002): `<githubuser>.<name>`.

## Decision
<Owner fills in>
