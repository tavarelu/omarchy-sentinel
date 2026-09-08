#!/usr/bin/env bash
# Install the Sentinel daemon from this plugin checkout (D-004: one repo is both
# the Omarchy plugin and the Python package). Dry-run unless --apply.
#
#   venv:   ~/.local/share/<plugin-id>/venv     (never inside the plugin dir: the
#                                                 Omarchy validator refuses symlinks)
#   CLIs:   ~/.local/bin/sentinel{,-action,-scout}  (on omarchy-shell's PATH)
#   units:  ~/.config/systemd/user/               (ExecStart rewritten to the venv)
#   config: ~/.config/sentinel/config.toml        (copied only if absent)
#
# Enables the nightly inventory timer. Does NOT enable sentinel.service; that is
# the Phase 2 smoke gate and stays a deliberate command the user runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ID="$(jq -r '.id // "tav.sentinel"' "$ROOT/manifest.json" 2>/dev/null || echo tav.sentinel)"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$ID"
VENV="$DATA_DIR/venv"
BIN_DIR="${SENTINEL_BIN_DIR:-$HOME/.local/bin}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sentinel"
APPLY=0
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
do_or_show() {
  if (( APPLY )); then "$@"; else say "  would run: $*"; fi
}

say "plugin:  $ROOT ($ID)"
say "venv:    $VENV"
say "cli dir: $BIN_DIR"
say "units:   $UNIT_DIR"
(( APPLY )) || say "(dry-run; pass --apply to perform these steps)"

say "1. Python venv + package (editable, so 'omarchy plugin update' updates the daemon too)"
if [[ ! -x "$VENV/bin/python" ]]; then
  do_or_show mkdir -p "$DATA_DIR"
  do_or_show python3 -m venv "$VENV"
fi
do_or_show "$VENV/bin/pip" -q install -e "$ROOT"

say "2. CLIs on PATH"
do_or_show mkdir -p "$BIN_DIR"
for cli in sentinel sentinel-action sentinel-scout sentinel-scan; do
  do_or_show ln -sfn "$VENV/bin/$cli" "$BIN_DIR/$cli"
done

say "3. systemd user units with absolute ExecStart"
do_or_show mkdir -p "$UNIT_DIR"
for src in "$ROOT"/track-b/systemd/*.service "$ROOT"/track-b/systemd/*.timer; do
  name="$(basename "$src")"
  if (( APPLY )); then
    sed "s|%h/Work/sentinel/.venv|$VENV|g" "$src" >"$UNIT_DIR/$name"
  else
    say "  would write: $UNIT_DIR/$name (ExecStart -> $VENV/bin/...)"
  fi
done
do_or_show systemctl --user daemon-reload
do_or_show systemctl --user enable --now sentinel-inventory.timer

say "4. Config template"
if [[ ! -f "$CFG_DIR/config.toml" ]]; then
  do_or_show mkdir -p "$CFG_DIR"
  do_or_show cp "$ROOT/packaging/config.toml" "$CFG_DIR/config.toml"
else
  say "  keeping existing $CFG_DIR/config.toml"
fi

say "5. First inventory (metadata only) so the daemon has a watchlist"
do_or_show "$VENV/bin/sentinel-scout" --refresh

say
say "Not done on purpose: the daemon is not enabled. After the smoke test run:"
say "  systemctl --user enable --now sentinel.service"
say "Wrappers (primary bypass detection) are opt-in: scripts/install-wrappers.sh claude codex"
