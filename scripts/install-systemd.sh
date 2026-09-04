#!/usr/bin/env bash
# Install Track B systemd --user units for Sentinel.
# Copies units to ~/.config/systemd/user/, reloads, enables the inventory timer.
# Copies sentinel-unstable.service (OnFailure helper) but does not enable it.
# Does NOT enable sentinel.service — do that only after Phase 2 acceptance smoke:
#   systemctl --user enable --now sentinel.service
#
# Unit ExecStart paths use %h/Work/sentinel/.venv/bin/...
# If the repo is elsewhere, override after install:
#   systemctl --user edit sentinel.service
#   systemctl --user edit sentinel-inventory.service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UNIT_SRC="$REPO_ROOT/track-b/systemd"
UNIT_DST="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

UNITS=(
  sentinel.service
  sentinel-unstable.service
  sentinel-inventory.service
  sentinel-inventory.timer
)

for u in "${UNITS[@]}"; do
  if [[ ! -f "$UNIT_SRC/$u" ]]; then
    echo "install-systemd: missing $UNIT_SRC/$u" >&2
    exit 1
  fi
done

mkdir -p "$UNIT_DST"
for u in "${UNITS[@]}"; do
  cp -f -- "$UNIT_SRC/$u" "$UNIT_DST/$u"
  echo "installed $UNIT_DST/$u"
done

systemctl --user daemon-reload
systemctl --user enable --now sentinel-inventory.timer

echo
echo "Enabled: sentinel-inventory.timer (OnCalendar=03:30, Persistent=true)"
echo "Deferred: sentinel.service — enable only after Phase 2 acceptance smoke:"
echo "  systemctl --user enable --now sentinel.service"
echo "If the repo is not at ~/Work/sentinel, override ExecStart with:"
echo "  systemctl --user edit sentinel.service"
echo "  systemctl --user edit sentinel-inventory.service"
