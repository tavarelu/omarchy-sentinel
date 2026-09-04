#!/usr/bin/env bash
# Install Track A Omarchy hooks + user systemd health timer.
# Uses `omarchy hook install`. Does NOT install battery-low hooks.
# Does NOT run fingerprint / Touch ID setup (password auth only).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $0 [--dry-run]

Installs:
  - post-boot hook:  track-a/hooks/post-boot.d/sentinel-health
  - post-update hook: track-a/hooks/post-update.d/sentinel-recheck
  - user units: sentinel-health.service + sentinel-health.timer

Skips: battery-low hooks, fingerprint / Touch ID setup.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -x "$REPO_ROOT/.venv/bin/python" ]]; then
  echo "install-track-a: missing $REPO_ROOT/.venv/bin/python (create venv + pip install -e .)" >&2
  exit 1
fi

if ! command -v omarchy >/dev/null 2>&1; then
  echo "install-track-a: omarchy not on PATH" >&2
  exit 1
fi

rewrite() {
  local src="$1" dest="$2"
  sed "s|@SENTINEL_REPO@|$REPO_ROOT|g" "$src" >"$dest"
  chmod 755 "$dest"
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

boot_src="$REPO_ROOT/track-a/hooks/post-boot.d/sentinel-health"
update_src="$REPO_ROOT/track-a/hooks/post-update.d/sentinel-recheck"
svc_src="$REPO_ROOT/track-a/systemd/sentinel-health.service"
timer_src="$REPO_ROOT/track-a/systemd/sentinel-health.timer"

for f in "$boot_src" "$update_src" "$svc_src" "$timer_src"; do
  if [[ ! -f "$f" ]]; then
    echo "install-track-a: missing $f" >&2
    exit 1
  fi
done

boot_out="$tmpdir/sentinel-health"
update_out="$tmpdir/sentinel-recheck"
svc_out="$tmpdir/sentinel-health.service"
timer_out="$tmpdir/sentinel-health.timer"

rewrite "$boot_src" "$boot_out"
rewrite "$update_src" "$update_out"
sed "s|@SENTINEL_REPO@|$REPO_ROOT|g" "$svc_src" >"$svc_out"
sed "s|@SENTINEL_REPO@|$REPO_ROOT|g" "$timer_src" >"$timer_out"
chmod 644 "$svc_out" "$timer_out"

echo "REPO_ROOT=$REPO_ROOT"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: would run: omarchy hook install post-boot $boot_out"
  echo "dry-run: would run: omarchy hook install post-update $update_out"
  echo "dry-run: would install units to $UNIT_DIR"
  echo "dry-run: would enable --now sentinel-health.timer"
  echo "dry-run: skipping battery-low and fingerprint setup"
  exit 0
fi

omarchy hook install post-boot "$boot_out"
omarchy hook install post-update "$update_out"

mkdir -p "$UNIT_DIR"
cp "$svc_out" "$UNIT_DIR/sentinel-health.service"
cp "$timer_out" "$UNIT_DIR/sentinel-health.timer"

systemctl --user daemon-reload
systemctl --user enable --now sentinel-health.timer

echo "installed Track A hooks + sentinel-health.timer"
echo "skipped: battery-low hook, fingerprint / Touch ID"
