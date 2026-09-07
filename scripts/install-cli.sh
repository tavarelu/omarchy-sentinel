#!/usr/bin/env bash
# Symlink sentinel, sentinel-action, sentinel-scout from this checkout's venv
# into ~/.local/bin, which IS on omarchy-shell's PATH (unlike a raw shim in
# the same dir — see install-wrappers.sh's PATH-order check for why that
# distinction matters).
#
# Dry-run by default; pass --apply to write anything. Idempotent when a
# target already symlinks to the venv's own binary. Formalizes the hand
# step already done once on the Owner's machine (2026-09-05); does not
# install, enable or run anything else.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ID="$(jq -r '.id // "tav.sentinel"' "$ROOT/manifest.json" 2>/dev/null || echo tav.sentinel)"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$ID"
VENV="${SENTINEL_VENV:-$DATA_DIR/venv}"
BIN_DIR="${SENTINEL_BIN_DIR:-$HOME/.local/bin}"
CLIS=(sentinel sentinel-action sentinel-scout)

APPLY=0
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    -h|--help)
      echo "usage: $0 [--apply]"
      echo "  symlinks ${CLIS[*]} from \$VENV/bin into \$BIN_DIR"
      echo "  VENV:    $VENV   (override with SENTINEL_VENV)"
      echo "  BIN_DIR: $BIN_DIR   (override with SENTINEL_BIN_DIR)"
      echo "  dry-run unless --apply is passed"
      exit 0
      ;;
    *)
      echo "unknown arg: $a" >&2
      exit 2
      ;;
  esac
done

say() { printf '%s\n' "$*"; }
do_or_show() {
  if (( APPLY )); then
    "$@"
  else
    say "  would run: $*"
  fi
}

# Canonicalize for comparison only (never for execution) — see
# install-wrappers.sh's canon() for why a raw string compare is unsafe here.
canon() {
  local p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath -m -- "$p" 2>/dev/null && return 0
  fi
  local dir base
  dir="$(dirname -- "$p")"
  base="$(basename -- "$p")"
  if dir="$(cd "$dir" 2>/dev/null && pwd -P)"; then
    printf '%s/%s\n' "$dir" "$base"
  else
    printf '%s\n' "$p"
  fi
}

backup_if_needed() {
  local target="$1"
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    return 0
  fi
  local ts bak
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  bak="${target}.sentinel-bak.${ts}"
  do_or_show mv -n -- "$target" "$bak"
  if (( APPLY )); then
    say "  backed up existing $(basename "$target") -> $bak"
  else
    say "  would back up existing $(basename "$target") -> $bak"
  fi
}

say "venv:    $VENV"
say "bin dir: $BIN_DIR"
(( APPLY )) || say "(dry-run; pass --apply to perform these steps)"

if [[ ! -d "$VENV/bin" ]]; then
  echo "install-cli: missing $VENV/bin (build the venv first, e.g. scripts/install-daemon.sh)" >&2
  exit 1
fi

do_or_show mkdir -p "$BIN_DIR"

for cli in "${CLIS[@]}"; do
  target="$BIN_DIR/$cli"
  desired="$VENV/bin/$cli"

  if [[ -L "$target" ]]; then
    current="$(readlink -f -- "$target" 2>/dev/null || true)"
    if [[ -n "$current" && "$(canon "$current")" == "$(canon "$desired")" ]]; then
      say "already linked: $target -> $desired"
      continue
    fi
    # A symlink already pointing into SOME plugin venv's bin/ is left alone
    # unless the caller opts in: relinking it here would silently move a
    # working live CLI onto whatever venv this checkout happens to be.
    if [[ -n "$current" && "$current" == */venv/bin/"$cli" && "${SENTINEL_CLI_FORCE:-0}" != "1" ]]; then
      echo "install-cli: refusing to relink $target (currently -> $current); set SENTINEL_CLI_FORCE=1 to override" >&2
      continue
    fi
  fi

  backup_if_needed "$target"
  do_or_show ln -sfn "$desired" "$target"
  if (( APPLY )); then
    say "linked: $target -> $desired"
  else
    say "would link: $target -> $desired"
  fi
done
