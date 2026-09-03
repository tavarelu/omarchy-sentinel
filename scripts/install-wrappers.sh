#!/usr/bin/env bash
# Install opt-in launcher shims into ~/.local/bin that record via sentinel-wrap.
# Usage: scripts/install-wrappers.sh <basename> [basename...]
# Never overwrites an existing file without renaming it to *.sentinel-bak.<ts>
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <basename> [basename...]" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WRAP_SRC="$REPO_ROOT/wrappers/sentinel-wrap"
BIN_DIR="${SENTINEL_BIN_DIR:-$HOME/.local/bin}"

if [[ ! -x "$WRAP_SRC" ]]; then
  if [[ -f "$WRAP_SRC" ]]; then
    chmod +x "$WRAP_SRC"
  else
    echo "install-wrappers: missing $WRAP_SRC" >&2
    exit 1
  fi
fi

mkdir -p "$BIN_DIR"

backup_if_needed() {
  local target="$1"
  if [[ ! -e "$target" ]]; then
    return 0
  fi
  # Already our shim — replace in place without backup noise.
  if [[ -f "$target" ]] && head -n 5 "$target" 2>/dev/null | grep -q 'sentinel-wrap'; then
    return 0
  fi
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local bak="${target}.sentinel-bak.${ts}"
  mv -n -- "$target" "$bak"
  echo "backed up existing $(basename "$target") → $bak"
}

# Resolve the current real binary before we put a shim on PATH.
find_real() {
  local name="$1"
  local self_dir="$BIN_DIR"
  local dir candidate
  local -a path_dirs
  IFS=':' read -r -a path_dirs <<< "${PATH:-}"
  for dir in "${path_dirs[@]}"; do
    [[ -z "$dir" ]] && continue
    # Prefer binaries outside the install bin dir so we don't pick an old shim.
    [[ "$(cd "$dir" 2>/dev/null && pwd)" == "$(cd "$self_dir" 2>/dev/null && pwd)" ]] && continue
    candidate="${dir%/}/$name"
    if [[ -x "$candidate" && -f "$candidate" ]]; then
      # Skip other sentinel-wrap shims.
      if head -n 5 "$candidate" 2>/dev/null | grep -q 'sentinel-wrap'; then
        continue
      fi
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  # Fall back: allow a binary already in BIN_DIR if it is not a shim (pre-backup).
  candidate="$BIN_DIR/$name"
  if [[ -x "$candidate" && -f "$candidate" ]] &&
    ! head -n 5 "$candidate" 2>/dev/null | grep -q 'sentinel-wrap'; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

env_key() {
  echo "$1" | tr '[:lower:]-' '[:upper:]_'
}

for name in "$@"; do
  target="$BIN_DIR/$name"
  real=""
  if real="$(find_real "$name")"; then
    :
  else
    echo "install-wrappers: warning: no existing '$name' on PATH; shim will need SENTINEL_REAL_$(env_key "$name")" >&2
  fi

  backup_if_needed "$target"

  {
    echo '#!/usr/bin/env bash'
    echo "# sentinel shim for $name — managed by install-wrappers.sh"
    echo 'set -euo pipefail'
    if [[ -n "$real" ]]; then
      echo "export SENTINEL_REAL_$(env_key "$name")=$(printf '%q' "$real")"
    fi
    echo "exec $(printf '%q' "$WRAP_SRC") $(printf '%q' "$name") -- \"\$@\""
  } >"$target"
  chmod +x "$target"
  echo "installed $target → sentinel-wrap $name${real:+ (real=$real)}"
done
