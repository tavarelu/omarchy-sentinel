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
  # Prints backup path on stdout when a non-shim target is moved; else prints nothing.
  local target="$1"
  if [[ ! -e "$target" ]]; then
    return 0
  fi
  # Already our shim — replace in place without backup noise.
  if [[ -f "$target" ]] && head -n 5 "$target" 2>/dev/null | grep -q 'sentinel-wrap'; then
    return 0
  fi
  local ts bak
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  bak="${target}.sentinel-bak.${ts}"
  mv -n -- "$target" "$bak"
  echo "backed up existing $(basename "$target") → $bak" >&2
  printf '%s\n' "$bak"
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

# Canonicalize a path for comparison only (never for execution): PATH can
# carry two spellings of the same real directory (this machine's uv-style
# ~/.local/bin/env prepends the non-canonical "~/.local/share/../bin"), so a
# raw string compare of `command -v` output against $target false-positives
# "shadowed" on a shim that is genuinely first on PATH.
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

# Never leave a silent shadowed shim: verify the shell a toast click
# actually runs through (a login shell) resolves this name to the shim we
# just wrote, not to something earlier on PATH (mise installs on this
# machine, most often).
verify_on_login_path() {
  local name="$1" target="$2"
  local resolved
  resolved="$(bash -lc "command -v $(printf '%q' "$name")" 2>/dev/null || true)"
  if [[ -z "$resolved" ]]; then
    echo "install-wrappers: FATAL: '$name' is not on the login PATH at all after install (shim at $target is unreachable)" >&2
    print_path_fix "$name"
    return 1
  fi
  if [[ "$(canon "$resolved")" != "$(canon "$target")" ]]; then
    echo "install-wrappers: FATAL: '$name' is shadowed — the login shell resolves it to $resolved, not $target" >&2
    print_path_fix "$name"
    return 1
  fi
  echo "verified: '$name' resolves to $target on the login PATH"
  return 0
}

print_path_fix() {
  local name="$1"
  echo "  fix 1: put \$BIN_DIR ($BIN_DIR) before the mise entries in your shell rc" >&2
  echo "  fix 2: set SENTINEL_BIN_DIR to a directory that already precedes mise on PATH" >&2
  echo "         (~/.local/share/mise/shims is NOT acceptable — it IS the shadow)" >&2
  echo "  re-run: SENTINEL_BIN_DIR=<dir> $0 $name" >&2
}

for name in "$@"; do
  target="$BIN_DIR/$name"
  real=""
  if real="$(find_real "$name")"; then
    :
  else
    echo "install-wrappers: warning: no existing '$name' on PATH; shim will need SENTINEL_REAL_$(env_key "$name")" >&2
  fi

  # If the only real binary lived at $target, backup moves it — retarget SENTINEL_REAL.
  real_was_target=0
  if [[ -n "$real" && "$real" == "$target" ]]; then
    real_was_target=1
  fi
  bak_path="$(backup_if_needed "$target")"
  if [[ "$real_was_target" -eq 1 && -n "$bak_path" ]]; then
    real="$bak_path"
  fi

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
  verify_on_login_path "$name" "$target"
done
