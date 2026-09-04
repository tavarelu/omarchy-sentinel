#!/usr/bin/env bash
# Merge Sentinel menu ids into ~/.config/omarchy/extensions/omarchy-menu.jsonc.
# Default: dry-run (print unified diff). Pass --apply to write after backup.
# Usage: scripts/install-menu.sh [--dry-run|--apply] [--target PATH]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SNIPPET="${SENTINEL_MENU_SNIPPET:-$REPO_ROOT/packaging/omarchy-menu-sentinel.jsonc}"
TARGET="${SENTINEL_MENU_TARGET:-$HOME/.config/omarchy/extensions/omarchy-menu.jsonc}"
MODE=dry-run

BEGIN_MARK='// BEGIN sentinel-menu (managed by scripts/install-menu.sh)'
END_MARK='// END sentinel-menu'

usage() {
  cat <<EOF
usage: $0 [--dry-run|--apply] [--target PATH]

Merge packaging/omarchy-menu-sentinel.jsonc into the Omarchy menu extension.
Default mode is --dry-run (no writes). --apply backs up the target first.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE=dry-run; shift ;;
    --apply) MODE=apply; shift ;;
    --target)
      [[ $# -ge 2 ]] || { echo "install-menu: --target needs a path" >&2; exit 2; }
      TARGET="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "install-menu: unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$SNIPPET" ]]; then
  echo "install-menu: missing snippet $SNIPPET" >&2
  exit 1
fi

# Build proposed target text (stdout). Preserves non-sentinel content via markers.
propose() {
  python3 - "$SNIPPET" "$TARGET" "$BEGIN_MARK" "$END_MARK" <<'PY'
import json, re, sys
from pathlib import Path

snippet_path, target_path, begin_mark, end_mark = sys.argv[1:5]

def strip_jsonc(text: str) -> str:
    # Drop // line comments and /* */ blocks outside strings (good enough for menu files).
    out = []
    i, n = 0, len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] not in "\n\r":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i = min(i + 2, n)
                continue
        out.append(c)
        i += 1
    return "".join(out)

def load_jsonc(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(strip_jsonc(raw) or "{}")
    if not isinstance(data, dict):
        raise SystemExit(f"install-menu: {path} root must be an object")
    return data

snippet = load_jsonc(Path(snippet_path))
expected = ("sentinel", "sentinel.alerts", "sentinel.status", "sentinel.inventory", "sentinel.pause")
missing = [k for k in expected if k not in snippet]
if missing:
    raise SystemExit(f"install-menu: snippet missing keys: {', '.join(missing)}")

# Stable key order from the packaging file / expected list, then any extras.
ordered_keys = [k for k in expected if k in snippet] + [k for k in snippet if k not in expected]
entries = []
for key in ordered_keys:
    entries.append(f'  {json.dumps(key, ensure_ascii=False)}: {json.dumps(snippet[key], ensure_ascii=False, separators=(", ", ": "))}')
block_body = ",\n".join(entries)
managed = f"  {begin_mark}\n{block_body}\n  {end_mark}"

target = Path(target_path)
if target.is_file():
    text = target.read_text(encoding="utf-8")
else:
    text = "{\n}\n"

# Remove a previous managed block if present.
pattern = re.compile(
    re.escape(begin_mark) + r".*?" + re.escape(end_mark),
    re.DOTALL,
)
text_wo = pattern.sub("", text)
# Drop orphaned sentinel.* / "sentinel" keys outside the managed block (re-install).
# Conservative: only strip lines that look like those object entries.
line_re = re.compile(
    r'^[ \t]*"(sentinel|sentinel\.(?:alerts|status|inventory|pause))"\s*:\s*\{.*?\}\s*,?[ \t]*\n',
    re.MULTILINE,
)
text_wo = line_re.sub("", text_wo)

# Insert managed block before the final closing brace of the root object.
close_idx = text_wo.rfind("}")
if close_idx < 0:
    raise SystemExit(f"install-menu: no closing }} in {target_path}")

before = text_wo[:close_idx].rstrip()
after = text_wo[close_idx:]

# Ensure a trailing comma on the last real entry before our block, if needed.
# Find last non-empty, non-comment line in `before` (excluding the opening `{`).
lines = before.splitlines()
last_code_i = None
for i in range(len(lines) - 1, -1, -1):
    s = lines[i].strip()
    if not s or s.startswith("//") or s.startswith("/*") or s.startswith("*"):
        continue
    if s == "{":
        break
    last_code_i = i
    break

if last_code_i is not None:
    raw_line = lines[last_code_i]
    stripped = raw_line.rstrip()
    if not stripped.endswith(",") and not stripped.endswith("{") and not stripped.endswith("["):
        lines[last_code_i] = stripped + ","
    before = "\n".join(lines)

if before.endswith("{"):
    proposed = before + "\n" + managed + "\n" + after.lstrip()
else:
    proposed = before + "\n" + managed + "\n" + after.lstrip()

if not proposed.endswith("\n"):
    proposed += "\n"
sys.stdout.write(proposed)
PY
}

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
propose >"$TMP"

if [[ ! -f "$TARGET" ]]; then
  CURRENT_EMPTY=1
  mkdir -p "$(dirname "$TARGET")"
  # For diff only: compare against empty object if missing (do not create in dry-run).
  CURRENT_FOR_DIFF="$(mktemp)"
  trap 'rm -f "$TMP" "$CURRENT_FOR_DIFF"' EXIT
  printf '{\n}\n' >"$CURRENT_FOR_DIFF"
  DIFF_LEFT="$CURRENT_FOR_DIFF"
else
  CURRENT_EMPTY=0
  DIFF_LEFT="$TARGET"
fi

echo "install-menu: mode=$MODE"
echo "install-menu: snippet=$SNIPPET"
echo "install-menu: target=$TARGET"
if [[ "$CURRENT_EMPTY" -eq 1 ]]; then
  echo "install-menu: note: target does not exist yet (diff vs empty {})"
fi
echo "----- diff -----"
if diff -u "$DIFF_LEFT" "$TMP" || true; then
  :
fi
echo "----- end diff -----"

if [[ "$MODE" == dry-run ]]; then
  echo "install-menu: dry-run only; re-run with --apply to write (backup first)."
  exit 0
fi

# --apply
mkdir -p "$(dirname "$TARGET")"
if [[ -f "$TARGET" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  bak="${TARGET}.sentinel-bak.${ts}"
  cp -a -- "$TARGET" "$bak"
  echo "install-menu: backed up → $bak"
fi
cp -- "$TMP" "$TARGET"
echo "install-menu: wrote $TARGET"
echo "install-menu: verify with: omarchy menu summon sentinel"
