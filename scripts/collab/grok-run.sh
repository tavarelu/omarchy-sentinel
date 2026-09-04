#!/usr/bin/env bash
# Run one task packet with Grok Build headless in an isolated branch + worktree.
# Usage: scripts/collab/grok-run.sh <PACKET-ID> [--dry-run] [--max-turns N] [--lean]
# Grok usage is metered: the run preflights connectivity so it cannot burn quota retrying,
# defaults to 40 turns, and --lean disables subagents for small packets.
# Creates branch grok/<ID> from the current branch, a worktree at .worktrees/grok-<ID>,
# a fresh venv there, then runs Grok under --sandbox workspace with an explicit allow/deny list.
# Never touches the live machine: systemctl, omarchy, sudo, and ~/.config edits are denied.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <PACKET-ID> [--dry-run] [--max-turns N]" >&2
  exit 2
fi
ID="$1"; shift
DRY=0; MAX_TURNS=40; LEAN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --max-turns) MAX_TURNS="$2"; shift 2 ;;
    --lean) LEAN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKET="$(ls "$ROOT"/docs/collab/packets/"$ID"-*.md 2>/dev/null | head -1 || true)"
if [[ -z "$PACKET" ]]; then
  echo "grok-run: no packet matching docs/collab/packets/$ID-*.md" >&2
  exit 1
fi
BASE_BRANCH="$(git -C "$ROOT" branch --show-current)"
BRANCH="grok/$ID"
WT_DIR="$ROOT/.worktrees/grok-$ID"
RUN_DIR="$ROOT/docs/collab/runs"
mkdir -p "$RUN_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_JSON="$RUN_DIR/$ID-$STAMP.json"
PROMPT_FILE="$RUN_DIR/$ID-$STAMP.prompt.md"

cat >"$PROMPT_FILE" <<PROMPT
You are the Lead Developer. Read AGENTS.md and docs/collab/PROTOCOL.md, then execute packet $ID at docs/collab/packets/$(basename "$PACKET").
Work only in this worktree on branch $BRANCH. Fact-check every numbered Context claim first. Use the implementer, reviewer, and auditor roles.
Finish by writing docs/collab/reports/$ID-report.md (format: docs/collab/reports/TEMPLATE.md) and any asks under docs/collab/asks/ (format: docs/collab/asks/TEMPLATE.md), and commit them with the trailer "Packet: $ID".
Run the full suite with .venv/bin/pytest -q and put the real count in the report.
PROMPT

CMD=(grok --prompt-file "$PROMPT_FILE" --cwd "$WT_DIR"
  --output-format json --permission-mode dontAsk --sandbox workspace
  --max-turns "$MAX_TURNS" --effort high -s "sentinel-$ID"
  --allow "Read" --allow "Grep" --allow "Edit" --allow "Write"
  --allow "Bash(git*)" --allow "Bash(.venv/bin/*)" --allow "Bash(python*)"
  --allow "Bash(pytest*)" --allow "Bash(ls*)" --allow "Bash(cat*)" --allow "Bash(grep*)"
  --allow "Bash(rg*)" --allow "Bash(find*)" --allow "Bash(sed*)" --allow "Bash(head*)"
  --allow "Bash(tail*)" --allow "Bash(wc*)" --allow "Bash(diff*)" --allow "Bash(shellcheck*)"
  --allow "Bash(bash scripts/*)" --allow "Bash(claude --help*)" --allow "Bash(codex --help*)"
  --allow "Bash(gemini --help*)" --allow "Bash(grok --help*)" --allow "Bash(cursor-agent --help*)"
  --deny "Bash(systemctl*)" --deny "Bash(sudo*)" --deny "Bash(omarchy*)" --deny "Bash(rm -rf*)"
  --deny "Bash(git push*)" --deny "Bash(git merge*)" --deny "Bash(git rebase*)" --deny "Bash(git checkout feature*)"
  --deny "Edit($HOME/.config/**)" --deny "Write($HOME/.config/**)"
  --deny "Edit($HOME/.local/**)" --deny "Write($HOME/.local/**)")

echo "packet:   $PACKET"
echo "branch:   $BRANCH (from $BASE_BRANCH)"
echo "worktree: $WT_DIR"
echo "output:   $OUT_JSON"
if [[ "$LEAN" -eq 1 ]]; then CMD+=(--no-subagents); fi
if [[ "$DRY" -eq 1 ]]; then
  echo "dry-run: would run:"; printf '  %q' "${CMD[@]}"; echo
  exit 0
fi

# Preflight: do not spend Grok quota if its endpoints are unreachable (DNS or network).
for host in auth.x.ai cli-chat-proxy.grok.com; do
  if ! curl -s -o /dev/null -m 6 "https://$host/"; then
    echo "grok-run: cannot reach https://$host/ within 6s; fix connectivity or DNS before running Grok" >&2
    exit 3
  fi
done
echo "preflight: xAI endpoints reachable"

if ! git -C "$ROOT" show-ref --verify --quiet "refs/heads/$BRANCH"; then
  git -C "$ROOT" branch "$BRANCH" "$BASE_BRANCH"
fi
if [[ ! -d "$WT_DIR" ]]; then
  git -C "$ROOT" worktree add "$WT_DIR" "$BRANCH"
fi
if [[ ! -x "$WT_DIR/.venv/bin/pytest" ]]; then
  python3 -m venv "$WT_DIR/.venv"
  "$WT_DIR/.venv/bin/pip" -q install -e "$WT_DIR[dev]"
fi

"${CMD[@]}" >"$OUT_JSON" 2>"$RUN_DIR/$ID-$STAMP.stderr" || true
echo "stop reason: $(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d.get('stopReason'),'session',d.get('sessionId'))" "$OUT_JSON" 2>/dev/null || echo 'unparsable output')"
echo "report:   $WT_DIR/docs/collab/reports/$ID-report.md"
git -C "$WT_DIR" log --oneline "$BASE_BRANCH..$BRANCH" | head -20
