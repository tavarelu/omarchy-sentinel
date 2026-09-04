#!/usr/bin/env bash
# Cheapest possible Grok job: a single-pass, read-only review of a branch against a packet.
# Usage: scripts/collab/grok-review.sh <PACKET-ID> [branch] [--dry-run]
# Runs under --sandbox read-only, no subagents, 15 turns, and writes the review to
# docs/collab/reviews/<ID>-grok-review.md. Preflights connectivity so it cannot burn quota retrying.
set -euo pipefail
ID="${1:?packet id}"; shift
BRANCH="${1:-}"; [[ -n "$BRANCH" && "$BRANCH" != --* ]] && shift || BRANCH=""
DRY=0; for a in "$@"; do [[ $a == --dry-run ]] && DRY=1; done
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKET="$(ls "$ROOT"/docs/collab/packets/"$ID"-*.md | head -1)"
[[ -n "$BRANCH" ]] || BRANCH="$(git -C "$ROOT" branch --show-current)"
OUT_DIR="$ROOT/docs/collab/reviews"; mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/$ID-grok-review.md"
PROMPT="$ROOT/docs/collab/runs/$ID-review.prompt.md"; mkdir -p "$(dirname "$PROMPT")"
cat >"$PROMPT" <<P
You are the Lead Developer acting as read-only reviewer and fact-checker. Do not edit files.
Packet: docs/collab/packets/$(basename "$PACKET"). Implementation report: docs/collab/reports/$ID-report.md.
Review the diff \`git diff feature/omarchy-sentinel...$BRANCH\` against the packet's Changes and Tests sections.
1. For each numbered Context claim in the packet, run the evidence command yourself and mark CONFIRMED / REFUTED / UNVERIFIED.
2. For each Changes and Tests item: DONE / PARTIAL / MISSING with file and line.
3. Run \`.venv/bin/pytest -q\` and report the real count.
4. Check the six security invariants in AGENTS.md against the diff: HOLDS / BROKEN with evidence.
5. Give Chief tasks: anything you think Chief must fix, decide, or verify, as a numbered list.
Reply with the review in Markdown only, under 1500 words. Verdict line first: READY or NOT READY.
P
for host in auth.x.ai cli-chat-proxy.grok.com; do
  curl -s -o /dev/null -m 6 "https://$host/" || { echo "grok-review: cannot reach $host; not spending quota" >&2; exit 3; }
done
CMD=(grok --prompt-file "$PROMPT" --cwd "$ROOT" --output-format json --permission-mode dontAsk
  --sandbox read-only --no-subagents --max-turns 15 --effort high
  --tools "read_file,grep,list_dir,run_terminal_cmd"
  --allow "Read" --allow "Grep" --allow "Bash(git diff*)" --allow "Bash(git log*)" --allow "Bash(git show*)"
  --allow "Bash(.venv/bin/pytest*)" --allow "Bash(.venv/bin/python*)" --allow "Bash(grep*)" --allow "Bash(rg*)"
  --allow "Bash(ls*)" --allow "Bash(cat*)" --allow "Bash(sed -n*)" --allow "Bash(head*)" --allow "Bash(wc*)"
  --deny "Bash(systemctl*)" --deny "Bash(sudo*)" --deny "Bash(omarchy*)" --deny "Bash(git checkout*)" --deny "Bash(git merge*)")
echo "review: $ID on $BRANCH -> $OUT"
if [[ "$DRY" -eq 1 ]]; then printf '  %q' "${CMD[@]}"; echo; exit 0; fi
"${CMD[@]}" >"$OUT.json" 2>"$OUT.stderr" || true
python3 - "$OUT.json" "$OUT" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1])); text = d.get("text", "")
    open(sys.argv[2], "w").write(text + "\n"); print("stop:", d.get("stopReason"), "session:", d.get("sessionId"))
except Exception as e:
    print("unparsable output:", e)
PY
echo "review written: $OUT"
