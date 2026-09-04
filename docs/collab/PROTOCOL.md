# Sentinel two-agent protocol: Claude (Chief of Design) + Grok Build (Lead Developer)

**Purpose.** Turn Omarchy Sentinel into a respectable, production-ready, open-source package whose sole job is protecting people and their hardware from runaway or malicious AI coding agents. Two AI systems build it together under one human owner, and each system checks the other.

**Status of this document.** Source of truth for how work moves. If a task packet and this file disagree, this file wins and the packet is wrong.

---

## 1. Roles

| Role | Who | Owns | Never does |
|------|-----|------|------------|
| Owner | the user | direction, live-machine actions, publishing, name, license, anything irreversible | nothing is off limits |
| Chief of Design | Claude Code | architecture, specs, task packets, acceptance criteria, review of every diff, merge into `feature/omarchy-sentinel`, answers to asks | implement packets it authored, merge its own unreviewed code, enable services |
| Lead Developer | Grok Build | implementation in an isolated branch, tests, reports, fact-checks of Chief claims, asks to Chief | merge, edit anything outside its worktree, touch `~/.config`, `systemctl`, `omarchy`, secrets |

Grok may run as many subagents as it likes inside its worktree. Three roles are predefined in `.grok/roles/`: `implementer`, `reviewer`, `auditor`. The reviewer and auditor never edit files.

## 2. The channel

Everything both systems read or write lives in the repo. No chat state counts.

```
AGENTS.md                      Grok's standing rules (Grok appends this to its system prompt)
CLAUDE.md                      Claude's standing rules
docs/collab/PROTOCOL.md        this file
docs/collab/ROADMAP.md         waves to v1.0 and the definition of production-ready
docs/collab/LEDGER.md          single status table: HEAD, reviewed range, packet states
docs/collab/packets/<ID>-*.md  Chief -> Grok task packets
docs/collab/reports/<ID>-report.md   Grok -> Chief report for one packet
docs/collab/asks/ASK-<n>.md    Grok -> Chief: a fact-check verdict, a question, or a task for Chief
docs/collab/decisions/D-<n>.md Owner decisions (ADR-lite); Chief drafts, Owner decides
docs/collab/runs/              headless run logs (gitignored except summaries)
```

Packet IDs are `W<wave>-<nn>`, for example `W3-01`. A revision of a packet after a RETURN is `W3-01r2`.

## 3. The loop (one packet)

1. **Chief writes a packet** (format in section 4). Every factual claim in the packet's *Context* section is numbered so Grok can fact-check it.
2. **Driver launches Grok** with `scripts/collab/grok-run.sh <ID>`. The driver creates branch `grok/<ID>` from the current feature branch, a worktree at `.worktrees/grok-<ID>`, a fresh venv, and runs Grok headless under `--sandbox workspace` with an explicit allow and deny list. Grok commits on its branch only.
3. **Grok delivers**: commits, `docs/collab/reports/<ID>-report.md`, and zero or more `docs/collab/asks/ASK-<n>.md`, all on its branch.
4. **Chief reviews**: reads the report, runs the full test suite in Grok's worktree, verifies every acceptance command in the packet, reads the diff, and answers every ask. Verdict is one of:
   - `ACCEPT`: merge `grok/<ID>` into `feature/omarchy-sentinel` with `--no-ff`, update LEDGER.
   - `RETURN`: write `<ID>r2` packet listing exactly what failed, relaunch with the same session id so Grok keeps context.
   - `ESCALATE`: an Owner decision is needed; draft `D-<n>`, stop, and report to Owner.
5. **Owner checkpoint** at the end of every wave: Chief posts a plain-language summary, the decisions needed, and the next wave. The Owner can stop, redirect, or approve.

## 4. Packet format (Chief -> Grok)

```
# <ID> <title>
Depends on: <IDs or none>          Parallel-safe with: <IDs>
## Goal            one paragraph, what is true when this is done
## Context         numbered facts with the command or file:line that proves each one
## Changes         exact files, functions, and behavior; no "consider"
## Tests           tests to add, by name and assertion
## Acceptance      commands that must pass, with expected output
## Fact-check      claims Grok must verify and mark CONFIRMED / REFUTED / UNVERIFIED with evidence
## Non-goals       what not to touch
## Forbidden       actions that fail the packet outright
## Report          path of the report file
```

## 5. Report format (Grok -> Chief)

```
# <ID> report
Branch: grok/<ID>   Commits: <shas>   Tests: <n passed / failed>
## Done            what changed, by file
## Fact-check      one row per numbered Context claim: CONFIRMED / REFUTED / UNVERIFIED + evidence
## Deviations      anything done differently from the packet and why
## Not done        anything left, and why
## Asks            list of ASK ids filed
## Self-review     reviewer and auditor subagent verdicts, verbatim summary
```

A report that omits the Fact-check table is incomplete and gets RETURNed.

## 6. Asks (Grok -> Chief)

An ask is how Grok gives Chief work. Three kinds:

- `fact-check`: "Claim N in W3-02 is false because <evidence>. Chief must revise the packet."
- `question`: a design ambiguity that blocks or risks the packet. Grok proceeds under a stated assumption unless the ask is marked `blocking`.
- `task`: work only Chief should do, for example "write the threat model section for the README", "decide the alert schema for R-NEW-AGENT", "benchmark X on the live machine". Grok can and should assign these.

Chief answers every ask in the review, inline in the ask file under `## Answer`, and closes it.

## 7. Mutual fact-checking rules

- Neither system trusts prose. A claim without a command, a file and line, or a test is `UNVERIFIED`.
- Grok verifies Chief's Context claims before implementing. A REFUTED claim that changes the design stops the packet with a blocking ask.
- Chief verifies Grok's report by rerunning, never by reading. Test counts are checked by running pytest. "Works" is checked by the acceptance commands.
- Both record evidence as commands whose output another party can reproduce.

## 8. Gates

| Gate | Passes when | Who runs it |
|------|-------------|-------------|
| G0 tests | full pytest green in Grok's worktree and after merge | Chief |
| G1 audit | security invariants hold (section 9) on the merged tree | Chief, plus Grok's auditor role |
| G2 smoke | acceptance smoke passes on the live machine with dry-run first | Owner, guided by Chief |
| G3 release | ROADMAP release checklist complete | Owner |

## 9. Security invariants (fail any and the packet is RETURNed)

1. Sentinel runs as the user, never root. Kill only user-owned PIDs, and only after verifying the process start time still matches the alert.
2. No file bodies of transcripts, credentials, MCP env, or settings are read into alerts, logs, reports, or any cloud payload. Hashes and paths only.
3. The daemon process imports no cloud SDK and makes no network call. Summarize is a separate oneshot behind an explicit click.
4. No silent auto-kill. Every kill goes through a confirm.
5. No secrets in the repo. `~/.config/sentinel` is never committed.
6. Nothing in a packet run enables, starts, or edits a systemd unit, an Omarchy hook, a menu file, or a wrapper on the live machine. Install is Owner-run.

## 10. Branching and merging

- `main`: release history only. `feature/omarchy-sentinel`: integration branch. `grok/<ID>`: one per packet.
- Grok commits with conventional messages and a trailer `Packet: <ID>`.
- Chief merges with `git merge --no-ff grok/<ID>` and records the range in LEDGER. Chief never rebases Grok's branch.
- The `.superpowers/sdd` audit trail and `docs/collab/` are committed history, not scratch (Owner decision D-001 covers un-ignoring the existing trail).

## 11. Cadence and budget

- One wave is 3 to 6 parallel-safe packets. Grok may run independent packets concurrently in separate worktrees; dependent packets wait for the merge of what they depend on.
- Chief reviews within the same session a report lands. A packet that has not reported after `--max-turns` is RETURNed with a smaller scope, never widened.
- Owner is looped in at: packet launch (one line), every ESCALATE, every wave end.

## 12. Definitions

- **Production-ready** is defined in ROADMAP.md section "Definition of production-ready" and is the only definition that counts.
- **Done** means merged into `feature/omarchy-sentinel` with tests green and the LEDGER row updated. A commit on a `grok/` branch is not done.
