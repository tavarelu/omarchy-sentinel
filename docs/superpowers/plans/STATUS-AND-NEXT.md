# Sentinel — honest status and next plan

> **Superseded 2026-09-04.** State now lives in `docs/collab/LEDGER.md`; the working agreement is `docs/collab/PROTOCOL.md`; the plan is `docs/collab/ROADMAP.md`. This file is kept for history. Note: at the time it was written, T12 and T14 were already committed (`e0f2c86`, `30533f6`), not untracked WIP; the "100 passed + 3 failed" line describes an earlier moment than the 116-passed header.

**Date:** 2026-09-03 (paused for token/usage risk)  
**Branch:** `feature/omarchy-sentinel`  
**Worktree:** `/home/tav/Work/sentinel/.worktrees/omarchy-sentinel`  
**Last Chief-reviewed commit:** `4ebfb5d` — pause gates notify + flap toast  
**Later unreviewed commits:** `e0f2c86` T12, `30533f6` T14, `c015834` T13 (landed; **not** R&D-audited)  
**Working tree:** clean except this STATUS file. Pytest **116 passed** at snapshot.

**Say to resume:** `resume Sentinel from STATUS-AND-NEXT.md`

---

## Partner note (honesty)

This is a real, working core — not vaporware. It is **not** finished product. We have not installed it live on the laptop (no `enable --now sentinel.service`). Fingerprint/Touch ID is skipped because it does not work on this machine. Wave-2 (Investigate / child-shell / cloud summarize / acceptance) was started in parallel and **was not finished or reviewed** when this file was written.

If a later session claims T12–T15 are done, check git: they must have commits after `4ebfb5d`. Untracked `investigate.py` / `summarize.py` at snapshot time were WIP.

---

## What we have (committed, wave 1)

Tests at last clean Chief commit: **87 passed**. After WIP files appeared: 100 passed + **3 failed** (summarize CLI wiring — incomplete).

| Piece | Status | Where |
|-------|--------|--------|
| Python package + XDG paths | Done | `src/sentinel/paths.py` |
| Alert JSONL store | Done | `models.py`, `store.py` |
| Allowlist scopes (session/24h/this-repo/forever) | Done | `allowlist.py` |
| Scout metadata watchlist (no file bodies) | Done | `scout.py`, `sentinel-scout` |
| Rules MVP: R-BYPASS, R-HOOK-WRITE, R-SELF | Done | `rules.py` |
| Launcher wrappers + install script | Done | `wrappers/`, `scripts/install-wrappers.sh` |
| Daemon: inotify + sampler + coalesce | Done + review fixes | `daemon.py` |
| Omarchy notify (`omarchy notification send`) | Done | `notify.py` |
| Approve / Kill / Dismiss / Pause CLI | Done | `action.py`, `kill.py` |
| Menu JSONC + dry-run installer | Done | `packaging/`, `scripts/install-menu.sh` |
| Track A health hooks + sticky timer | Done | `health.py`, `track-a/` |
| systemd user units (not live-enabled) | Done | `track-b/systemd/`, `scripts/install-systemd.sh` |
| Pause actually suppresses toasts | Done (Chief) | `notify.py` + `is_paused()` |
| Flap → “Sentinel unstable” | Done (Chief) | unit `StartLimitBurst` / `OnFailure` |

**R&D audit:** `PASS_WITH_GAPS` then Chief closed the two must-fixes.  
Files: `.superpowers/sdd/2026-09-03-omarchy-sentinel/rnd-audit-wave1.md`, `chief-integrate-wave1.md`

**User rulings already applied**
- No local LLMs
- No silent auto-kill
- No battery-low throttle
- Fingerprint / Touch ID **skipped** (reader not working)
- FIDO2 deferred

---

## What is left

### Must finish (wave 2)

| Task | Need | Notes |
|------|------|--------|
| **T12 Investigate** | Pager detail view | Commit `e0f2c86` exists — **needs R&D review**, not just a commit |
| **T13 R-CHILD-SHELL** | Surprise shells + precious worktrees | Commit `c015834` — **needs R&D**. Implementer noted daemon sampler is **not wired**, so the rule may not fire live until that hook exists |
| **T14 Summarize** | Opt-in redacted cloud digest | Commit `30533f6` exists — **needs R&D review** |
| **T15 Acceptance** | Smoke script + README; fingerprint skip docs | **Not started** |

### Then (human / install — not code)

1. Review `watchlist.json` from a real `sentinel-scout --refresh` on this machine.
2. Install wrappers **opt-in** (`scripts/install-wrappers.sh claude` etc.) — backs up first.
3. Menu: `scripts/install-menu.sh` (default dry-run).
4. Track A: `scripts/install-track-a.sh --dry-run` first.
5. systemd: copy units; **do not** `enable --now sentinel.service` until smoke.
6. ExecStart currently assumes `%h/Work/sentinel/.venv` — this clone is a **worktree**. Override or install to canonical path.

### Explicitly out of v1

- Fingerprint / Touch ID
- FIDO2
- Falco / eBPF / Wazuh
- Auto-kill without confirm
- Per-tool-call approval
- Clawbox / Hypr Agent Bar / Timerheart / Desktop Copilot (backlog)

---

## How to resume (next session)

1. Open worktree: `cd ~/Work/sentinel/.worktrees/omarchy-sentinel`
2. `git status` — if dirty, either finish/commit wave-2 WIP **or** `git checkout --` / clean untracked if agents left garbage.
3. Confirm `git log -1` is `4ebfb5d` or later **reviewed** commits.
4. Finish T12 → T13 → T14 → T15 (or one parallel wave then R&D + Chief again).
5. Run `pytest` until green.
6. Only then consider live install.

**Do not re-do tasks 0–11** unless tests regress.

---

## Spec / plan files (source of truth)

- Design: `docs/superpowers/specs/2026-09-03-omarchy-sentinel-design.md`
- Implementation plan: `docs/superpowers/plans/2026-09-03-omarchy-sentinel.md`
- This status: `docs/superpowers/plans/STATUS-AND-NEXT.md`
