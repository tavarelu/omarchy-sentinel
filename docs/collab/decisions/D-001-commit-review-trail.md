# D-001: Commit the wave 1 and 2 review trail?
Status: OPEN (Owner)
Drafted by: Chief, 2026-09-04

## Question
`.superpowers/` is gitignored, so the R&D audit, Chief integration notes, 30 task briefs and reports, and the per-task review diffs exist only in this worktree. Removing the worktree after merge erases the only evidence that wave 1 was reviewed.

## Options
1. Un-ignore `.superpowers/sdd/` and commit it. Full history, but internal notes become public in an open-source repo.
2. Copy only `rnd-audit-wave1.md`, `chief-integrate-wave1.md`, and `progress.md` into `docs/collab/history/` and commit those. Keeps the verdicts, drops the diffs and briefs.
3. Leave it ignored and accept the loss.

## Chief recommendation
Option 2. The verdicts are what future contributors need; the diffs are recoverable from git.

## Decision
<Owner fills in>
