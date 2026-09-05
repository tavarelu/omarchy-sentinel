# Sentinel roadmap to v1.0

The project exists to protect people and their hardware from AI coding agents that run with too much privilege, in loops, or with planted code. It watches behavior on the machine; it does not scan skill code before install (NVIDIA SkillSpector does that) and it does not sandbox (OpenShell and bubblewrap do that). Those are the layers above and below; Sentinel is the one in the middle and integrates with both later.

## Where we are (2026-09-04)

- 20 commits on `feature/omarchy-sentinel`, 116 tests green, nothing installed live.
- Three commits are unreviewed (`e0f2c86`, `30533f6`, `c015834`).
- The Chief's audit on 2026-09-04 found 13 defects that would surface within minutes of a live install. Wave 3 fixes them.

## Wave 3: make it true (correctness before anything else)

| Packet | Title | Parallel-safe |
|--------|-------|---------------|
| W3-01 | Allowlist and Approve correctness | yes |
| W3-02 | One alert per process instance, safe kill, store hygiene | yes |
| W3-03 | Scout v2: precise watchlist, project dirs, hot reload | yes |
| W3-04 | Wire R-CHILD-SHELL into the sampler | after W3-02 |
| W3-05 | Vendor bypass table, install truth, a real click path | yes |
| W3-06 | Docs truth: ledger, status, review trail (Chief-owned) | yes |
| W3-07 | Self-defense: journal mirror, foreign-write tripwire, pause cap (security review S1) | after W3-02 |

Exit: all merged, G0 and G1 green, watch roots on the Chief's machine under 20, a simulated plugin-marketplace refresh produces zero alerts, one bypass session produces exactly one toast.

## Wave 4: prove it

- W4-01 Acceptance smoke rewritten for what the code can actually observe (no writer PID from inotify).
- W4-02 Live install, dry-run first, Owner-run with Chief guidance: wrappers with PATH verification, menu, Track A, then the daemon.
- W4-03 Seven-day soak with a noise budget: alerts per day, false positives per day, daemon RSS and CPU sampled by the health timer. Tune until the budget holds.
- W4-04 R-NEW-AGENT: first-seen agent binary, new MCP config entry, new plugin or skill directory.

Exit: G2 passes, the noise budget holds for seven days on the Owner's machine.

## Wave 5: package it

- W5-01 Name and license. "Sentinel" collides with several security products; Owner picks the public name (D-002) and the license (D-003).
- W5-02 Packaging: wheel via pyproject, an AUR PKGBUILD, binaries on PATH, systemd units with installed absolute ExecStart, config template installed to `~/.config/<name>/`.
- W5-03 Omarchy plugin: `manifest.json` at the repo root, `BarWidget.qml` with the open-alert count, `Panel.qml` listing alerts with Approve, Kill, Investigate and Dismiss, plus an install-daemon button (D-004). Publish through the marketplace issue form; see `docs/collab/PUBLISHING.md`. Scaffolded by Chief 2026-09-04 so the shape is settled before wave 3 finishes.
- W5-04 CI: pytest, ruff, shellcheck, `systemd-analyze verify`, a fake-/proc integration test, SkillSpector run on the repo itself.
- W5-05 Docs: README for humans, threat model, SECURITY.md with disclosure policy, CONTRIBUTING.md, CHANGELOG.
- W5-06 Adapters: Codex config bypass keys, Gemini CLI, Cursor agent, Grok Build config bypass, each with a test fixture.

Exit: `pip install` and the AUR package both work on a clean Omarchy VM; docs reviewed by Owner.

## Wave 6: extend it

- W6-01 Gate: run NVIDIA SkillSpector on new skill, plugin and MCP roots the moment they appear and surface the verdict in the same notification. Detailed plan: `docs/collab/plans/SKILLSPECTOR-INTEGRATION.md` (packets W6-01a to W6-01e).
- W6-02 Loop detection: process spawns and shell children per agent per minute versus that session's own baseline.
- W6-03 Content-hash diff for hooks and settings so the alert says which file changed and only fires on real change.
- W6-04 Writer attribution prototype with unprivileged fanotify on Linux 5.13+, behind a flag, with a measured false-positive comparison against inotify.
- W6-05 Containment hook: optional bubblewrap launch profile per agent, off by default.

## Definition of production-ready (v1.0)

All of the following, verified by Chief and signed by Owner:

1. Installs from a package on a clean Omarchy system with one documented command, and uninstalls cleanly.
2. Seven-day soak on a daily-driver machine with the noise budget held and no missed synthetic bypass launch.
3. All security invariants in PROTOCOL section 9 hold and are covered by tests.
4. Every rule has a documented false-positive story and an Approve path that actually suppresses it.
5. Kill cannot hit a recycled PID and never targets a non-owned process.
6. Daemon stays under 64 MiB RSS and 1 percent CPU at idle for the soak.
7. README, threat model, SECURITY.md and CHANGELOG exist and match the code.
8. CI green on every merge, including a SkillSpector scan of the repo.
9. No open ESCALATE decisions.

## Release checklist (G3)

- [ ] version bumped, CHANGELOG written
- [ ] tag signed by Owner
- [ ] AUR package updated and installed from AUR on a clean VM
- [ ] wheel published to the index Owner chose
- [ ] announcement draft reviewed by Owner
