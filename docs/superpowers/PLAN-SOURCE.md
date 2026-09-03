# Plan: Omarchy Sentinel — OS ↔ Agent Control Plane

**Status:** Design rewrite — Approach 2 locked. Ready for formal spec after review.  
**Date:** 2026-09-03  
**Classification:** Architectural (new subsystems; no existing app flow to extend)  
**Repo note:** Target tree under `~/Work/` (no git root yet). Spec will live at `docs/superpowers/specs/2026-09-03-omarchy-sentinel-design.md` once the project exists. This file is the working plan, not application code.

**Hardware:** MacBook Pro 2019 T2  
**OS:** Omarchy 4.0.2-1 · Kernel `linux-t2` 7.1.8 · 8GB RAM · ~95GB free

---

## 1. Mission

This computer stays the user’s. Agents are first-class on Omarchy — visible, steerable, stoppable — not an invisible second user.

**OS ↔ AI working together** means:

- The OS gives agents a place to work (session, filesystem, network, hooks).
- Sentinel gives the user a control plane over that work.
- Friction appears only when the *shape* of a session changes (bypass flags, hook writes, new binaries, surprise shells, attacks on the monitor itself).
- Normal coding-agent flow stays silent.

This is not a prompt on every tool call. It is not a SOC. It is a personal HIDS + decision UI sized for an 8GB T2 daily driver.

### Protect means

| Protect | v1 mechanism | Explicitly not |
|---------|--------------|----------------|
| Machine stays bootable, cool, online | Track A hooks + sticky health checks | Distro fork / kernel work |
| User understands agent activity | Inventory, alerts, Investigate detail | Session replay of every token |
| User controls privilege | Ask on bypass / hooks / surprise children | Per-tool-call RBAC |
| Rogue or planted agent | Generated watch list + self-watch | Full antivirus / eBPF SOC |
| Secrets do not leak into the monitor | Metadata only (path, mtime, hash, writer PID, cmdline) | Transcripts or `auth.json` in alerts or cloud payloads |

### Response mode (locked)

Notify + interactive decision. Actions: **Approve** / **Kill** / **Investigate** / **Dismiss**.  
No silent auto-kill. Cloud LLM only if the user clicks **Summarize**.

---

## 2. Decisions locked

| Decision | Choice |
|----------|--------|
| Approach | **2 — Sentinel user daemon + Omarchy UI**, with Approach-1 hooks/timers as shared foundation |
| Tracks | **A (device/Omarchy)** and **B (Sentinel)** designed and shipped in parallel, one spec with clear A/B sections |
| Models | **No local LLMs** (VRAM/RAM). Cloud APIs only, Investigate → Summarize only |
| Threat model (v1) | Runaway / over-privileged / planted local agents first: bypass flags, unexpected shell/network helpers, hook/config tampering, monitor self-defense |
| Privilege | Sentinel runs as **the user**, not root. Kill only user-owned PIDs |
| Battery-low | **Out of scope** — no performance throttle |
| FIDO2 | Deferred and explained; not v1 |
| Fingerprint | Track A goal (fingerprint first, password fallback). **Not a blocker** for Track B |
| Timers | systemd `--user` timers, not crontab, for Sentinel jobs |
| UI | Omarchy notification path + `omarchy-menu.jsonc` extension. No permanent browser UI |
| Code gate | No product daemon until this plan is approved and the formal spec is written and approved |

---

## 3. Scope

| Track | What it is | v1 status |
|-------|------------|-----------|
| **A. Device / Omarchy foundation** | T2 stability after boot/update, fans, disk, wifi, optional fingerprint, hooks | Active — parallel |
| **B. Agentic control plane** | User-space daemon: inventory, inotify, launch visibility, rules, notify, Approve/Kill/Investigate | Active — parallel |
| **C. Scheduled automation** | systemd timers for health + inventory | Shared substrate |
| **D. OS↔AI integration lab** | Skills, MCP, Omarchy hooks as richer agent control plane | Backlog |
| **E. Project portfolio** | Clawbox, Hypr Agent Bar, Timerheart, Desktop Copilot Loop | Backlog after A+B |

**v1 deliverable:** one repo (or `track-a/` + `track-b/` in one tree) that keeps the T2 session healthy and makes agent privilege changes visible and reversible.

---

## 4. What changed from the previous draft

Kept:

- Approach 2 architecture (hooks + user daemon + notify + menu).
- Threat model focused on agent artifacts and unattended flags (Blacklight / EAA-shaped).
- systemd timers over cron.
- Omarchy-native hooks before inventing infra.
- No Falco/Wazuh/local LLM/auto-kill in v1.
- Alert schema, three-way action UX, resource caps.

Changed (the previous “bad”):

| Problem | Replacement |
|---------|-------------|
| Process sampler treated as realtime | Launcher wrappers are the reliable `R-BYPASS` path; 2–5s sampler is backup only |
| Kill the whole agent tree | Narrow kill policy: alerting child first, supervisor only on “kill session,” refuse foreign PIDs, double-confirm precious worktrees |
| Allowlist keyed on exe hash | `rule + basename + flag-set + cwd-prefix` with session / 24h / this-repo / forever |
| Hardcoded `~/.claude` / `~/.codex` / Cursor only | Generated watch list from a scout pass (includes Grok Build, MCP, project-local agent dirs if present) |
| Alerts could grow file bodies | Evidence is metadata only; redaction rules for Investigate/cloud |
| `notify-send` as the notification story | Omarchy notification sender / D-Bus Notify; menu via `omarchy-menu.jsonc` |
| Health checks page on every wifi flap | Sticky failures only (N consecutive) |
| Sentinel could be disabled by the thing it watches | `R-SELF` on unit, config, allowlist |
| Fingerprint blocked the rest of the plan | Fingerprint is gated Phase 0; Track B ships anyway |
| Five cool projects competing with v1 | Appendix only |

---

## 5. Architecture

```
Track A — Omarchy / T2 foundation
  hooks: post-boot, post-update
  health timer → sticky checklist (fan / wifi / disk / sentinel unit)
  omarchy setup security fingerprint (optional, non-blocking)
                    │
                    │  ~/.local/state/sentinel/
                    │  ~/.config/sentinel/
                    ▼
Track B — Sentinel (user daemon)
  scout inventory → generated watch list
  inotify(watch list + self paths)
  launcher wrappers + process sampler (backup)
  rule engine
  alert queue (alerts.jsonl)
                    │
                    ▼
  notifier  → Omarchy desktop notification (critical = sticky)
  menu      → omarchy-menu.jsonc "Sentinel"
              sentinel-action <alert-id> <approve|kill|investigate|dismiss>
  investigate → local detail; optional redacted cloud Summarize
```

### Boundaries

- Sentinel is a **user** systemd service. No root helper in v1.
- Track A never calls an LLM. Track B calls a cloud LLM **only** from `sentinel-investigate` on an explicit button.
- Shared state: `~/.local/state/sentinel/` (alerts, health, inventory, allowlist runtime).
- Shared config: `~/.config/sentinel/` (watch seeds, rules, API settings).
- Hooks are small scripts: write health, poke inventory, warn if Sentinel is down. They do not embed rule logic.
- Daemon process must not import a cloud SDK. Summarize is a separate oneshot.

### Non-goals (v1)

- Falco / eBPF / auditd-as-product / Wazuh
- Local model weights
- Silent auto-kill
- Multi-user or server mode
- Per-tool-call approval
- Always-on “last tool call” bar
- Auto-disabling `--dangerously-skip-permissions` (it remains allowed; it becomes visible and scopable)
- Battery-based throttling
- FIDO2

---

## 6. Components

### Track A

| Component | Role |
|-----------|------|
| `hooks/post-boot.d/sentinel-health` | After desktop start: `t2fanrd`, wifi iface, disk >10% free, Sentinel unit active → `health.json`. Notify only on failure |
| `hooks/post-update.d/sentinel-recheck` | After `omarchy update`: confirm `linux-t2`, `apple-bcm-firmware`, `t2fanrd` still installed; trigger one inventory |
| `sentinel-health.timer` | Every 30–60 min oneshot. Notify only after **sticky** fail (default: 3 consecutive) |
| `omarchy hook install` | Install method for hooks so updates do not fight hand-copied files |
| `omarchy setup security fingerprint` | Fingerprint first, password fallback for lock / sudo / polkit. Recovery = password still works |

`battery-low` hook: do not install.

### Track B

| Component | Role |
|-----------|------|
| `sentinel-scout` | Metadata inventory of agent homes (path, size, mtime, kind). Writes watch list. No session bodies |
| `sentinel-daemon` | Long-running user service: inotify + sampler + rules + enqueue alerts |
| `sentinel-wrap` | Thin wrappers around known launchers so bypass flags are visible at start |
| `sentinel-notify` | Turns alerts into Omarchy notifications |
| `sentinel-action` | Approve / Kill / Investigate / Dismiss |
| `sentinel-investigate` | Local detail view; optional redacted cloud digest |
| `sentinel-inventory.timer` | Daily off-peak deep scout + refresh watch list |
| Config | `~/.config/sentinel/config.toml` |
| State | `~/.local/state/sentinel/alerts.jsonl`, `health.json`, `inventory.json`, `watchlist.json`, `allowlist.json` |

### systemd --user units

| Unit | Purpose | Budget |
|------|---------|--------|
| `sentinel.service` | Daemon, `Restart=on-failure`, `RestartSec=5` | MemoryMax ≈ 256M |
| `sentinel-health.timer` | Periodic health oneshot | Lightweight |
| `sentinel-inventory.timer` | Daily inventory oneshot | MemoryMax ≈ 512M |

Enable via user systemd, not a second copy in `~/.config/hypr/autostart.lua`.

If the daemon flaps (N restarts in a window), notify “Sentinel unstable” and leave Track A hooks running.

---

## 7. Watch list and scout

Do not hardcode three vendor homes and call it done.

**Seed candidates (if present):**

- `~/.claude/`, project `.claude/`
- `~/.codex/`, project `.codex/`
- Cursor / agent config dirs
- Grok Build / custom MCP server config dirs actually used on this machine
- `~/.config/sentinel/` and `~/.local/state/sentinel/` (self)

**Scout rules:**

- Record path, kind (settings / hooks / mcp / auth / other), size, mtime.
- Do not open transcript or credential file bodies.
- Missing dirs = skip quietly (no “not installed” alert).
- Nightly inventory + post-update + first run refresh `watchlist.json`.
- Daemon watches the generated list, not the seed comments in this plan.

---

## 8. Detection rules (v1)

| ID | Trigger | Severity | Default prompt |
|----|---------|----------|----------------|
| `R-BYPASS` | Known agent started with bypass / yolo / trust-all / skip-permissions flags | high | Kill / Investigate / Approve |
| `R-HOOK-WRITE` | Write to agent lifecycle hook or settings under the watch list, especially non-editor writers | high | Investigate / Approve |
| `R-CHILD-SHELL` | Agent parent spawns interactive shell, `curl\|bash` / `wget\|sh`, or unexpected net helper | high | Kill (child) / Investigate |
| `R-NEW-AGENT` | First-seen agent binary path or new MCP server config entry | medium | Investigate / Approve |
| `R-SELF` | Edit/disable of Sentinel unit, config, allowlist, or watch list by a non-Sentinel writer | high | Investigate / Kill |
| `R-ALLOW-EXPIRE` | Previously approved fingerprint expired and the pattern recurred | low | Approve again |

Deferred: `R-TIMER-NEW`, Falco host rules, sandbox escapes.

### How `R-BYPASS` is seen

1. **Primary:** `sentinel-wrap` on known binaries (`claude`, `codex`, Cursor agent CLIs, grok/build wrappers as discovered by scout). Wrapper records argv, then execs the real binary.
2. **Backup:** process sampler every 2–5s. Document this as near-realtime, not syscall-realtime. Coalesce duplicate alerts for 60s.
3. inotify coalescing on bursty editors for hook/settings writes.

### Noise control (8GB)

- Sampler interval 2–5s.
- Duplicate coalesce 60s.
- Heavy inventory only on timer / post-update / explicit “inventory now.”
- Health notifications only when sticky.

---

## 9. Alert schema

`alerts.jsonl` — one JSON object per line.

```json
{
  "id": "uuid",
  "ts": "ISO-8601",
  "rule": "R-BYPASS",
  "severity": "high",
  "summary": "claude started with bypassPermissions",
  "pids": [1234, 1250],
  "exe": "/usr/bin/claude",
  "basename": "claude",
  "cmdline": ["claude", "--dangerously-skip-permissions"],
  "cwd": "/home/tav/Work/scratch",
  "parent": {"pid": 1200, "exe": "foot"},
  "paths": ["/home/tav/.claude/settings.json"],
  "writer_pid": null,
  "hashes": {"/home/tav/.claude/settings.json": "sha256:…"},
  "evidence": {"flag": "bypassPermissions"},
  "status": "open"
}
```

`status`: `open` | `approved` | `killed` | `investigated` | `dismissed`

**Forbidden in alerts and in any cloud payload:**

- Transcript / session text
- `auth.json` / token / refresh contents
- MCP env values and API keys
- File bodies of settings (hash + path only)

---

## 10. Allowlist (so this does not bottleneck work)

**Key:** `rule + basename + flag-set + cwd-prefix`

**Scopes:**

| Scope | Meaning |
|-------|---------|
| session | Until logout / daemon restart |
| 24h | Wall clock |
| this-repo | This `cwd` prefix only |
| forever | Until manually revoked |

Approve writes the key + scope + expiry.  
Kill never allowlists.  
Expired keys emit `R-ALLOW-EXPIRE` (low), not a new high-severity panic.

This is how “I meant to yolo in `~/Work/scratch`” stays quiet there without blessing `~/Work/prod`.

---

## 11. Kill policy

Kill is the feature that can wreck a real workflow. Default is **narrow**.

1. Menu confirm. Show PIDs, cmdlines, cwd.
2. Default target = the **alerting child** (`bash`, `sh`, `curl`, `wget`, `nc`, unexpected one-liner interpreter), not the whole tree.
3. Optional second action: **Kill session** = SIGTERM the agent supervisor for that alert.
4. Wait 3s; SIGKILL only the PIDs still alive from that target set.
5. Refuse any PID not owned by the user.
6. If cwd is in a configured “precious worktrees” list, require a second confirm before supervisor kill.
7. Already-exited PID = success, note in log.
8. Do not allowlist on kill.

Precious worktrees start empty and are user-filled (`~/Work/…` paths they do not want a stray SIGTERM to touch).

---

## 12. Notification and menu UX

### Notification

- Use Omarchy’s notification path (`omarchy-notification-send` or session-bus `Notify`), not raw `notify-send` argv parsing.
- Title: severity + short summary.
- Body: basename + one-line why + cwd basename.
- High = critical / sticky. Medium = normal. Low = quiet.
- Action affordance opens Sentinel menu for that `alert.id`.

### Menu (`~/.config/omarchy/extensions/omarchy-menu.jsonc`)

```
Sentinel
  Open alerts
  Status
  Inventory now
  Pause 1h
```

Per-alert actions (via `sentinel-action`):

| Action | Behavior |
|--------|----------|
| Approve | Submenu: Session / 24h / This repo / Forever → write allowlist → `approved` → dismiss |
| Kill | Confirm → narrow kill policy → `killed` |
| Investigate | Local detail (cmdline, cwd, parent, paths, hashes, recent related events). Button **Summarize with cloud AI** is opt-in per click |
| Dismiss | Close without allowlist (`dismissed`) |

### UX principles

- Never Kill without confirm.
- Never call cloud LLM unless Summarize is clicked.
- If daemon is down, Track A post-boot / health hook notifies “Sentinel inactive.”
- No permanent browser UI in v1.
- Pause 1h suppresses new notifications but keeps logging (so a noisy session is not “turn it off forever”).

---

## 13. Investigate and cloud digest

Investigate is local first: pager or terminal detail from the alert object + recent coalesced events for the same key.

**Summarize** (optional):

- Separate process, not the daemon.
- Sends a **redacted bundle** only: rule, severity, basename, flags, cwd, parent basename, path names, hashes, writer PID.
- Never sends file bodies, transcripts, tokens, env.
- On API failure: show raw local evidence; do not block Kill/Approve.
- API key from env / secret file with mode `0600`, never committed.

Preferred provider at implement time: whatever is already configured for this user (xAI / other). Not a v1 blocker.

---

## 14. Fingerprint and FIDO2 (Track A)

**Fingerprint (v1, non-blocking):**

1. Guided `omarchy setup security fingerprint`.
2. Goal order: fingerprint first, password fallback (lock, sudo, polkit).
3. Verify each of those three prompts prefers the reader when it works.
4. Document recovery: password still works if the reader fails.
5. Sentinel Approve/Kill stay click-confirm — not gated on fingerprint.

**FIDO2 (deferred):** a hardware security key (e.g. YubiKey) you tap instead of typing a password. Useful later. Not part of v1 unless hardware is already on hand.

---

## 15. Error handling

| Condition | Behavior |
|-----------|----------|
| Daemon crash | systemd restart; flap → “Sentinel unstable”; hooks stay up |
| Cloud LLM failure | Raw evidence only |
| Kill of exited PID | Success + log |
| inotify queue overflow | One warning alert + force inventory |
| Missing agent dirs | Skip quietly |
| Wrapper missing / agent launched unwrapped | Sampler backup; do not fail closed |
| Health wifi/fan blip | Count toward sticky threshold; no toast until sticky |
| User not in graphical session | Queue notifications; do not spawn UI from a timer in a vacuum |

---

## 16. Resource budget

- Daemon MemoryMax soft target ≤ 256M.
- Inventory oneshot ≤ 512M.
- No always-on browser UI.
- No local model weights.
- No battery-based slowdown.
- Python is acceptable for v1 if it stays stdlib + inotify and the cloud client lives in the investigate oneshot. If RSS will not stay near budget, rewrite the daemon later (Go/Rust). Do not start there.

---

## 17. Testing and rollout (this T2 laptop)

### Phase 0 — Scout + baseline (same day)

- Confirm `linux-t2`, `t2fanrd`, wifi modules (already expected healthy).
- Run `sentinel-scout` once; review `watchlist.json` before any daemon.
- Attempt fingerprint setup; if the reader is flaky, continue.
- Create project dirs under `~/Work/` (`sentinel/` or mono-repo with `track-a/` + `track-b/`).
- Still no long-running product daemon until spec + implementation plan are approved.

### Phase 1 — Track A

- Install post-boot + post-update via `omarchy hook install`.
- Enable `sentinel-health.timer`.
- Test: reboot → `health.json` OK.
- Test: simulated missing fan service → notification.
- Test: wifi flap does **not** toast until sticky.
- Test: no battery-low behavior change.

### Phase 2 — Sentinel MVP

- Watch list + inotify + wrappers + sampler backup.
- Rules: `R-BYPASS`, `R-HOOK-WRITE`, `R-SELF` only.
- Wire notify + menu Approve / Kill / Investigate (local detail).
- Synthetic `R-BYPASS` via a test script / wrapped fake flag.
- Test kill only on an owned throwaway process.
- Enable `sentinel.service` + nightly inventory timer.

### Phase 3 — Child policy + allowlist scopes

- `R-CHILD-SHELL` with narrow kill policy.
- Session / 24h / this-repo / forever.
- Precious-worktree second confirm.

### Phase 4 — Cloud Summarize

- Opt-in button only.
- Failure path = raw evidence.

### Acceptance

- [ ] Fake bypass-flag process → notification within a few seconds (wrapper path).
- [ ] Unwrapped bypass still caught by sampler on next tick (documented lag).
- [ ] Approve this-repo suppresses re-alert in that cwd and not in another.
- [ ] Kill stops the target child; refuses non-owned PIDs; does not SIGTERM an unrelated compile by default.
- [ ] Investigate shows detail; LLM only on Summarize; payload has no file bodies.
- [ ] Test write to `~/.config/sentinel/config.toml` from a non-Sentinel process → `R-SELF`.
- [ ] After reboot, daemon + health timer return.
- [ ] Daemon RSS stays near budget at idle.
- [ ] Fingerprint unlock + sudo work **or** documented skip; password always works.
- [ ] Health wifi flap does not spam.

### Rollout caution

No product code until:

1. This plan is accepted.
2. Formal spec is written and accepted.
3. `writing-plans` produces an implementation DAG and that DAG is accepted.

---

## 18. Formal next steps

1. Review this `plan.md`.
2. Write `docs/superpowers/specs/2026-09-03-omarchy-sentinel-design.md` (Tracks A+B, one file, clear sections). Spec must include: mission, kill policy, allowlist key, generated watch list, self-watch, redaction, Omarchy menu/notification APIs, launcher wrappers.
3. User reviews the spec.
4. Invoke `writing-plans` for the implementation DAG.
5. Only then write daemon / hook / unit files.

---

## Appendix A — Research that still applies

Treat local agent artifacts like browser profiles (SpecterOps Blacklight): credentials, settings, sessions, MCP configs, trusted roots under agent homes.

Defend the EAA-shaped techniques that match this laptop: malicious/unattended CLI invocation, permissive flags, lifecycle hook planting, transcript theft, hostile MCP/tools. v1 covers invocation, flags, hooks, and surprise children. Memory/instruction poisoning and transcript theft are inventory/hardening follow-ons, not daemon features.

Prefer systemd timers (journald, `Persistent=`, cgroup limits, no overlap).

Use Omarchy hooks that already exist: `post-boot`, `post-update`. Empty hook dirs today except `.sample` files.

Runtime isolation (Clawbox / bubblewrap / microVM) is the right *next* product for untrusted repos. RAM is tight — do not pretend v1 is a sandbox.

T2 QoL already good: `linux-t2`, `t2fanrd`, `apple-bcm-firmware`, wifi modules. Track A only re-verifies and notices drift after `omarchy update`. Optional later: lid/resume black-screen probe in the health snapshot. `tiny-dfr` / Touch Bar is not v1.

---

## Appendix B — Backlog (not v1 body)

1. **Clawbox-on-Omarchy** — disposable worktree/VM for untrusted agent runs. Host secrets stay out.
2. **Hypr Agent Bar** — live agent status, last tool call, egress flag, one-key kill. After the daemon is trusted for a week.
3. **Timerheart** — YAML job registry compiled to systemd timers; natural-language schedule proposals.
4. **Desktop Copilot Loop** — constrained computer-use agent gated by Sentinel policy.
5. FIDO2 when a key exists.
6. `R-TIMER-NEW`, Falco, auditd shipping.

Sentinel itself is the flagship. The others wait until A+B survive real use without being muted.

---

## Appendix C — One-page operating model

```
You launch an agent in a trusted repo, no bypass flags
        → silent

You launch with yolo in ~/Work/scratch and Approve “this-repo”
        → silent there; still asks elsewhere

Something writes ~/.claude hooks or Sentinel config
        → sticky notify → Investigate / Approve / Kill

Agent spawns curl | bash
        → notify → Kill child (default) or Investigate

You are deep in a noisy session
        → Pause 1h (log continues)

You want a plain-language digest
        → Investigate → Summarize (redacted, optional)

Machine just updated Omarchy
        → post-update rechecks T2 packages + one inventory
```

That is the product: the OS and the agents share a session; the user keeps the controls.
