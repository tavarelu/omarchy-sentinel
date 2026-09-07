# Omarchy Sentinel — Design Spec

**Date:** 2026-09-03  
**Status:** Draft for user review (no product daemon until this file is approved)  
**Hardware target:** MacBook Pro 2019 T2 · Omarchy 4.0.2-1 · `linux-t2` · 8GB RAM  
**Source plan:** `docs/superpowers/PLAN-SOURCE.md` (approved rewrite)  
**Repo layout:** `~/Work/sentinel/` with `track-a/` and `track-b/`

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
| Threat model (v1) | Runaway / over-privileged / planted local agents: bypass flags, unexpected shell/network helpers, hook/config tampering, monitor self-defense |
| Privilege | Sentinel runs as **the user**, not root. Kill only user-owned PIDs |
| Battery-low | **Out of scope** — no performance throttle |
| FIDO2 | Deferred; not v1 |
| Fingerprint | Track A goal (fingerprint first, password fallback). **Not a blocker** for Track B |
| Timers | systemd `--user` timers, not crontab, for Sentinel jobs |
| UI | `omarchy notification send` + `omarchy-menu.jsonc` extension. No permanent browser UI |
| Language (v1) | Python acceptable if stdlib + inotify; cloud client only in investigate oneshot |

---

## 3. Scope

| Track | What it is | v1 status |
|-------|------------|-----------|
| **A. Device / Omarchy foundation** | T2 stability after boot/update, fans, disk, wifi, optional fingerprint, hooks | Active — parallel |
| **B. Agentic control plane** | User-space daemon: inventory, inotify, launch visibility, rules, notify, Approve/Kill/Investigate | Active — parallel |
| **C. Scheduled automation** | systemd timers for health + inventory | Shared substrate |
| **D–E** | Richer OS↔AI lab + portfolio projects | Backlog (appendix) |

**v1 deliverable:** one tree under `~/Work/sentinel/` that keeps the T2 session healthy and makes agent privilege changes visible and reversible.

---

## 4. Architecture

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
  notifier  → omarchy notification send (critical = sticky)
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
- Auto-disabling `--dangerously-skip-permissions` (allowed; becomes visible and scopable)
- Battery-based throttling
- FIDO2

---

## 5. Track A — Device / Omarchy foundation

| Component | Role |
|-----------|------|
| `hooks/post-boot.d/sentinel-health` | After desktop start: `t2fanrd`, wifi iface, disk >10% free, Sentinel unit active → `health.json`. Notify only on failure |
| `hooks/post-update.d/sentinel-recheck` | After `omarchy update`: confirm `linux-t2`, `apple-bcm-firmware`, `t2fanrd` still installed; trigger one inventory |
| `sentinel-health.timer` | Every 30–60 min oneshot. Notify only after **sticky** fail (default: 3 consecutive) |
| Install path | `omarchy hook install` (do not hand-copy into package-owned trees) |
| Fingerprint | `omarchy setup security fingerprint` — fingerprint first, password fallback for lock / sudo / polkit |

**Do not install** a `battery-low` throttle hook.

### Fingerprint (non-blocking)

1. Guided `omarchy setup security fingerprint`.
2. Goal order: fingerprint first, password fallback.
3. Verify lock, sudo, and polkit prefer the reader when it works.
4. Document recovery: password still works if the reader fails.
5. Sentinel Approve/Kill stay click-confirm — not gated on fingerprint.
6. If the reader is flaky, skip and continue Track B.

**FIDO2 (deferred):** hardware security key (e.g. YubiKey). Not v1.

---

## 6. Track B — Sentinel control plane

| Component | Role |
|-----------|------|
| `sentinel-scout` | Metadata inventory of agent homes (path, size, mtime, kind). Writes watch list. No session bodies |
| `sentinel-daemon` | Long-running user service: inotify + sampler + rules + enqueue alerts |
| `sentinel-wrap` | Thin wrappers around known launchers so bypass flags are visible at start |
| `sentinel-notify` | Turns alerts into Omarchy notifications via `omarchy notification send` |
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

Enable via user systemd, not a second copy in Hyprland autostart.

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

- Record path, kind (`settings` / `hooks` / `mcp` / `auth` / `other`), size, mtime.
- Do not open transcript or credential file bodies.
- Missing dirs = skip quietly (no “not installed” alert).
- Nightly inventory + post-update + first run refresh `watchlist.json`.
- Daemon watches the generated list, not seed comments in this spec.

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

**Deferred:** `R-TIMER-NEW`, Falco host rules, sandbox escapes.

### How `R-BYPASS` is seen

1. **Primary:** `sentinel-wrap` on known binaries (`claude`, `codex`, Cursor agent CLIs, grok/build wrappers as discovered by scout). Wrapper records argv, then execs the real binary.
2. **Backup:** process sampler every 2–5s (near-realtime, not syscall-realtime). Coalesce duplicate alerts for 60s.
3. inotify coalescing on bursty editors for hook/settings writes.

### Noise control (8GB)

- Sampler interval 2–5s.
- Duplicate coalesce 60s.
- Heavy inventory only on timer / post-update / explicit “inventory now.”
- Health notifications only when sticky.

**MVP rule subset (Phase 2):** `R-BYPASS`, `R-HOOK-WRITE`, `R-SELF` only.  
**Phase 3 adds:** `R-CHILD-SHELL`, full allowlist scopes, precious-worktree confirm.

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
  "cwd": "~/Work/scratch",
  "parent": {"pid": 1200, "exe": "foot"},
  "paths": ["~/.claude/settings.json"],
  "writer_pid": null,
  "hashes": {"~/.claude/settings.json": "sha256:…"},
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

## 10. Allowlist

**Key:** `rule + basename + flag-set + cwd-prefix`

| Scope | Meaning |
|-------|---------|
| session | Until logout / daemon restart |
| 24h | Wall clock |
| this-repo | This `cwd` prefix only |
| forever | Until manually revoked |

Approve writes the key + scope + expiry.  
Kill never allowlists.  
Expired keys emit `R-ALLOW-EXPIRE` (low), not a new high-severity panic.

Example: “yolo in `~/Work/scratch`” with Approve **this-repo** stays quiet there without blessing `~/Work/prod`.

---

## 11. Kill policy

Default is **narrow** — Kill must not wreck real workflows.

1. Menu confirm. Show PIDs, cmdlines, cwd.
2. Default target = the **alerting child** (`bash`, `sh`, `curl`, `wget`, `nc`, unexpected one-liner interpreter), not the whole tree.
3. Optional second action: **Kill session** = SIGTERM the agent supervisor for that alert.
4. Wait 3s; SIGKILL only the PIDs still alive from that target set.
5. Refuse any PID not owned by the user.
6. If cwd is in a configured “precious worktrees” list, require a second confirm before supervisor kill.
7. Already-exited PID = success, note in log.
8. Do not allowlist on kill.

Precious worktrees start empty and are user-filled.

---

## 12. Notification and menu UX

### Notification

Use Omarchy’s notification path:

```bash
omarchy notification send -u critical -g "<glyph>" --app-name Sentinel \
  "HIGH: bypass flags" "claude — dangerously-skip-permissions (scratch)" \
  --exec sentinel-action <alert-id> menu
```

- Title: severity + short summary.
- Body: basename + one-line why + cwd basename.
- High = `-u critical` (sticky). Medium = `normal`. Low = `low`.
- Prefer `--exec` to open the action path for that `alert.id`.
- Do not parse raw `notify-send` argv as the primary story.

### Menu (`~/.config/omarchy/extensions/omarchy-menu.jsonc`)

Extend with dotted ids, for example:

```jsonc
{
  "sentinel": {"icon": "󰒃", "label": "Sentinel"},
  "sentinel.alerts": {"icon": "󰀪", "label": "Open alerts", "action": "sentinel-action list"},
  "sentinel.status": {"icon": "󰋼", "label": "Status", "action": "sentinel-action status"},
  "sentinel.inventory": {"icon": "󰮗", "label": "Inventory now", "action": "sentinel-scout --refresh"},
  "sentinel.pause": {"icon": "󰏤", "label": "Pause 1h", "action": "sentinel-action pause 1h"}
}
```

Per-alert actions (via `sentinel-action`):

| Action | Behavior |
|--------|----------|
| Approve | Submenu: Session / 24h / This repo / Forever → write allowlist → `approved` → dismiss |
| Kill | Confirm → narrow kill policy → `killed` |
| Investigate | Local detail; optional **Summarize with cloud AI** per click |
| Dismiss | Close without allowlist (`dismissed`) |

### UX principles

- Never Kill without confirm.
- Never call cloud LLM unless Summarize is clicked.
- If daemon is down, Track A post-boot / health hook notifies “Sentinel inactive.”
- No permanent browser UI in v1.
- Pause 1h suppresses new notifications but keeps logging.

---

## 13. Investigate and cloud digest

Investigate is local first: pager or terminal detail from the alert object + recent coalesced events for the same key.

**Summarize** (optional):

- Separate process, not the daemon.
- Sends a **redacted bundle** only: rule, severity, basename, flags, cwd, parent basename, path names, hashes, writer PID.
- Never sends file bodies, transcripts, tokens, env.
- On API failure: show raw local evidence; do not block Kill/Approve.
- API key from env / secret file with mode `0600`, never committed.
- Provider chosen at implement time from what is already configured (xAI / other). Not a v1 blocker for Phases 0–3.

---

## 14. Error handling

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

## 15. Resource budget

- Daemon MemoryMax soft target ≤ 256M.
- Inventory oneshot ≤ 512M.
- No always-on browser UI.
- No local model weights.
- No battery-based slowdown.
- If Python RSS will not stay near budget, rewrite the daemon later (Go/Rust). Do not start there.

---

## 16. Testing and rollout

### Phase 0 — Scout + baseline

- Confirm `linux-t2`, `t2fanrd`, wifi modules.
- Run `sentinel-scout` once; review `watchlist.json` before any daemon.
- Attempt fingerprint setup; if flaky, continue.
- Project dirs already under `~/Work/sentinel/`.
- No long-running product daemon until this spec **and** the implementation plan are approved.

### Phase 1 — Track A

- Install post-boot + post-update via `omarchy hook install`.
- Enable `sentinel-health.timer`.
- Tests: reboot → `health.json` OK; simulated missing fan → notification; wifi flap does not toast until sticky; no battery-low behavior change.

### Phase 2 — Sentinel MVP

- Watch list + inotify + wrappers + sampler backup.
- Rules: `R-BYPASS`, `R-HOOK-WRITE`, `R-SELF`.
- Wire notify + menu Approve / Kill / Investigate (local detail).
- Synthetic `R-BYPASS` via wrapped fake flag.
- Kill only on an owned throwaway process.
- Enable `sentinel.service` + nightly inventory timer.

### Phase 3 — Child policy + allowlist scopes

- `R-CHILD-SHELL` with narrow kill policy.
- Session / 24h / this-repo / forever.
- Precious-worktree second confirm.

### Phase 4 — Cloud Summarize

- Opt-in button only.
- Failure path = raw evidence.

### Acceptance checklist

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

---

## 17. Implementation gate

No product daemon / hook / unit code until:

1. ~~Plan accepted~~ (done).
2. **This design spec is accepted by the user.**
3. `writing-plans` produces an implementation DAG and that DAG is accepted.

---

## Appendix A — Research basis (summary)

- SpecterOps **Blacklight**: local AI agent artifacts are an endpoint surface (credentials, settings, sessions, MCP, trusted roots). Sentinel inventories and watches metadata; it does not exfiltrate session bodies.
- **EAA** techniques relevant to v1: unattended/permissive CLI invocation, lifecycle hook planting, surprise children. Memory poisoning and transcript theft are later hardening, not daemon features.
- Prefer **systemd timers** over crontab (journald, `Persistent=`, cgroup limits).
- Use existing **Omarchy hooks** (`post-boot`, `post-update`) via `omarchy hook install`.
- Runtime isolation (Clawbox / bubblewrap / microVM) is the next product after Sentinel is trusted — not v1.
- T2 baseline already healthy (`linux-t2`, `t2fanrd`, `apple-bcm-firmware`); Track A re-verifies after updates.

## Appendix B — Backlog (not v1)

1. Clawbox-on-Omarchy  
2. Hypr Agent Bar  
3. Timerheart  
4. Desktop Copilot Loop  
5. FIDO2 when a key exists  
6. `R-TIMER-NEW`, Falco, auditd shipping  

## Appendix C — Operating model

```
Trusted repo, no bypass flags          → silent
Yolo in scratch + Approve this-repo    → silent there; asks elsewhere
Hook / Sentinel config write           → sticky notify → Investigate / Approve / Kill
Agent spawns curl | bash               → notify → Kill child (default)
Noisy session                          → Pause 1h (log continues)
Want plain-language digest             → Investigate → Summarize (redacted, optional)
After omarchy update                   → recheck T2 packages + one inventory
```

---

## Spec self-review (2026-09-03)

| Check | Result |
|-------|--------|
| Placeholders / TBD | None remaining for v1 behavior |
| Internal consistency | Kill narrow by default; wrappers primary for R-BYPASS; fingerprint non-blocking; no battery throttle |
| Scope | Single implementation plan for A+B phased rollout; backlog clearly appendix |
| Ambiguity | Omarchy notify/menu APIs pinned to `omarchy notification send` and `omarchy-menu.jsonc` |
| Secrets | Explicit forbid list for alerts and cloud payloads |
