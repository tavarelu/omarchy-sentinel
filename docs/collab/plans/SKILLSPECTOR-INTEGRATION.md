# Plan: NVIDIA SkillSpector as Sentinel's install-time gate

Author: Chief, 2026-09-05. Status: proposed; packets W6-01a to W6-01e. Depends on W3-02 and W3-03.

## 1. Why

Sentinel watches what agents *do*. SkillSpector judges what a skill, plugin or MCP server *is* before it runs. The two are complementary layers, and the gap between them is exactly where the ClawHavoc-style attacks live: a skill that passes a glance, gets installed, and misbehaves later. Integrating the scanner gives Sentinel the one thing it cannot do by design, which is look inside new code, while keeping Sentinel's own invariants: the daemon never parses bodies, never imports the scanner, and never calls the network.

## 2. What SkillSpector is (verified 2026-09-05 from github.com/NVIDIA/skillspector and docs.nvidia.com/skills)

| Fact | Value |
|------|-------|
| License | Apache-2.0 |
| Install | `uv tool install git+https://github.com/NVIDIA/skillspector.git` or `pip install git+...` into a venv; Docker image available |
| Command | `skillspector scan <target>`; targets: directory, `SKILL.md`, git URL, zip, single file |
| Output | `--format terminal|json|markdown|sarif`, `-o PATH` |
| Static stage | regex, AST, taint tracking, YARA; **no key, no network** |
| LLM stage | optional; needs a provider (OpenAI, Anthropic, Bedrock, NVIDIA, or a local Claude/Codex CLI); file contents are sent; **`--no-llm` disables** |
| Supply chain | queries `api.osv.dev` for CVEs with an offline fallback to a bundled list |
| Coverage | 71 patterns, 17 categories: prompt injection, anti-refusal, exfiltration, privilege escalation, supply chain, excessive agency, output handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse, behavioral AST, taint, YARA, MCP least privilege, MCP tool poisoning |
| Score | 0 to 100; 0 to 20 SAFE, 21 to 50 CAUTION, 51 to 80 and 81 to 100 DO NOT INSTALL |
| Exit codes | 0 score ≤ 50; 1 score > 50; 2 error |
| Baselines | `skillspector baseline <path> -o FILE`, then `scan -b FILE` suppresses known findings |
| Extras | `skillspector mcp` runs it as an MCP server for runtime guardrails (not used in v1) |

Not on this machine yet: `uv`, `pipx`, `skillspector`. Python 3.14 venv available.

## 3. Rules the integration must respect

1. The daemon never imports SkillSpector and never runs it in-process. A separate oneshot, `sentinel-scan`, does.
2. Default is static only: `--no-llm`. The LLM stage is a per-scan click, exactly like Summarize, and the user sees what would be sent.
3. Network: the static stage makes one class of call, OSV CVE lookups, which send package names and versions only. Owner decision D-006 sets the default; the scan unit gets `PrivateNetwork=yes` when it is off.
4. The scanner parses hostile input, so it runs in its own transient systemd unit with `MemoryMax=512M`, a 120 s timeout, `ProtectHome=read-only`, `ReadWritePaths=` limited to the report directory, `NoNewPrivileges=yes`, `Nice=10`.
5. Alerts carry the verdict, the score, counts by severity, and the top findings' titles, files and lines. Never file contents. The full report stays on disk in the state dir.
6. SkillSpector is pinned to a tag or commit (D-007) and updated deliberately; its version is recorded in every scan result.

## 4. What counts as a scannable root, and where they are on this machine

| Kind | Marker | Roots seen here |
|------|--------|-----------------|
| Claude Code skill | `SKILL.md` | `~/.claude/skills/*`, `<project>/.claude/skills/*` |
| Claude Code plugin | `.claude-plugin/plugin.json` | `~/.claude/plugins/marketplaces/*/plugins/*`, `~/.claude/plugins/marketplaces/*/external_plugins/*`, `~/.claude/plugins/cache/*` when present |
| Codex skill | `SKILL.md` | `~/.codex/skills/*` |
| Grok Build plugin | plugin dir | `~/.grok/installed-plugins/*` |
| Omarchy shell plugin | `manifest.json` | `~/.config/omarchy/plugins/*` |
| MCP server config | `.mcp.json`, `mcpServers` in `~/.claude.json`, `[mcp]` in `~/.grok/config.toml`, `~/.codex/config.toml` | present: `~/.claude.json` (0 servers), `~/.grok/config.toml` |

Counts today: 31 `SKILL.md` under `~/.claude`, 6 under `~/.codex`, 83 under `~/.grok`. The marketplace cache alone is dozens of roots, which is why scanning is queued, one root at a time, and why baselines matter.

**Root identity** is a tree hash: sha256 over the sorted list of `(relative path, size, mtime_ns)` for every file under the root, plus the sha256 of the marker file. Metadata only, consistent with the scout. A changed hash means "re-scan".

## 5. Architecture

```
scout (nightly, post-update, first run)
  discovers roots by marker → writes roots + tree hashes into watchlist.json ("roots": [...])
  diff against previous inventory → new or changed roots → queue

daemon (inotify)
  IN_CREATE|IN_ISDIR directly under a skill/plugin parent dir → debounce 5 s (git clone writes many files)
  → verify marker exists → queue

queue: state_dir()/scans/queue/<hash>.json   (path, kind, reason, discovered_at)
runner: sentinel-scan (oneshot, spawned by daemon via systemd-run --user, one at a time)
  skillspector scan <root> --no-llm --format json -o state_dir()/scans/<hash>.json [-b baseline]
  parse → ScanResult → Alert R-NEW-AGENT → append + notify + journal mirror

actions (sentinel-action / panel)
  approve   → allowlist the (kind, root hash) pair; write a baseline for the root
  report    → open the markdown report in the floating terminal pager
  scan      → re-run; --llm asks first and shows the file list that would be sent
  quarantine→ rename root to <name>.quarantined-<ts> after confirm (reversible; never delete)
  dismiss   → close without allowlisting
```

The daemon's only new responsibilities: enqueue, and spawn the runner with `subprocess.Popen(["systemd-run", "--user", "--collect", "--unit=sentinel-scan-<hash8>", "-p", "MemoryMax=512M", "-p", "RuntimeMaxSec=120", ..., sentinel_scan, "--from-queue", hash])`. No new imports.

## 6. Alert schema addition

```json
{
  "rule": "R-NEW-AGENT",
  "severity": "high | medium | low",
  "summary": "new plugin hookify: SkillSpector score 72, DO NOT INSTALL",
  "paths": ["~/.claude/plugins/marketplaces/claude-plugins-official/plugins/hookify"],
  "hashes": {"tree": "sha256:…", "marker": "sha256:…"},
  "evidence": {
    "kind": "plugin",
    "vendor": "claude",
    "reason": "new | changed | manual",
    "scan": {
      "tool": "skillspector", "version": "x.y.z", "mode": "static",
      "risk_score": 72, "verdict": "DO NOT INSTALL",
      "counts": {"critical": 1, "high": 2, "medium": 3, "low": 5},
      "top": [{"id": "EX-002", "severity": "high", "title": "curl to external host in hook", "file": "hooks/stop-hook.sh", "line": 14}],
      "report": "~/.local/state/sentinel/scans/<hash>.json",
      "duration_ms": 4120
    }
  }
}
```

Severity mapping: score ≤ 20 → low (logged, no toast unless `scan.toast_low = true`); 21 to 50 → medium toast; > 50 → high sticky toast whose body names the top finding. Scanner absent or exit 2 → medium, `verdict: "UNSCANNED"`, body says why.

## 7. Configuration (`~/.config/sentinel/config.toml`)

```toml
[scan]
enabled = true
tool = "skillspector"                 # only value in v1
path = ""                              # absolute path to the CLI; empty = ~/.local/share/<id>/scanner/bin/skillspector
mode = "static"                        # static | llm-on-click
osv_lookup = true                      # D-006; false adds PrivateNetwork=yes to the scan unit
timeout_sec = 120
memory_max = "512M"
toast_low = false
roots_extra = []                       # additional parent dirs to watch for new roots
quarantine_dir = ""                    # empty = rename in place
```

## 8. Failure handling

| Condition | Behavior |
|-----------|----------|
| scanner not installed | R-NEW-AGENT medium, verdict UNSCANNED, panel shows Install scanner |
| exit 2 or malformed JSON | UNSCANNED with the stderr tail in the on-disk report, never in the alert |
| timeout | unit killed by RuntimeMaxSec; UNSCANNED with reason timeout; not retried automatically |
| root vanished before scan | queue entry dropped, one journal line |
| marketplace refresh changes 40 roots at once | queue drains one at a time at Nice=10; each root gets its own alert; baselines suppress unchanged findings so re-scans of known-good roots stay quiet |
| scanner itself compromised or crashing | sandboxed unit limits blast radius; version pin makes the update explicit |

## 9. Privacy

Static mode reads files locally and writes a local report. Nothing leaves the machine except OSV lookups (package name and version) when enabled. The LLM stage is per click, and the click shows the list of files that would be sent before sending. Alerts and the journal mirror carry titles, paths, scores and counts only.

## 10. Testing

- A stub `skillspector` executable in `tests/bin/` that returns canned JSON per fixture root, so the suite never needs the real tool or the network.
- Fixture roots under `tests/fixtures/roots/`: a benign skill, a skill with a `curl | bash` in a hook, a plugin with a prompt-injection string in `SKILL.md`, an MCP config with an underdeclared capability. Files are inert text; no executable bits.
- Captured real reports from one scan of each fixture with the pinned SkillSpector, committed as JSON, and a contract test that our parser accepts them and the mapping produces the expected severity.
- Daemon tests: new root → one alert; changed tree hash → one alert with reason changed; approved root with unchanged hash → nothing; queue drains one at a time; scanner absent → UNSCANNED.
- Sandbox test (Owner-run, documented): `systemd-run` properties applied, scan of the marketplace cache finishes under 512 MiB.

## 11. Packets

| Packet | Scope | Depends on | Parallel-safe with |
|--------|-------|------------|--------------------|
| W6-01a | `src/sentinel/scan.py` (ScanResult, parser, severity mapping), `sentinel-scan` entry point and queue runner, `scripts/install-scanner.sh` (venv under `~/.local/share/<id>/scanner`, pinned ref, dry-run default), systemd-run sandbox wrapper, stub scanner and fixtures | W3-02 | W6-01b |
| W6-01b | scout root discovery by marker across the table in section 4, tree hash, `roots` in `watchlist.json`, inventory diff → queue; daemon inotify debounce on parent dirs → queue; daemon spawn of the runner; R-NEW-AGENT alert construction | W3-03 | W6-01a |
| W6-01c | `sentinel-action <id> approve|report|scan|quarantine`, allowlist key `(rule, kind, tree hash)`, panel verdict pill and buttons, notify body with the top finding, Install scanner button | W6-01a, W6-01b | none |
| W6-01d | baselines on approve, re-scan diff on change, CI: GitHub Action running SkillSpector on this repository with SARIF upload, `make scan` | W6-01c | none |
| W6-01e (Chief) | threat-model section, README section, D-006 and D-007 drafts, acceptance smoke for the gate | W6-01c | none |

Estimated size: about 500 lines of Python plus tests, 150 lines of QML, one shell script. Three Grok packets and two Chief ones.

## 12. Open decisions for Owner

- **D-006** OSV lookups on by default? Sends package names and versions to `api.osv.dev`. Recommendation: on, with `PrivateNetwork=yes` when off.
- **D-007** SkillSpector pinning and update policy. Recommendation: pin to a release tag, bump in a dedicated commit after running the fixture contract test.
- **D-005** (already open from the lock-file discussion) whether Sentinel may parse settings bodies to tell a `/effort` save from a hook change. The gate does not need it; noted for completeness.

## 13. What this does not solve

A skill that passes both the static and LLM stages can still misbehave; that is why the runtime layer exists. And the scanner, like Sentinel, runs as the user; an agent could tamper with the queue or the reports, which W3-07's tripwire covers for the state dir and the journal mirror makes evident.
