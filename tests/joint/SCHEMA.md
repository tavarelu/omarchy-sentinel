# Joint adversarial suite: the case contract

Test 3 is written by two authors. **Grok is the red team** and writes case files under `tests/joint/cases/`
plus any fixture text they need. **Claude wrote the harness** (`tests/joint/test_adversarial.py`), which loads
every case file and asserts exactly what the case declares. Neither side edits the other's half: a
disagreement becomes an ask under `docs/collab/asks/`, and both verdicts are recorded in
`docs/collab/reports/UX-tests-report.md`.

The harness fails loudly on any key it does not implement, so a case can never silently assert nothing.

What the prefs file may and may not do is worth stating once, because several cases turn on it: a pref may
flip a severity's `enabled` in either direction (that is the panel's filter), and it may never change a
severity's urgency or timeout, never affect a sticky self-tamper alert, and never make Sentinel read anything
it would not otherwise read. Non-boolean and unknown keys are ignored one by one rather than rejecting the
whole file.

## File format

One JSON object per file, `tests/joint/cases/<id>.json`. `id` must match the filename stem.

```json
{
  "id": "prefs-with-extra-keys",
  "title": "A tampered prefs file: unknown keys are ignored, only `enabled` can change",
  "author": "grok",
  "why": "An agent that can write the state dir tries to turn a severity back on, or add a new one.",
  "requires": ["ux-01"],
  "config": "[notify]\nhigh_timeout = 30\n",
  "state": {"notify-prefs.json": "{\"version\":1,\"severities\":{\"high\":false,\"bogus\":true}}"},
  "action": {"type": "notify", "interval_sec": 1,
             "alerts": [{"severity": "high", "summary": "s"}]},
  "expect": {"no_exception": true, "toasts": 0, "summaries": 0}
}
```

### Top-level keys
| key | required | meaning |
|---|---|---|
| `id` | yes | matches the filename stem; appears in the pytest test id |
| `title` | yes | one line, what the case proves |
| `author` | yes | `grok` or `claude` |
| `why` | yes | the attack or mistake being modelled, in the author's own words |
| `requires` | no | feature gates; a case naming an unimplemented gate is **skipped**, not failed. Known gates: `ux-01` (notify policy and burst), `ux-02a` (investigate v2 and `open`) |
| `config` | no | raw text written to `XDG_CONFIG_HOME/sentinel/config.toml` before the action |
| `state` | no | filename → raw text, written into `XDG_STATE_HOME/sentinel/` before the action. Raw text on purpose: a case may write invalid JSON, a truncated file, or a file full of newlines |
| `state_mode` | no | filename → octal string (e.g. `"666"`) applied after writing, so a case can model a foreign-written file |
| `action` | yes | see below |
| `expect` | yes | see below |

### Actions
- `{"type": "notify", "alerts": [ …alert stubs… ], "interval_sec": 1}` — each stub is passed to
  `Alert.new` with defaults filled in (`rule` `R-BYPASS`, `severity` `high`, `pids` `[]`, `exe`/`basename`/
  `cwd` synthetic). The alerts go through a real `Notifier` built from the case's config, with a recording
  runner in place of `omarchy notification send` and a fake clock advanced by `interval_sec` per alert.
- `{"type": "cli", "argv": ["notify", "--json"]}` — runs `sentinel.action.main(argv)` in-process with stdout
  captured. No network, no real notification server, no subprocess.

### Expectations
| key | asserts |
|---|---|
| `no_exception` | the action completed without raising (a `false` value asserts it *did* raise) |
| `toasts` | number of per-alert toasts sent (argv without `-p`/`-r`) |
| `summaries` | number of summary toasts sent (argv with `-p` or `-r`) |
| `urgencies` | the exact set of `-u` values seen, as a sorted list |
| `timeouts` | the exact set of `-t` values seen, as a sorted list of strings; a sticky toast contributes nothing |
| `argv_excludes` | no argv element equals any of these strings |
| `body_contains` / `body_excludes` | substrings that must / must not appear anywhere in the sent argv |
| `exit_code` | return value of `main` (cli actions) |
| `stdout_contains` / `stdout_excludes` | substrings of captured stdout (cli actions) |
| `state_modes` | filename → octal string the file must have after the action |
| `state_json_keys` | filename → keys the file's JSON must contain after the action |
| `unchanged` | list of state filenames whose bytes must be identical after the action |

Two invariants are asserted for **every** case without being declared, because they are the point of the
exercise: every argv is a list of `str` (nothing is ever handed to a shell), and no argv element contains a
newline. A case that expects a violation must say so with `argv_excludes` or by expecting an exception.
