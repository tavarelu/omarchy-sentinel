# UX-02a report

Branch: grok/UX-02a   Commits: 964c461 (Grok's tree), 743dee3 (Chief review fixes), merged as 0e1fe2e on feature/omarchy-sentinel
Tests: 210 passed / 0 failed (`.venv/bin/pytest -q`, 1.46 s)

Authorship note: Grok Build (grok-4.6) wrote every line of 964c461 in 16 tool calls
($0.20). The headless client ended the session on a text-only turn before Grok could run
the acceptance command, write this report, or commit, and two resume attempts ended the
same way ($0.04 more, no further work). The Chief therefore committed Grok's tree
verbatim and wrote this report from a full read of the diff. Nothing in 964c461 was
edited by the Chief; the review fixes are a separate commit, 743dee3.

## Done
- `src/sentinel/investigate.py`: `Section`, `SECTION_ORDER`, `RULE_TEXT`, `_fact(label, value, source)`,
  per-rule renderers for R-BYPASS, R-HOOK-WRITE, R-SELF (write, watch-lost and the W3-07 tamper events),
  R-CHILD-SHELL, R-ALLOW-EXPIRE, R-NEW-AGENT, plus `_render_generic`; `render_sections(alert, line_no=,
  state_dir=)`; `action_lines(alert)` shared with the menu; `format_detail`/`page_detail` take `line_no`.
- `src/sentinel/store.py`: `find_alert(alert_id) -> (1-based line, Alert) | None`, read under `_locked()`.
- `src/sentinel/action.py`: `sentinel-action <id> open [--logs]` with `open_target`, `open_argv`,
  `launch_detached`; `get_alert` and `cmd_investigate` now use `find_alert`; `cmd_menu` prints `action_lines`.
- Tests: `tests/test_investigate.py` (+428 lines), `tests/test_action.py` (+104), `tests/test_store.py` (+60).

## Fact-check
| Claim | Verdict | Evidence |
|-------|---------|----------|
| 1 flat field dump, `page_detail` pipes to `$PAGER`, `redact_mapping` drops token/auth/body keys | CONFIRMED | pre-change `format_detail`; the redaction tests still pass unchanged |
| 2 `iter_alerts` has no line lookup; `_locked()` exists and must wrap a new reader | CONFIRMED | `find_alert` added and it takes `_locked()`; 210 green |
| 3 alert field inventory, including the W3-02 additions | CONFIRMED | every renderer reads only listed fields; per-rule fixtures pass |
| 4 `cmd_menu` prints the cheat sheet, `cmd_investigate` pages then marks investigated | CONFIRMED | menu now prints `action_lines`; the investigated-status test still passes |
| 5 `uwsm-app -- nautilus --select <uri>` / `--new-window <dir>`, detached | UNVERIFIED live | argv is asserted in tests; no file manager is launched by design, so the desktop behaviour is an Owner-run check |
| 6 journal mirror not merged; the `journalctl` lines are harmless when empty | CONFIRMED | the queries print; they return nothing until W3-07 |

## Acceptance
```
.venv/bin/pytest -q                                  -> 210 passed in 1.46s
<packet one-liner>| grep -c -E "^(What fired|...)$"  -> 6
```

## Deviations
- `cmd_open` returns exit code 1 when `nautilus` is absent, after printing the path. The packet only said
  "prints the path"; a non-zero code is what lets a caller tell "opened" from "here is the path instead".
- The report and the commits are the Chief's, for the client reason described above.

## Review findings, fixed in 743dee3
- `_render_child_shell` called `int()` directly on `evidence["child_pids"]` and the parent pid, so a
  hand-edited or truncated alert row raised instead of rendering. Pids now go through `_as_pid()` and a
  non-list `child_pids` is ignored. This is one of the Test 3 red-team cases, so it would have failed there.
- `_SAMPLER_MAX_S = 5` mirrors `daemon.SAMPLER_MAX` so the CLI need not import the daemon's ctypes binding.
  A test now pins the two together, so the Limits line cannot quote a stale window.

## Not done
- Live desktop check of `sentinel-action <id> open` on the Owner's machine (opens nautilus; Owner-run).

## Asks
- ASK-1: `format_detail` still prints the raw `evidence: {...}` line in the header block and then renders the
  same facts, better, in the Evidence section. The packet asked to keep the header, so it was kept; propose
  dropping that one line in UX-02b now that Evidence supersedes it.
- ASK-2: until UX-02b lands `evidence.schema = 2`, *every* alert — including one raised seconds ago — carries
  the Limits line "recorded before evidence v2". Correct by the packet, but it reads oddly on the live
  machine, so UX-02b should follow closely.

## Self-review
- reviewer (Chief): the whole diff was read. Argv arrays only, `shlex.quote` on every alert-derived token,
  `redact_mapping` on every rendered value, absolute-path check before `Path.as_uri()`, no file bodies, no
  network, no new dependencies. Section order and the citation shape match the packet.
- auditor (Chief): 210 tests green; the acceptance one-liner prints 6; the rendered R-BYPASS sample shows
  correct flag index, citations, quoted `/tmp/a b`, and the log locations.
