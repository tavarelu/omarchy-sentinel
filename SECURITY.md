# Security policy

Sentinel watches AI coding agents on the user's own machine. Its threat model is an agent, or
anything running as the same user, trying to widen its own access or silence the watchdog. That
makes Sentinel itself a target, so reports are taken seriously and handled privately first.

## Reporting

Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a
vulnerability"). Please do not open a public issue for something exploitable. Include the version
or commit, what an attacker needs (same uid, a writable state dir, a crafted alert row...), and how
to reproduce. You will get an acknowledgement, and a fix or a documented limitation before any
public discussion.

## What Sentinel promises

- Runs as the user, never as root.
- Records metadata only: paths, hashes, pids, redacted argv. Never file bodies, credentials or
  transcripts. Auth-classified files are watched but never opened.
- The daemon makes no network calls.
- State files are 0600 inside 0700 directories.
- Tampering with Sentinel's own state, prefs or pause raises a sticky alert that ignores pause and
  notification preferences. Evidence, not prevention: a same-uid attacker can still stop the
  daemon, but not quietly.

A report showing any of these is false is in scope even if you do not have an exploit.

## Supported versions

The latest release on `main`. Older tags receive no fixes.
