# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
from pathlib import Path

from sentinel.scout import scout, write_watchlist


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command")
    daemon_p = sub.add_parser(
        "daemon",
        aliases=["run"],
        help="Run inotify + process sampler loop",
    )
    daemon_p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config.toml (default: XDG config)",
    )
    daemon_p.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Sampler interval in seconds (clamped to 2-5)",
    )
    args = parser.parse_args(argv)
    if args.command in {"daemon", "run"}:
        from sentinel.daemon import load_config, run_forever

        config = load_config(args.config)
        if args.interval is not None:
            config["sampler_interval"] = args.interval
        run_forever(config)
        return 0
    parser.print_help()
    return 0


def scout_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-scout")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Re-scout agent homes and write watchlist.json",
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=None,
        help="Home directory to scout (default: user home)",
    )
    args = parser.parse_args(argv)
    if not args.refresh:
        parser.error("--refresh is required")
    home = args.home if args.home is not None else Path.home()
    result = scout(home)
    out = write_watchlist(result)
    count = len(result.get("paths", []))
    print(f"{count} paths -> {out}")
    return 0


def action_main(argv: list[str] | None = None) -> int:
    from sentinel.action import action_main as _action_main

    return _action_main(argv)


def scan_main(argv: list[str] | None = None) -> int:
    """sentinel-scan <root> [--json] [--timeout N]

    Runs SkillSpector over root in a sandbox, writes a sanitized report under
    state_dir()/scans/<tree_hash>.json, and prints the parsed ScanResult.
    Deferred import: keeps sentinel.scan (which shells out and, if OSV
    lookups are ever enabled, would touch the network) out of every other
    console script's import path, and out of the daemon's entirely -- the
    daemon never imports sentinel.cli at all, let alone sentinel.scan.
    """
    import dataclasses
    import json

    from sentinel.scan import DEFAULT_TIMEOUT_S, ScannerNotInstalled, run_scan

    parser = argparse.ArgumentParser(prog="sentinel-scan")
    parser.add_argument("root", type=Path, help="Directory to scan")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"Scanner timeout in seconds (default: {DEFAULT_TIMEOUT_S:g})",
    )
    args = parser.parse_args(argv)

    try:
        result = run_scan(args.root, timeout=args.timeout)
    except ScannerNotInstalled as exc:
        print(str(exc))
        return 2
    except NotADirectoryError as exc:
        print(f"sentinel-scan: {exc}")
        return 1
    except ValueError as exc:
        print(f"sentinel-scan: {exc}")
        return 1

    if args.json:
        print(json.dumps(dataclasses.asdict(result), sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
