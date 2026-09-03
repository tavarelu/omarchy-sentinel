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
    parser = argparse.ArgumentParser(prog="sentinel-action")
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
