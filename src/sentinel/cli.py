from __future__ import annotations

import argparse
from pathlib import Path

from sentinel.scout import scout, write_watchlist


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    parser.parse_args(argv)
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
