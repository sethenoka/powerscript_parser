from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .discovery import collect_default_sources, collect_sources
from .parsers import parse_sources
from .timeutils import parse_timezone
from .writers import resolve_output_path, write_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="powerscript-parser",
        description=(
            "Parse PowerShell transcripts and PSReadLine ConsoleHost_history.txt "
            "into forensic-friendly output."
        ),
    )
    parser.add_argument(
        "-d",
        "--directory",
        action="append",
        type=Path,
        default=[],
        help="Recursive directory or zip input. May be supplied multiple times.",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        type=Path,
        default=[],
        help="Single transcript or ConsoleHost_history.txt input file. May be supplied multiple times.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file or directory. Defaults to powerscript_parser_<ISO_TIMESTAMP>.<ext> in the current directory.",
    )
    parser.add_argument(
        "--format",
        choices=("l2tcsv", "csv", "json", "xml"),
        default="csv",
        help="Output format. Default: csv.",
    )
    parser.add_argument(
        "-a",
        "--artifact",
        choices=("transcripts", "history", "all"),
        default="all",
        help="Artifact type to parse. Default: all.",
    )
    parser.add_argument(
        "--input-timezone",
        default="UTC",
        help=(
            "Timezone for transcript timestamps without offsets. Accepts UTC, "
            "+/-HH:MM, or an IANA timezone. Default: UTC."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        parse_timezone(args.input_timezone)
        if args.directory or args.file:
            sources = collect_sources(args.directory, args.file, args.artifact)
        else:
            sources = collect_default_sources(args.artifact)
        events = parse_sources(sources, args.artifact, args.input_timezone)
        output_path = resolve_output_path(args.output, args.format)
        write_events(events, output_path, args.format)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"powerscript-parser: error: {exc}\n")

    print(f"Wrote {len(events)} events to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
