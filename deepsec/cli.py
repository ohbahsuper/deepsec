import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .config import ScanConfig
from .reporting import html_report, json_report, write_report
from .scanner import Scanner
from .utils.console import render_terminal
from .utils.validation import validate_target

LEGAL = "DeepSec is intended only for systems you own or are explicitly authorized to test."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deepsec.py", description="Defensive, passive exposure assessment for authorized HTTP targets.")
    parser.add_argument("target", nargs="?", help="Absolute http:// or https:// target")
    parser.add_argument("--version", action="version", version=f"DeepSec {__version__}")
    parser.add_argument("--rate-limit", type=float, default=3.0, help="Maximum requests per second (0.5–10)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (1–60)")
    parser.add_argument("--max-workers", type=int, default=5, help="Maximum worker budget (1–10)")
    parser.add_argument("--format", choices=("terminal", "json", "html"), default="terminal")
    parser.add_argument("--output", type=Path, help="Write the selected report to this file")
    return parser


async def run(args: argparse.Namespace) -> int:
    try:
        target = validate_target(args.target)
        config = ScanConfig(timeout=args.timeout, max_workers=args.max_workers, requests_per_second=args.rate_limit)
    except ValueError as exc:
        Console().print(f"[red]Invalid configuration or target:[/red] {exc}")
        return 2
    findings = await Scanner(target, config).run()
    if args.format == "terminal":
        render_terminal(target, findings)
        if args.output:
            write_report(args.output, json_report(target, findings))
    else:
        content = json_report(target, findings) if args.format == "json" else html_report(target, findings)
        if args.output:
            write_report(args.output, content)
        else:
            print(content)
    return 0


def main() -> None:
    print(LEGAL)
    parser = build_parser()
    args = parser.parse_args()
    if not args.target:
        parser.print_help()
        return
    try:
        raise SystemExit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\nScan interrupted cleanly.", file=sys.stderr)
        raise SystemExit(130) from None
