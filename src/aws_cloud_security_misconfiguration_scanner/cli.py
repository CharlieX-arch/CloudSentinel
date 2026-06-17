from __future__ import annotations

import argparse
from pathlib import Path

import boto3

from .report import format_summary, write_report
from .scanner import AwsMisconfigurationScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AWS Cloud Security Misconfiguration Scanner")
    parser.add_argument("--region", dest="region", action="append", help="AWS region to scan. Can be repeated.")
    parser.add_argument("--regions", nargs="+", help="One or more AWS regions to scan.")
    parser.add_argument("--all-regions", action="store_true", help="Scan all regions available in the boto3 session.")
    parser.add_argument("--iam-unused-days", type=int, default=90, help="Days since last use before a role is considered unused.")
    parser.add_argument("--output", type=Path, default=Path("report.json"), help="Path to the JSON output report.")
    parser.add_argument("--format", choices=["json", "csv", "html"], default="json", help="Report format.")
    parser.add_argument("--json-only", action="store_true", help="Suppress the text summary and only write JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    session = boto3.Session()
    requested_regions: list[str] | None
    if args.all_regions:
        requested_regions = session.get_available_regions("ec2") or ["us-east-1"]
    else:
        requested_regions = []
        if args.region:
            requested_regions.extend(args.region)
        if args.regions:
            requested_regions.extend(args.regions)
        requested_regions = list(dict.fromkeys(requested_regions)) or None

    scanner = AwsMisconfigurationScanner(
        session=session,
        regions=requested_regions,
        iam_unused_days=args.iam_unused_days,
    )
    report = scanner.scan()
    write_report(report, args.output, format_name=args.format)

    if not args.json_only:
        print(format_summary(report), end="")
        print(f"JSON report written to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
