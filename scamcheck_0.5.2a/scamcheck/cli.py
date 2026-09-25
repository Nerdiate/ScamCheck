"""Command-line entry point.

Usage:
    python -m scamcheck email path/to/email.eml
    python -m scamcheck email path/to/email.eml --json
    python -m scamcheck email path/to/email.eml --no-whois   # skip network WHOIS lookup

    python -m scamcheck domain example.com
    python -m scamcheck domain example.com --json
"""

import argparse
import json
import sys

from .emcc import analyze_domain_config
from .models import Severity
from .scoring import analyze_file

_SEVERITY_ICON = {
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED] ",
    Severity.LOW: "[LOW] ",
    Severity.INFO: "[INFO]",
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="scamcheck",
        description="ScamCheck: analyze a suspicious email, or check a domain's email-authentication configuration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    email_parser = subparsers.add_parser("email", help="Analyze a .eml file for phishing/scam signals")
    email_parser.add_argument("eml_file", help="Path to a .eml (raw email) file")
    email_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a text report")
    email_parser.add_argument("--no-whois", action="store_true", help="Skip the WHOIS domain-age lookup (faster, no network call)")

    domain_parser = subparsers.add_parser("domain", help="Check a domain's SPF/DKIM/DMARC/MX configuration (EMCC)")
    domain_parser.add_argument("domain", help="Domain name to check, e.g. example.com")
    domain_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a text report")

    args = parser.parse_args(argv)

    if args.command == "email":
        return _run_email(args)
    return _run_domain(args)


def _run_email(args) -> int:
    try:
        report = analyze_file(args.eml_file, skip_whois=args.no_whois)
    except FileNotFoundError:
        print(f"error: file not found: {args.eml_file}", file=sys.stderr)
        return 1
    except Exception as exc:  # keep the CLI usable even on unexpected parse errors
        print(f"error: could not analyze {args.eml_file}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    _print_email_report(report, args.eml_file)
    return 0


def _run_domain(args) -> int:
    try:
        report = analyze_domain_config(args.domain)
    except Exception as exc:
        print(f"error: could not analyze {args.domain}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    _print_domain_report(report)
    return 0


def _print_email_report(report, filename) -> None:
    bar_filled = int(report.score / 5)
    bar = "#" * bar_filled + "-" * (20 - bar_filled)

    print("=" * 60)
    print(f"ScamCheck report: {filename}")
    print("=" * 60)
    print(f"Suspicion score: {report.score}/100  [{bar}]")
    print(f"Risk level:      {report.risk_level}")
    print()
    print(report.summary_line)
    if report.limited_headers:
        print()
        print(
            "NOTE: this message has no Received/Authentication-Results/Return-Path headers, "
            "which usually means only the visible body was provided rather than the full "
            '"show original" source. Header, authentication, and domain checks were skipped -- '
            "this score reflects link and language analysis only and likely understates risk."
        )
    print()

    _print_findings(report.findings)


def _print_domain_report(report) -> None:
    bar_filled = int(report.score / 5)
    bar = "#" * bar_filled + "-" * (20 - bar_filled)

    print("=" * 60)
    print(f"EMCC report: {report.domain}")
    print("=" * 60)
    print(f"Spoofing exposure: {report.score}/100  [{bar}]")
    print(f"Assessment:        {report.risk_level}")
    print()
    print(report.summary_line)
    print()

    _print_findings(report.findings)


def _print_findings(findings) -> None:
    concerning = [f for f in findings if f.weight > 0]
    reassuring = [f for f in findings if f.weight < 0]
    neutral = [f for f in findings if f.weight == 0]

    if concerning:
        print("-" * 60)
        print("Findings (most concerning first):")
        print("-" * 60)
        for f in concerning:
            print(f"{_SEVERITY_ICON[f.severity]} {f.summary}")
            print(f"        Evidence: {f.evidence}")
            if f.advice:
                print(f"        What to do: {f.advice}")
            print()

    if reassuring:
        print("-" * 60)
        print("Positive signals:")
        print("-" * 60)
        for f in reassuring:
            print(f"{_SEVERITY_ICON[f.severity]} {f.summary}")
            print(f"        {f.evidence}")
            print()

    if neutral:
        print("-" * 60)
        print("Other notes:")
        print("-" * 60)
        for f in neutral:
            print(f"{_SEVERITY_ICON[f.severity]} {f.summary}")
            print(f"        {f.evidence}")
            print()


if __name__ == "__main__":
    sys.exit(main())
