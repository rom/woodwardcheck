#!/usr/bin/env python3
"""
Command-line interface for WoodwardCheck.

Provides a comprehensive CLI for running security audits on Woodward EasyGen controllers.
"""

import argparse
import sys
from typing import List, Optional

from . import __version__
from .engine import AuditEngine
from .utils.config import Config
from .utils.constants import (
    CheckCategory,
    Protocol,
    Severity,
    SCAN_PROFILES,
)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="woodwardcheck",
        description="Security Audit Tool for Woodward EasyGen Controllers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
      Run default audit on target

  %(prog)s 192.168.1.100 --profile quick-scan
      Run quick scan profile

  %(prog)s 192.168.1.100 --category auth,net --format html -o report.html
      Run auth and network checks, output HTML report

  %(prog)s 192.168.1.100 --checks AUTH-001,NET-001 --verbose
      Run specific checks with verbose output

  %(prog)s 192.168.1.100 --min-severity high --format json
      Run only high+ severity checks, output JSON

  %(prog)s --list-checks
      List all available security checks

  %(prog)s --list-profiles
      List available scan profiles

For more information, see: https://github.com/woodwardcheck/woodwardcheck
        """,
    )

    # Target argument
    parser.add_argument(
        "target",
        nargs="?",
        help="Target host IP address or hostname",
    )

    # Connection options
    conn_group = parser.add_argument_group("Connection Options")
    conn_group.add_argument(
        "-p", "--port",
        type=int,
        default=502,
        help="Target port (default: 502 for Modbus)",
    )
    conn_group.add_argument(
        "--protocol",
        choices=["modbus-tcp", "http", "https", "snmp"],
        default="modbus-tcp",
        help="Communication protocol (default: modbus-tcp)",
    )
    conn_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Connection timeout in seconds (default: 30)",
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication Options")
    auth_group.add_argument(
        "-u", "--username",
        help="Username for authentication",
    )
    auth_group.add_argument(
        "-P", "--password",
        help="Password for authentication",
    )
    auth_group.add_argument(
        "--password-file",
        help="File containing password",
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--profile",
        choices=list(SCAN_PROFILES.keys()),
        help="Use predefined scan profile",
    )
    scan_group.add_argument(
        "-c", "--category",
        help="Check categories to run (comma-separated: auth,net,cfg,fw,proto,crypto)",
    )
    scan_group.add_argument(
        "--checks",
        help="Specific check IDs to run (comma-separated)",
    )
    scan_group.add_argument(
        "--exclude",
        help="Check IDs to exclude (comma-separated)",
    )
    scan_group.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity level to report",
    )
    scan_group.add_argument(
        "--safe-mode",
        action="store_true",
        default=True,
        help="Only run safe, read-only checks (default: enabled)",
    )
    scan_group.add_argument(
        "--no-safe-mode",
        action="store_true",
        help="Disable safe mode (allows potentially disruptive checks)",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-f", "--format",
        choices=["text", "html", "json", "markdown", "rtf"],
        default="text",
        help="Output format (default: text)",
    )
    output_group.add_argument(
        "-o", "--output",
        help="Output file path (prints to stdout if not specified)",
    )
    output_group.add_argument(
        "--no-evidence",
        action="store_true",
        help="Exclude evidence from report",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (minimal output)",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config",
        help="Path to configuration file (YAML)",
    )
    config_group.add_argument(
        "--log-file",
        help="Path to log file",
    )
    config_group.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Log level (default: info)",
    )

    # Information options
    info_group = parser.add_argument_group("Information")
    info_group.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available security checks",
    )
    info_group.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles",
    )
    info_group.add_argument(
        "--list-categories",
        action="store_true",
        help="List check categories",
    )
    info_group.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def list_checks(config: Config) -> None:
    """List all available security checks."""
    from .engine import AuditEngine

    # Create a minimal config for listing
    config.target.host = "127.0.0.1"

    engine = AuditEngine(config)
    checks = engine.get_available_checks()

    print("\nAvailable Security Checks")
    print("=" * 60)

    for module_name, module_checks in sorted(checks.items()):
        print(f"\n{module_name.upper()} Module")
        print("-" * 40)

        for check in sorted(module_checks, key=lambda x: x["id"]):
            safe_indicator = " [SAFE]" if check["safe_mode"] else ""
            print(f"  {check['id']:12} [{check['severity']:8}] {check['name']}{safe_indicator}")
            if check["description"]:
                print(f"               {check['description'][:50]}...")

    print("\n" + "=" * 60)
    print(f"Total: {sum(len(c) for c in checks.values())} checks")

    engine.cleanup()


def list_profiles() -> None:
    """List available scan profiles."""
    print("\nAvailable Scan Profiles")
    print("=" * 60)

    for name, profile in SCAN_PROFILES.items():
        print(f"\n{name}")
        print("-" * 40)
        print(f"  Description: {profile['description']}")
        print(f"  Categories:  {', '.join(c.name for c in profile['categories'])}")
        print(f"  Min Severity: {profile['min_severity'].name}")
        print(f"  Timeout:     {profile['timeout']}s")

    print("\n" + "=" * 60)


def list_categories() -> None:
    """List check categories."""
    print("\nCheck Categories")
    print("=" * 60)

    for category in CheckCategory:
        print(f"  {category.name:10} - {category.value}")

    print("\n" + "=" * 60)


def run_audit(args: argparse.Namespace, config: Config) -> int:
    """Run the security audit."""
    # Apply CLI arguments to config
    config.apply_cli_args(args)

    # Handle safe mode
    if args.no_safe_mode:
        config.scan.safe_mode = False
        print("WARNING: Safe mode disabled. Potentially disruptive checks may be run.")

    # Validate configuration
    errors = config.validate()
    if errors:
        print("Configuration errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    # Create engine and run audit
    engine = AuditEngine(config)

    try:
        # Determine filters
        categories = None
        if args.category:
            categories = [CheckCategory[c.upper()] for c in args.category.split(",")]

        min_severity = None
        if args.min_severity:
            min_severity = Severity.from_string(args.min_severity)

        check_ids = None
        if args.checks:
            check_ids = args.checks.split(",")

        exclude_checks = None
        if args.exclude:
            exclude_checks = args.exclude.split(",")

        # Run the audit
        engine.run_audit(
            check_ids=check_ids,
            categories=categories,
            min_severity=min_severity,
            exclude_checks=exclude_checks,
        )

        # Generate report
        include_evidence = not args.no_evidence

        if args.output:
            output_path = engine.generate_report(args.format, args.output)
            print(f"\nReport saved to: {output_path}")
        else:
            report = engine.generate_report(args.format)
            print(report)

        # Return exit code based on findings
        findings = engine.get_findings()
        critical_high = sum(
            1 for f in findings
            if f.result.value == "FAIL" and f.severity in [Severity.CRITICAL, Severity.HIGH]
        )

        if critical_high > 0:
            return 2  # Critical/High findings
        elif any(f.result.value == "FAIL" for f in findings):
            return 1  # Other findings
        return 0

    finally:
        engine.cleanup()


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    # Handle information commands
    if args.list_profiles:
        list_profiles()
        return 0

    if args.list_categories:
        list_categories()
        return 0

    # Load configuration
    config = Config()
    if args.config:
        try:
            config = Config.from_file(args.config)
        except Exception as e:
            print(f"Error loading config file: {e}", file=sys.stderr)
            return 1

    # Handle list-checks (needs engine)
    if args.list_checks:
        list_checks(config)
        return 0

    # Require target for actual audits
    if not args.target:
        parser.print_help()
        print("\nError: target is required for running audits", file=sys.stderr)
        return 1

    config.target.host = args.target

    return run_audit(args, config)


if __name__ == "__main__":
    sys.exit(main())
