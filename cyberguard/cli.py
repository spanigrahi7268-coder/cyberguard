"""
cli.py
Command-line interface for CyberGuard.
"""

import argparse
import getpass
import sys
import json

from cyberguard.strength import analyze_password
from cyberguard.breach_check import check_password_breach


def print_report(password: str, do_breach_check: bool, as_json: bool):
    report = analyze_password(password)

    breach_result = None
    if do_breach_check:
        breach_result = check_password_breach(password)
        report["breach_check"] = breach_result

    if as_json:
        print(json.dumps(report, indent=2))
        return

    print("\n===== CyberGuard Password Report =====")
    print(f"Length          : {report['password_length']}")
    print(f"Entropy (bits)  : {report['entropy_bits']}")
    print(f"Strength        : {report['strength_label']}")
    print(f"Rules Passed    : {report['rules_passed']}")
    print("\n--- Rule Breakdown ---")
    for rule, passed in report["rule_details"].items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {rule}")

    if do_breach_check:
        print("\n--- Breach Check (Have I Been Pwned) ---")
        if breach_result["error"]:
            print(f"  Could not check (network error): {breach_result['error']}")
        elif breach_result["breached"]:
            print(f"  WARNING: This password was found in {breach_result['times_seen']:,} known breaches!")
            print("  Do NOT use this password. Change it immediately.")
        else:
            print("  Good news: This password was not found in known breaches.")
    print("========================================\n")


def main():
    parser = argparse.ArgumentParser(
        prog="cyberguard",
        description="CyberGuard - Password Strength & Data Breach Checker"
    )
    parser.add_argument(
        "-p", "--password",
        help="Password to check (omit this flag to be prompted securely instead)"
    )
    parser.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip the online Have I Been Pwned breach check (offline mode only)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON"
    )

    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Enter password to analyze (input hidden): ")

    if not password:
        print("Error: No password provided.", file=sys.stderr)
        sys.exit(1)

    print_report(password, do_breach_check=not args.no_breach_check, as_json=args.json)


if __name__ == "__main__":
    main()
