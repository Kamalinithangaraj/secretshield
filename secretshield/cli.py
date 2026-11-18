

import argparse

from .combined_scanner import scan_project
from .remediation import remediation_for
from .install_hook import install_hook, uninstall_hook


def main():
    parser = argparse.ArgumentParser(
        prog="secretshield",
        description="Scan files and directories for potential secrets."
    )

    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser(
        "scan",
        help="Scan a file or directory"
    )
    scan_parser.add_argument("path", help="Path to scan")
    scan_parser.add_argument(
        "--guidance",
        action="store_true",
        help="Show type-specific remediation instructions"
    )

    sub.add_parser(
        "install-hook",
        help="Install SecretShield Git pre-commit protection"
    )

    sub.add_parser(
        "uninstall-hook",
        help="Remove the SecretShield Git pre-commit hook"
    )

    args = parser.parse_args()

    if args.command == "install-hook":
        return install_hook()

    if args.command == "uninstall-hook":
        return uninstall_hook()

    if args.command == "scan":
        findings, warnings = scan_project(args.path)

        for warning in warnings:
            print(f"WARNING: {warning}")

        if not findings:
            if warnings:
                print(
                    "SecretShield: scan incomplete; "
                    "no potential secrets found by the available scanner."
                )
                return 2

            print("SecretShield: no potential secrets found.")
            return 0

        print(f"SecretShield: found {len(findings)} potential issue(s):")

        for item in findings:
            print(
                f"\n- [{item.risk.upper()}] "
                f"{item.file}:{item.line} | "
                f"{item.secret_type} | "
                f"{item.masked_value}"
            )

            print(f"  {item.message}")

            if args.guidance:
                guidance = remediation_for(item.secret_type)

                print("\n  IMPORTANT:")
                print(f"  {guidance['critical_reminder']}")

                print("\n  Type-specific remediation:")
                for number, step in enumerate(
                    guidance["type_specific_steps"], start=1
                ):
                    print(f"  {number}. {step}")

                print("\n  General remediation:")
                for number, step in enumerate(
                    guidance["common_steps"], start=1
                ):
                    print(f"  {number}. {step}")

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
