
import argparse

from .scanner import scan_path
from .remediation import remediation_for


def main():
    parser = argparse.ArgumentParser(
        prog="secretshield",
        description="Scan files for potential secrets."
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

    args = parser.parse_args()

    if args.command == "scan":
        findings = scan_path(args.path)

        if not findings:
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


if __name__ == "__main__":
    raise SystemExit(main())
