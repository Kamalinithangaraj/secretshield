
"""Git pre-commit protection for SecretShield."""

from __future__ import annotations

import subprocess
from pathlib import PurePosixPath

from .scanner import scan_text, _finding, _is_sensitive_file


def get_staged_files() -> list[str]:
    """Get added or modified staged files from Git."""
    result = subprocess.run(
        [
            "git", "diff", "--cached",
            "--name-only", "--diff-filter=ACMR", "-z",
        ],
        capture_output=True,
        check=True,
    )

    return [
        path.decode("utf-8", errors="surrogateescape")
        for path in result.stdout.split(b"\0")
        if path
    ]


def scan_staged_files():
    """Scan staged Git content, never the working-tree copy."""
    findings = []

    for file_name in get_staged_files():

        # Check sensitive filenames before reading file contents.
        if _is_sensitive_file(PurePosixPath(file_name)):
            findings.append(
                _finding(
                    file_name,
                    1,
                    "sensitive_file",
                    "high",
                    "[content hidden]",
                    "Sensitive file detected. Do not commit real credentials.",
                )
            )

        # Read the exact staged version from Git's index.
        result = subprocess.run(
            ["git", "show", f":{file_name}"],
            capture_output=True,
        )

        # Fail closed if Git cannot read a staged file.
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                output=result.stdout,
                stderr=result.stderr,
            )

        content_bytes = result.stdout

        # Skip binary or non-UTF-8 file contents.
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue

        findings.extend(scan_text(content, file_name))

    return findings


def main() -> int:
    try:
        findings = scan_staged_files()
    except (subprocess.CalledProcessError, OSError):
        print("SecretShield: Git scan failed. Commit blocked for safety.")
        return 2

    if findings:
        print("\nSecretShield: COMMIT BLOCKED!")
        print(f"Found {len(findings)} potential security issue(s):\n")

        for finding in findings:
            print(
                f"- [{finding.risk.upper()}] "
                f"{finding.file}:{finding.line} | "
                f"{finding.secret_type} | "
                f"{finding.masked_value}"
            )

        print("\nFix the findings and stage the corrected files.")
        return 1

    print("SecretShield: No potential secrets found. Commit allowed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
