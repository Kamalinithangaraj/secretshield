
"""Git pre-commit protection for SecretShield."""

from __future__ import annotations

import subprocess
from pathlib import PurePosixPath

from .scanner import scan_text, _finding, _is_sensitive_file
from .gitleaks_engine import (
    GitleaksError,
    GitleaksNotFound,
    scan_staged_with_gitleaks,
)


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


def _merge_findings(custom_findings, gitleaks_findings):
    """Merge findings and remove duplicates."""
    findings = []
    seen = set()

    for finding in custom_findings + gitleaks_findings:
        normalized_file = (
            PurePosixPath(finding.file.replace("\\", "/"))
            .as_posix()
            .casefold()
        )

        identity = (
            normalized_file,
            finding.line,
            finding.masked_value,
        )

        if identity not in seen:
            findings.append(finding)
            seen.add(identity)

    return findings


def main() -> int:
    # Run SecretShield's primary staged scanner.
    try:
        custom_findings = scan_staged_files()
    except (subprocess.CalledProcessError, OSError):
        print("SecretShield: Git scan failed. Commit blocked for safety.")
        return 2

    # Run Gitleaks as an additional staged scanner.
    try:
        gitleaks_findings = scan_staged_with_gitleaks()

    except GitleaksNotFound:
        print(
            "WARNING: Gitleaks is unavailable. "
            "Continuing with the SecretShield custom scanner only."
        )
        gitleaks_findings = []

    except GitleaksError:
        print(
            "SecretShield: Gitleaks scan failed. "
            "Commit blocked for safety."
        )
        return 2

    # Merge results and remove duplicate findings.
    findings = _merge_findings(
        custom_findings,
        gitleaks_findings,
    )

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
