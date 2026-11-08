


"""Gitleaks integration for SecretShield.

Gitleaks findings are converted into masked SecretShield findings.
Raw secret values must never be printed or logged.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .scanner import Finding, _finding


class GitleaksError(RuntimeError):
    """Raised when Gitleaks cannot complete a scan."""


class GitleaksNotFound(GitleaksError):
    """Raised when the Gitleaks executable is unavailable."""


def _find_gitleaks() -> str:
    """Locate the Gitleaks executable."""
    executable = shutil.which("gitleaks")

    if executable:
        return executable

    if os.name == "nt":
        packages = (
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Microsoft"
            / "WinGet"
            / "Packages"
        )

        if packages.exists():
            for folder in packages.glob("Gitleaks.Gitleaks_*"):
                candidate = folder / "gitleaks.exe"
                if candidate.is_file():
                    return str(candidate)

    raise GitleaksNotFound(
        "Gitleaks is not installed or could not be located."
    )


def _run_gitleaks(command: list[str]) -> list[dict]:
    """Run Gitleaks and safely parse its JSON report."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitleaksError("Gitleaks scan timed out.") from exc
    except OSError as exc:
        raise GitleaksError("Could not start Gitleaks.") from exc

    if result.returncode not in (0, 1):
        raise GitleaksError(
            f"Gitleaks failed with exit code {result.returncode}."
        )

    try:
        records = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise GitleaksError(
            "Gitleaks returned an invalid JSON report."
        ) from exc

    if not isinstance(records, list):
        raise GitleaksError(
            "Gitleaks returned an unexpected report format."
        )

    return [record for record in records if isinstance(record, dict)]


def _convert_records(
    records: list[dict],
    base_path: Path | None = None,
) -> list[Finding]:
    """Convert Gitleaks report records into masked findings."""
    findings: list[Finding] = []

    for record in records:
        raw_file = str(record.get("File") or "unknown")
        report_path = Path(raw_file)

        if base_path is not None:
            try:
                file_name = (
                    report_path.resolve()
                    .relative_to(base_path)
                    .as_posix()
                )
            except (ValueError, OSError):
                file_name = report_path.as_posix()
        else:
            file_name = report_path.as_posix()

        try:
            line = int(record.get("StartLine") or 0)
        except (TypeError, ValueError) as exc:
            raise GitleaksError(
                "Gitleaks returned an invalid line number."
            ) from exc

        rule_id = str(record.get("RuleID") or "gitleaks_finding")
        secret = str(record.get("Secret") or "")

        findings.append(
            _finding(
                file_name,
                line,
                f"gitleaks_{rule_id}",
                "high",
                secret if secret else "[content hidden]",
                "Gitleaks detected a potential secret. "
                "Verify it and revoke it first if exposed.",
            )
        )

    return findings


def scan_with_gitleaks(path: str | Path) -> list[Finding]:
    """Scan a file or directory using Gitleaks."""
    target = Path(path).expanduser().resolve()

    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")

    executable = _find_gitleaks()

    command = [
        executable,
        "dir",
        "--report-format",
        "json",
        "--report-path",
        "-",
        str(target),
    ]

    records = _run_gitleaks(command)
    return _convert_records(records, target)


def scan_staged_with_gitleaks() -> list[Finding]:
    """Scan only Git's staged changes using Gitleaks."""
    executable = _find_gitleaks()

    command = [
        executable,
        "git",
        "--staged",
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]

    records = _run_gitleaks(command)
    return _convert_records(records)
