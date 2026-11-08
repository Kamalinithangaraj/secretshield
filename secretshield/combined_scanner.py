
"""Combined SecretShield scanner.

Runs the custom scanner and Gitleaks, then removes duplicate findings.
"""

from pathlib import Path

from .scanner import Finding, scan_path
from .gitleaks_engine import GitleaksError, scan_with_gitleaks


def scan_project(
    path: str | Path,
) -> tuple[list[Finding], list[str]]:
    """Run both engines and return findings plus any engine warnings."""

    target = Path(path).expanduser().resolve()

    # The custom scanner is the primary engine.
    findings = scan_path(target)
    warnings: list[str] = []

    # Gitleaks is an additional detection engine.
    try:
        gitleaks_findings = scan_with_gitleaks(target)
    except GitleaksError:
        warnings.append(
            "Gitleaks could not complete. Results contain custom-scanner "
            "findings only."
        )
        return findings, warnings

    # Merge findings without reporting the same secret twice.
    seen = {
        (
            Path(item.file).as_posix().casefold(),
            item.line,
            item.masked_value,
        )
        for item in findings
    }

    for item in gitleaks_findings:
        identity = (
            Path(item.file).as_posix().casefold(),
            item.line,
            item.masked_value,
        )

        if identity not in seen:
            findings.append(item)
            seen.add(identity)

    return findings, warnings
