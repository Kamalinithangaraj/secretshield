"""Shared SecretShield detection engine.

Security invariant: Finding objects contain metadata and masked values only;
raw matched values are never returned, persisted, or logged by this module.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit
import re

SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key",
}
IGNORED_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
PRIVATE_KEY_MARKERS = (
    "-----BEGIN " + "PRIVATE KEY" + "-----",
    "-----BEGIN " + "RSA PRIVATE KEY" + "-----",
    "-----BEGIN " + "EC PRIVATE KEY" + "-----",
    "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----",
    "-----BEGIN " + "DSA PRIVATE KEY" + "-----",
    "-----BEGIN " + "ENCRYPTED PRIVATE KEY" + "-----",
)

# Rules are intentionally readable and conservative. Gitleaks will be added as
# a second detection layer; these rules provide deterministic local coverage.
RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "high"),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9]{10,}-[A-Za-z0-9-]{10,}\b"), "high"),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), "high"),
    ("database_url", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@[^\s]+"), "high"),
    ("generic_password_assignment", re.compile(r'''(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["']?([^\s"'#]{8,})'''), "high"),
    ("generic_api_key_assignment", re.compile(r'''(?i)\b(api[_-]?key|access[_-]?token|secret[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_\-/.+=]{12,})'''), "medium"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
]

@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    secret_type: str
    risk: str
    masked_value: str
    message: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _mask(value: str) -> str:
    """Return a masked hint; short values are completely hidden."""
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:2]}{'*' * min(12, len(value) - 4)}{value[-2:]}"


def _finding(file_name: str, line: int, kind: str, risk: str, value: str, message: str) -> Finding:
    return Finding(file=file_name, line=line, secret_type=kind, risk=risk,
                   masked_value=_mask(value) if value != "[content hidden]" else value,
                   message=message)


def _is_obvious_placeholder(value: str, rule_name: str) -> bool:
    """Avoid flagging clearly documented template credentials as live secrets."""
    if rule_name == "database_url":
        try:
            parsed = urlsplit(value)
            username = (parsed.username or "").lower()
            db_pass = (parsed.password or "").lower()
        except ValueError:
            return False

        placeholders = {
            "user", "username", "password", "your_password",
            "changeme", "change_me", "replace_me",
            "placeholder", "example",
        }
        return (
            username in placeholders
            or db_pass in placeholders
            or username.startswith("your_")
            or db_pass.startswith("your_")
        )

    normalized = value.strip().strip("\"'").lower()

    placeholders = {
        "changeme", "change_me", "replace_me",
        "placeholder", "example", "your_password",
        "your_api_key", "your_token",
    }

    return (
        normalized in placeholders
        or normalized.startswith("your_")
        or normalized.startswith("replace_me")
        or normalized.startswith("placeholder")
    )

def scan_text(text: str, file_name: str = "inline.txt") -> list[Finding]:
    """Scan text content and return metadata-only findings."""
    findings: list[Finding] = []
    seen: set[tuple[int, str, str]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        upper_line = line.upper()
        if any(marker in upper_line for marker in PRIVATE_KEY_MARKERS):
            key = (line_number, "private_key", "[content hidden]")
            if key not in seen:
                seen.add(key)
                findings.append(_finding(file_name, line_number, "private_key", "high",
                    "[content hidden]", "Private key material detected. Revoke/remove the old key and replace it everywhere."))
            continue

        for rule_name, pattern, risk in RULES:
            for match in pattern.finditer(line):
                # Assignment rules capture the actual value in group 2. Other
                # rules capture the whole token/URL, which is masked immediately.
                secret = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                placeholder_value = (
    match.group(0) if rule_name == "database_url" else secret
                )
                if _is_obvious_placeholder(placeholder_value, rule_name):
                    continue
                key = (line_number, rule_name, _mask(secret))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(file_name, line_number, rule_name, risk, secret,
                    "Potential secret detected. If it was uploaded, revoke it before removing it from code."))

    return findings


def _is_sensitive_file(file_path: Path) -> bool:
    name = file_path.name.lower()
    return name in SENSITIVE_FILENAMES or (name.startswith(".env.") and name != ".env.example")


def scan_path(path: str | Path) -> list[Finding]:
    """Scan a local file/directory. Callers must only scan authorized paths."""
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if not target.is_file() and not target.is_dir():
        raise ValueError("Scan target must be a regular file or directory")

    paths = [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file())
    findings: list[Finding] = []

    for file_path in paths:
        if any(part in IGNORED_PARTS for part in file_path.parts):
            continue
        relative_name = str(file_path.relative_to(target)) if target.is_dir() else file_path.name

        if _is_sensitive_file(file_path):
            findings.append(_finding(relative_name, 1, "sensitive_file", "high", "[content hidden]",
                "Sensitive file detected. Treat every credential inside it as exposed; use a fake-value example file instead."))

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            continue
        findings.extend(scan_text(content, relative_name))

    return findings
