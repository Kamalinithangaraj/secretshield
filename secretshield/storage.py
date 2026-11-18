

"""Persistent storage for SecretShield scan findings."""

import sqlite3
from pathlib import Path
from contextlib import contextmanager

DATABASE_PATH = Path(__file__).resolve().parent.parent / "secretshield.db"


@contextmanager
def get_connection():
    """Create and safely close a database connection."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    """Create or safely migrate the findings table."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                file TEXT NOT NULL,
                line INTEGER NOT NULL,
                secret_type TEXT NOT NULL,
                risk TEXT NOT NULL,
                masked_value TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                github_user_id INTEGER,
                fingerprint TEXT
            )
            """
        )

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()
        }


        if "fingerprint" not in columns:
            connection.execute(
               "ALTER TABLE findings ADD COLUMN fingerprint TEXT"
        )
        if "verification_status" not in columns:
            connection.execute(
                """
                ALTER TABLE findings
                ADD COLUMN verification_status TEXT
                NOT NULL DEFAULT 'not_requested'
                """
            )

        if "verified_at" not in columns:
            connection.execute(
                "ALTER TABLE findings ADD COLUMN verified_at TEXT"
            )

        if "verification_message" not in columns:
            connection.execute(
                "ALTER TABLE findings ADD COLUMN verification_message TEXT"
            )

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_findings_identity
            ON findings (
                github_user_id,
                repository,
                file,
                line,
                secret_type,
                masked_value
            )
            """
        )



def save_findings(
    repository: str,
    github_user_id: int,
    findings: list,
) -> None:
    """Save findings without duplicates or resetting fixed status."""
    with get_connection() as connection:
        for finding in findings:
            connection.execute(
                """
                INSERT INTO findings (
                    repository, file, line, secret_type,
                    risk, masked_value, message, github_user_id,
                    fingerprint
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    github_user_id,
                    repository,
                    file,
                    line,
                    secret_type,
                    masked_value
                )
                DO UPDATE SET
                    risk = excluded.risk,
                    message = excluded.message,
                    fingerprint = COALESCE(
                        excluded.fingerprint,
                        findings.fingerprint
                    )
                """,
                (
                    repository,
                    finding.file,
                    finding.line,
                    finding.secret_type,
                    finding.risk,
                    finding.masked_value,
                    finding.message,
                    github_user_id,
                    finding.fingerprint,
                ),
            )


def get_findings(
    github_user_id: int,
    repository: str | None = None,
) -> list[dict]:
    """Retrieve only findings belonging to the specified account."""
    with get_connection() as connection:
        if repository:
            rows = connection.execute(
                """
                SELECT id, repository, file, line, secret_type,
                risk, masked_value, message, status,
                created_at, github_user_id, verification_status,
verified_at, verification_message
                FROM findings
                WHERE github_user_id = ? AND repository = ?
                ORDER BY created_at DESC
                """,
                (github_user_id, repository),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT id, repository, file, line, secret_type,
                risk, masked_value, message, status,
                created_at, github_user_id, verification_status,
verified_at, verification_message
FROM findings
                WHERE github_user_id = ?
                ORDER BY created_at DESC
                """,
                (github_user_id,),
            ).fetchall()

    return [dict(row) for row in rows]


def update_finding_status(
    finding_id: int,
    github_user_id: int,
    status: str,
) -> bool:
    """Update a finding only if it belongs to the specified account."""
    if status not in {"open", "fixed"}:
        raise ValueError("Status must be 'open' or 'fixed'.")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE findings
            SET status = ?
            WHERE id = ? AND github_user_id = ?
            """,
            (status, finding_id, github_user_id),
        )

    return cursor.rowcount > 0

def get_finding_for_verification(
    finding_id: int,
    github_user_id: int,
) -> dict | None:
    """Retrieve internal verification data for an owned finding."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, repository, secret_type, fingerprint,
                   status, verification_status
            FROM findings
            WHERE id = ? AND github_user_id = ?
            """,
            (finding_id, github_user_id),
        ).fetchone()

    return dict(row) if row else None


def record_verification_result(
    finding_id: int,
    github_user_id: int,
    verification_status: str,
    message: str,
) -> bool:
    """Record verification without exposing internal fingerprints."""
    allowed = {
        "verified",
        "still_detected",
        "inconclusive",
        "manual_review_required",
    }

    if verification_status not in allowed:
        raise ValueError("Invalid verification status.")

    is_verified = verification_status == "verified"

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE findings
            SET status = ?,
                verification_status = ?,
                verified_at = CASE
                    WHEN ? = 1 THEN CURRENT_TIMESTAMP
                    ELSE NULL
                END,
                verification_message = ?
            WHERE id = ? AND github_user_id = ?
            """,
            (
                "fixed" if is_verified else "open",
                verification_status,
                int(is_verified),
                message,
                finding_id,
                github_user_id,
            ),
        )

    return cursor.rowcount > 0
