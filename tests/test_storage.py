from types import SimpleNamespace

import pytest

from secretshield import storage


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    database = tmp_path / "test_secretshield.db"
    monkeypatch.setattr(storage, "DATABASE_PATH", database)
    storage.initialize_database()
    return database


def make_finding(fingerprint="dummy-fingerprint"):
    return SimpleNamespace(
        file="config.py",
        line=5,
        secret_type="generic_password_assignment",
        risk="HIGH",
        masked_value="Du************45",
        message="Potential password detected",
        fingerprint=fingerprint,
    )


def test_fingerprint_is_stored_but_not_returned(test_db):
    storage.save_findings(
        "owner/repo", 101, [make_finding()]
    )

    results = storage.get_findings(101)

    assert len(results) == 1
    assert "fingerprint" not in results[0]

    with storage.get_connection() as connection:
        row = connection.execute(
            "SELECT fingerprint FROM findings"
        ).fetchone()

    assert row["fingerprint"] == "dummy-fingerprint"


def test_rescan_preserves_fingerprint_and_fixed_status(test_db):
    storage.save_findings(
        "owner/repo", 101, [make_finding()]
    )

    finding_id = storage.get_findings(101)[0]["id"]
    assert storage.update_finding_status(finding_id, 101, "fixed")

    storage.save_findings(
        "owner/repo", 101, [make_finding(fingerprint=None)]
    )

    results = storage.get_findings(101)

    assert len(results) == 1
    assert results[0]["status"] == "fixed"

    with storage.get_connection() as connection:
        row = connection.execute(
            "SELECT fingerprint FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()

    assert row["fingerprint"] == "dummy-fingerprint"


def test_findings_are_isolated_by_github_user(test_db):
    storage.save_findings(
        "owner/repo", 101, [make_finding()]
    )

    assert len(storage.get_findings(101)) == 1
    assert storage.get_findings(202) == []

    finding_id = storage.get_findings(101)[0]["id"]

    assert not storage.update_finding_status(
        finding_id, 202, "fixed"
    )
    assert storage.get_findings(101)[0]["status"] == "open"


def test_invalid_status_is_rejected(test_db):
    with pytest.raises(ValueError):
        storage.update_finding_status(1, 101, "verified")

def test_verification_data_is_owner_scoped(test_db):
    storage.save_findings("owner/repo", 101, [make_finding()])
    finding_id = storage.get_findings(101)[0]["id"]
    result = storage.get_finding_for_verification(finding_id, 101)

    assert result["fingerprint"] == "dummy-fingerprint"
    assert storage.get_finding_for_verification(finding_id, 202) is None


def test_only_verified_result_marks_finding_fixed(test_db):
    storage.save_findings("owner/repo", 101, [make_finding()])
    finding_id = storage.get_findings(101)[0]["id"]

    assert storage.record_verification_result(
        finding_id, 101, "still_detected", "Secret remains."
    )
    assert storage.get_findings(101)[0]["status"] == "open"

    assert storage.record_verification_result(
        finding_id, 101, "verified", "Secret no longer detected."
    )
    assert storage.get_findings(101)[0]["status"] == "fixed"


def test_inconclusive_verification_never_marks_fixed(test_db):
    storage.save_findings("owner/repo", 101, [make_finding()])
    finding_id = storage.get_findings(101)[0]["id"]

    assert storage.record_verification_result(
        finding_id, 101, "inconclusive", "Scan was incomplete."
    )
    result = storage.get_findings(101)[0]

    assert result["status"] == "open"
    assert result["verification_status"] == "inconclusive"


def test_invalid_verification_result_is_rejected(test_db):
    with pytest.raises(ValueError):
        storage.record_verification_result(
            1, 101, "fixed", "Invalid."
        )
