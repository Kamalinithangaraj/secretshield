
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from secretshield import api, storage


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    database = tmp_path / "test_verification.db"
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


def make_request(username="owner", user_id=101):
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/findings/1/verify",
        "headers": [],
        "session": {
            "github_user_id": user_id,
            "github_username": username,
        },
    }
    return Request(scope)


def create_original_finding(fingerprint="dummy-fingerprint"):
    storage.save_findings(
        "owner/repo", 101, [make_finding(fingerprint)]
    )
    return storage.get_findings(101)[0]["id"]


def test_verification_marks_finding_fixed_when_secret_is_absent(
    test_db, monkeypatch
):
    finding_id = create_original_finding()

    monkeypatch.setattr(
        api,
        "scan_github_repository",
        lambda username, repository: ([], []),
    )

    result = api.verify_finding(finding_id, make_request())

    assert result["status"] == "fixed"
    assert result["verification_status"] == "verified"
    assert storage.get_findings(101)[0]["status"] == "fixed"


def test_verification_keeps_finding_open_when_secret_remains(
    test_db, monkeypatch
):
    finding_id = create_original_finding()

    monkeypatch.setattr(
        api,
        "scan_github_repository",
        lambda username, repository: (
            [make_finding()],
            [],
        ),
    )

    result = api.verify_finding(finding_id, make_request())

    assert result["status"] == "open"
    assert result["verification_status"] == "still_detected"
    assert storage.get_findings(101)[0]["status"] == "open"


def test_incomplete_scan_never_marks_finding_fixed(
    test_db, monkeypatch
):
    finding_id = create_original_finding()

    monkeypatch.setattr(
        api,
        "scan_github_repository",
        lambda username, repository: (
            [],
            ["Some files could not be scanned."],
        ),
    )

    result = api.verify_finding(finding_id, make_request())

    assert result["status"] == "open"
    assert result["verification_status"] == "inconclusive"
    assert storage.get_findings(101)[0]["status"] == "open"


def test_scan_error_never_marks_finding_fixed(
    test_db, monkeypatch
):
    finding_id = create_original_finding()

    scan_error = SimpleNamespace(
        secret_type="scan_error",
        fingerprint=None,
        file="config.py",
        line=0,
        risk="LOW",
        masked_value="[content hidden]",
        message="Could not scan file",
    )

    monkeypatch.setattr(
        api,
        "scan_github_repository",
        lambda username, repository: ([scan_error], []),
    )

    result = api.verify_finding(finding_id, make_request())

    assert result["status"] == "open"
    assert result["verification_status"] == "inconclusive"


def test_missing_fingerprint_requires_manual_review(
    test_db, monkeypatch
):
    finding_id = create_original_finding(fingerprint=None)

    def unexpected_scan(username, repository):
        pytest.fail("Scanner should not run without a fingerprint")

    monkeypatch.setattr(
        api, "scan_github_repository", unexpected_scan
    )

    result = api.verify_finding(finding_id, make_request())

    assert result["status"] == "open"
    assert result["verification_status"] == "manual_review_required"


def test_repository_owner_must_match_github_session(
    test_db, monkeypatch
):
    storage.save_findings(
        "another-owner/repo", 101, [make_finding()]
    )
    finding_id = storage.get_findings(101)[0]["id"]

    with pytest.raises(HTTPException) as error:
        api.verify_finding(finding_id, make_request())

    assert error.value.status_code == 403

def test_manual_fixed_status_is_rejected(test_db):
    finding_id = create_original_finding()

    with pytest.raises(HTTPException) as error:
        api.change_finding_status(
            finding_id,
            api.StatusUpdate(status="fixed"),
            make_request(),
        )

    assert error.value.status_code == 422
    assert storage.get_findings(101)[0]["status"] == "open"

def test_other_github_user_cannot_verify_finding(
    test_db, monkeypatch
):
    finding_id = create_original_finding()

    def unexpected_scan(username, repository):
        pytest.fail("Another user must not be allowed to scan this finding")

    monkeypatch.setattr(
        api, "scan_github_repository", unexpected_scan
    )

    with pytest.raises(HTTPException) as error:
        api.verify_finding(
            finding_id,
            make_request(username="other-user", user_id=202),
        )

    assert error.value.status_code == 404
    assert storage.get_findings(101)[0]["status"] == "open"
    assert storage.get_findings(202) == []
