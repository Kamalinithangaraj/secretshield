
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from secretshield.api import app


client = TestClient(app)


def test_github_login_redirects_to_github():
    response = client.get("/auth/github", follow_redirects=False)

    assert response.status_code == 307

    redirect = urlparse(response.headers["location"])

    assert redirect.hostname == "github.com"
    assert redirect.path == "/login/oauth/authorize"

    params = parse_qs(redirect.query)

    assert params["client_id"]
    assert params["state"]
    assert params["redirect_uri"]


def test_github_callback_rejects_missing_state():
    response = client.get(
        "/auth/github/callback",
        params={"code": "fake-test-code", "state": "wrong-state"},
    )

    assert response.status_code == 400
    assert "Invalid OAuth state" in response.json()["detail"]


def test_github_callback_rejects_missing_code():
    response = client.get(
        "/auth/github/callback",
        params={"state": "some-state"},
    )

    assert response.status_code == 400

def test_github_scan_requires_authentication():
    response = client.post("/github/scan/secretshield-dummy-test")

    assert response.status_code == 401
    assert "connect your GitHub account" in response.json()["detail"]

def test_github_scan_rejects_invalid_repository_name():
    client.cookies.set(
        "session",
        "invalid",
    )

    response = client.post("/github/scan/../another-repo")

    assert response.status_code in {401, 404, 405}
