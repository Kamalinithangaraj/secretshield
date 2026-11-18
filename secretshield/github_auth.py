
"""GitHub App authentication for SecretShield."""

import os
import time
from pathlib import Path

import httpx
import jwt
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def generate_app_jwt() -> str:
    """Generate a short-lived JWT for GitHub App authentication."""

    app_id = os.getenv("GITHUB_APP_ID")
    private_key_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")

    if not app_id or not private_key_path:
        raise RuntimeError("GitHub App ID or private key path is missing.")

    key_path = PROJECT_ROOT / private_key_path

    if not key_path.is_file():
        raise RuntimeError("GitHub App private key file was not found.")

    private_key = key_path.read_text(encoding="utf-8")

    now = int(time.time())

    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": app_id,
    }

    return jwt.encode(payload, private_key, algorithm="RS256")


def verify_app_authentication() -> dict:
    """Verify the GitHub App credentials without exposing the JWT."""

    app_jwt = generate_app_jwt()

    response = httpx.get(
        "https://api.github.com/app",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15.0,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"GitHub App authentication failed (HTTP {response.status_code})."
        )

    app_data = response.json()

    return {
        "authenticated": True,
        "app_name": app_data.get("name"),
        "app_id": app_data.get("id"),
    }
def get_installation_for_account(account_login: str) -> dict:
    """Find this GitHub App's installation on a specific account."""

    app_jwt = generate_app_jwt()

    response = httpx.get(
        "https://api.github.com/app/installations",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params={"per_page": 100},
        timeout=15.0,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Could not retrieve GitHub installations "
            f"(HTTP {response.status_code})."
        )

    for installation in response.json():
        account = installation.get("account") or {}

        if account.get("login", "").lower() == account_login.lower():
            return {
                "installation_id": installation["id"],
                "account_login": account.get("login"),
            }

    raise RuntimeError(
        f"No SecretShield installation found for {account_login}."
    )


def create_installation_access_token(
    installation_id: int,
    repository_names: list[str] | None = None,
) -> str:
    """Create a short-lived installation token."""

    app_jwt = generate_app_jwt()

    payload = {}

    if repository_names:
        payload["repositories"] = repository_names

    response = httpx.post(
        f"https://api.github.com/app/installations/"
        f"{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json=payload,
        timeout=15.0,
    )

    if response.status_code != 201:
        raise RuntimeError(
            f"Could not create installation access token "
            f"(HTTP {response.status_code})."
        )

    token = response.json().get("token")

    if not token:
        raise RuntimeError("GitHub did not return an installation token.")

    return token


def list_installation_repositories(access_token: str) -> list[dict]:
    """List repositories accessible to an installation token."""

    response = httpx.get(
        "https://api.github.com/installation/repositories",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params={"per_page": 100},
        timeout=15.0,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Could not list installed repositories "
            f"(HTTP {response.status_code})."
        )

    return [
        {
            "name": repo["name"],
            "full_name": repo["full_name"],
            "private": repo["private"],
            "default_branch": repo.get("default_branch"),
        }
        for repo in response.json().get("repositories", [])
    ]
