
"""SecretShield API with GitHub OAuth authorization."""

import os
import secrets
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from . import storage
from .remediation import remediation_for
from .github_scanner import scan_github_repository

from .github_auth import (
    get_installation_for_account,
    create_installation_access_token,
    list_installation_repositories,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

app = FastAPI(title="SecretShield API", version="0.4.0")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv(
        "SECRET_KEY",
        "development-only-change-this-secret",
    ),
    same_site="lax",
    https_only=os.getenv("SECRET_SHIELD_HTTPS") == "1",
)




class StatusUpdate(BaseModel):
    status: str

def get_authenticated_github_user(request: Request) -> int:
    """Return the logged-in GitHub user's ID."""
    github_user_id = request.session.get("github_user_id")

    if not isinstance(github_user_id, int):
        raise HTTPException(
            status_code=401,
            detail="Please connect your GitHub account first.",
        )

    return github_user_id


@app.on_event("startup")
def startup():
    storage.initialize_database()

@app.get("/")
def dashboard():
    return FileResponse(PROJECT_ROOT / "static" / "index.html")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SecretShield",
        "version": "0.4.0",
    }


@app.get("/auth/github")
def github_login(request: Request):
    """Start GitHub OAuth authorization."""

    client_id = os.getenv("GITHUB_CLIENT_ID")
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI")

    if not client_id or not redirect_uri:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth configuration is incomplete.",
        )

    if not os.getenv("SECRET_KEY"):
        raise HTTPException(
            status_code=500,
            detail="OAuth session security is not configured.",
        )

    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    authorization_url = httpx.URL(
        "https://github.com/login/oauth/authorize"
    ).copy_merge_params({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    })

    return RedirectResponse(str(authorization_url))



@app.get("/auth/github/callback")
def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    """Validate GitHub's callback and identify the developer."""

    expected_state = request.session.pop("oauth_state", None)

    if error:
        raise HTTPException(
            status_code=400,
            detail="GitHub authorization was not completed.",
        )

    if (
        not code
        or not state
        or not expected_state
        or not secrets.compare_digest(state, expected_state)
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth state. Please try connecting again.",
        )

    client_id = os.getenv("GITHUB_CLIENT_ID")
    client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI")

    if not all([client_id, client_secret, redirect_uri]):
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth configuration is incomplete.",
        )

    try:
        token_response = httpx.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
            timeout=15.0,
        )

        token_response.raise_for_status()
        token_data = token_response.json()

        access_token = token_data.get("access_token")

        if not access_token:
            raise HTTPException(
                status_code=400,
                detail="GitHub did not issue an access token.",
            )

        user_response = httpx.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15.0,
        )

        user_response.raise_for_status()
        user_data = user_response.json()

    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Could not complete GitHub authorization.",
        )

    github_user_id = user_data.get("id")
    github_username = user_data.get("login")

    if not isinstance(github_user_id, int) or not github_username:
        raise HTTPException(
            status_code=502,
            detail="GitHub returned incomplete account information.",
        )

    request.session["github_user_id"] = github_user_id
    request.session["github_username"] = github_username

    return RedirectResponse(url="/", status_code=303)

@app.get("/github/repositories")
def list_github_repositories(request: Request):
    """List repositories authorized for SecretShield scanning."""

    get_authenticated_github_user(request)

    github_username = request.session.get("github_username")

    if not isinstance(github_username, str) or not github_username:
        raise HTTPException(
            status_code=401,
            detail="Please reconnect your GitHub account.",
        )

    try:
        installation = get_installation_for_account(github_username)

        access_token = create_installation_access_token(
            installation["installation_id"]
        )

        repositories = list_installation_repositories(access_token)

    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from None
    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Could not retrieve GitHub repositories.",
        )

    return {
        "repositories": repositories,
        "count": len(repositories),
    }


@app.post("/github/scan/{repository_name}")
def scan_github_repository_endpoint(
    repository_name: str,
    request: Request,
):
    """Scan an authorized GitHub repository and save its findings."""

    github_user_id = get_authenticated_github_user(request)
    github_username = request.session.get("github_username")

    if not isinstance(github_username, str) or not github_username:
        raise HTTPException(
            status_code=401,
            detail="Please reconnect your GitHub account.",
        )

    if (
        not repository_name
        or "/" in repository_name
        or "\\" in repository_name
        or repository_name in {".", ".."}
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid repository name.",
        )

    try:
        findings, warnings = scan_github_repository(
            github_username,
            repository_name,
        )

        full_name = f"{github_username}/{repository_name}"

        storage.save_findings(
            full_name,
            github_user_id,
            findings,
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from None
    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="GitHub could not complete the repository scan.",
        )

    return {
        "repository": full_name,
        "findings_count": len(findings),
        "findings": [
            {
                "file": finding.file,
                "line": finding.line,
                "secret_type": finding.secret_type,
                "risk": finding.risk,
                "masked_value": finding.masked_value,
                "message": finding.message,
            }
            for finding in findings
        ],
        "warnings": warnings,
        "message": "Repository scan completed.",
    }



@app.post("/findings/{finding_id}/verify")
def verify_finding(finding_id: int, request: Request):
    """Rescan an authorized repository before marking a finding fixed."""

    github_user_id = get_authenticated_github_user(request)
    github_username = request.session.get("github_username")

    if not isinstance(github_username, str) or not github_username:
        raise HTTPException(
            status_code=401,
            detail="Please reconnect your GitHub account.",
        )

    original = storage.get_finding_for_verification(
        finding_id,
        github_user_id,
    )

    if original is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found.",
        )

    repository = original["repository"]
    parts = repository.split("/")

    if (
        len(parts) != 2
        or parts[0].casefold() != github_username.casefold()
        or not parts[1]
    ):
        raise HTTPException(
            status_code=403,
            detail="Finding does not belong to your connected GitHub account.",
        )

    if not original["fingerprint"]:
        storage.record_verification_result(
            finding_id,
            github_user_id,
            "manual_review_required",
            "This finding cannot be automatically verified. Please review it manually.",
        )
        return {
            "id": finding_id,
            "status": "open",
            "verification_status": "manual_review_required",
            "message": "Manual review is required.",
        }

    try:
        findings, warnings = scan_github_repository(
            github_username,
            parts[1],
        )
    except (RuntimeError, httpx.HTTPError):
        storage.record_verification_result(
            finding_id,
            github_user_id,
            "inconclusive",
            "GitHub could not complete the verification scan.",
        )
        return {
            "id": finding_id,
            "status": "open",
            "verification_status": "inconclusive",
            "message": "Verification could not be completed. The finding remains open.",
        }

    scan_errors = [
        finding for finding in findings
        if finding.secret_type == "scan_error"
    ]

    # Save actual detections, but never store scan-error entries as findings.
    storage.save_findings(
        repository,
        github_user_id,
        [
            finding for finding in findings
            if finding.secret_type != "scan_error"
        ],
    )

    if warnings or scan_errors:
        verification_status = "inconclusive"
        message = "The repository scan was incomplete. The finding remains open."

    elif any(
        finding.fingerprint == original["fingerprint"]
        for finding in findings
    ):
        verification_status = "still_detected"
        message = "The original secret is still detected. The finding remains open."

    else:
        verification_status = "verified"
        message = "The original secret was not detected in a complete scan."

    storage.record_verification_result(
        finding_id,
        github_user_id,
        verification_status,
        message,
    )

    return {
        "id": finding_id,
        "status": (
            "fixed" if verification_status == "verified" else "open"
        ),
        "verification_status": verification_status,
        "message": message,
    }


@app.get("/findings")
def list_findings(
    request: Request,
    repository: str | None = None,
):
    github_user_id = get_authenticated_github_user(request)

    return {
        "findings": storage.get_findings(
            github_user_id,
            repository,
        )
    }


@app.patch("/findings/{finding_id}/status")
def change_finding_status(
    finding_id: int,
    update: StatusUpdate,
    request: Request,
):
    github_user_id = get_authenticated_github_user(request)

    if update.status != "open":
        raise HTTPException(
            status_code=422,
            detail="Findings can only be marked fixed through verification.",
)

    updated = storage.update_finding_status(
        finding_id,
        github_user_id,
        update.status,
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Finding not found.",
        )

    return {
        "id": finding_id,
        "status": update.status,
        "message": "Finding status updated.",
    }


@app.get("/remediation/{secret_type}")
def get_remediation(secret_type: str):
    return remediation_for(secret_type)
