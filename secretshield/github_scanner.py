
"""Safely fetch and scan files from authorized GitHub repositories."""

import base64
import binascii
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from .combined_scanner import scan_project
from .github_auth import (
    create_installation_access_token,
    get_installation_for_account,
    list_installation_repositories,
)


GITHUB_API = "https://api.github.com"

MAX_FILES = 1000
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_TOTAL_SIZE = 50 * 1024 * 1024  # 50 MB


def get_authorized_repository(
    github_username: str,
    repository_name: str,
) -> tuple[dict, str]:
    """Verify repository access and return its details and scoped token."""

    installation = get_installation_for_account(github_username)

    # Create a token restricted to the requested repository.
    access_token = create_installation_access_token(
        installation["installation_id"],
        [repository_name],
    )

    repositories = list_installation_repositories(access_token)

    expected_full_name = f"{github_username}/{repository_name}".casefold()

    for repository in repositories:
        if repository["full_name"].casefold() == expected_full_name:
            return repository, access_token

    raise RuntimeError(
        "The GitHub App is not authorized to access this repository."
    )

def get_repository_tree(
    access_token: str,
    owner: str,
    repository_name: str,
    default_branch: str,
) -> list[dict]:
    """Retrieve the complete file tree for the repository's default branch."""

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    branch_url = (
        f"{GITHUB_API}/repos/{owner}/{repository_name}"
        f"/branches/{quote(default_branch, safe='')}"
    )

    branch_response = httpx.get(
        branch_url,
        headers=headers,
        timeout=20.0,
    )

    if branch_response.status_code != 200:
        raise RuntimeError(
            f"Could not retrieve repository branch "
            f"(HTTP {branch_response.status_code})."
        )

    commit_sha = branch_response.json()["commit"]["sha"]

    tree_response = httpx.get(
        f"{GITHUB_API}/repos/{owner}/{repository_name}"
        f"/git/trees/{commit_sha}",
        headers=headers,
        params={"recursive": "1"},
        timeout=30.0,
    )

    if tree_response.status_code != 200:
        raise RuntimeError(
            f"Could not retrieve repository file tree "
            f"(HTTP {tree_response.status_code})."
        )

    tree_data = tree_response.json()

    if tree_data.get("truncated"):
        raise RuntimeError(
            "Repository file tree is too large to scan completely."
        )

    entries = tree_data.get("tree", [])

    if len(entries) > MAX_FILES:
        raise RuntimeError(
            f"Repository exceeds the {MAX_FILES}-file scan limit."
        )

    return entries

def download_repository_file(
    access_token: str,
    owner: str,
    repository_name: str,
    entry: dict,
    destination: Path,
) -> int:
    """Download one safe repository file and return its byte size."""

    if entry.get("type") != "blob":
        return 0

    if entry.get("mode") not in {"100644", "100755"}:
        return 0

    file_size = entry.get("size", 0)

    if not isinstance(file_size, int) or file_size < 0:
        raise RuntimeError("GitHub returned an invalid file size.")

    if file_size > MAX_FILE_SIZE:
        return 0

    relative_path = PurePosixPath(entry.get("path", ""))

    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or ".." in relative_path.parts
        or "\\" in relative_path.as_posix()
    ):
        raise RuntimeError("Repository contains an unsafe file path.")

    response = httpx.get(
        f"{GITHUB_API}/repos/{owner}/{repository_name}"
        f"/git/blobs/{entry['sha']}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=20.0,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Could not download repository file "
            f"(HTTP {response.status_code})."
        )

    try:
        encoded_content = response.json()["content"]

        # GitHub may include line breaks in Base64 content.
        encoded_content = "".join(encoded_content.split())

        content = base64.b64decode(
            encoded_content,
            validate=True,
        )
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise RuntimeError("GitHub returned invalid file content.") from None

    if len(content) != file_size or len(content) > MAX_FILE_SIZE:
        raise RuntimeError("Downloaded file size did not match GitHub metadata.")

    destination.mkdir(parents=True, exist_ok=True)
    target = destination.joinpath(*relative_path.parts)

    if not target.resolve().is_relative_to(destination.resolve()):
        raise RuntimeError("Repository file path escapes the scan directory.")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)

    return len(content)

def scan_github_repository(
    github_username: str,
    repository_name: str,
) -> tuple[list, list[str]]:
    """Download and scan an authorized GitHub repository."""

    repository, access_token = get_authorized_repository(
        github_username,
        repository_name,
    )

    owner = github_username
    default_branch = repository.get("default_branch")

    if not default_branch:
        raise RuntimeError("Repository has no default branch.")

    entries = get_repository_tree(
        access_token,
        owner,
        repository_name,
        default_branch,
    )

    warnings = []
    total_size = 0

    with tempfile.TemporaryDirectory(prefix="secretshield-") as temp_dir:
        scan_directory = Path(temp_dir)

        for entry in entries:
            if entry.get("type") != "blob":
                continue

            if entry.get("mode") not in {"100644", "100755"}:
                continue

            if entry.get("size", 0) > MAX_FILE_SIZE:
                warnings.append(
                    f"Skipped oversized file: {entry.get('path', 'unknown')}"
                )
                continue

            if total_size + entry.get("size", 0) > MAX_TOTAL_SIZE:
                raise RuntimeError(
                    "Repository exceeds the 50 MB download limit."
                )

            downloaded_size = download_repository_file(
                access_token,
                owner,
                repository_name,
                entry,
                scan_directory,
            )

            total_size += downloaded_size

        findings, scanner_warnings = scan_project(scan_directory)
        warnings.extend(scanner_warnings)

    return findings, warnings
