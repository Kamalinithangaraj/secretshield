
from unittest.mock import patch

import pytest

from secretshield.github_scanner import get_authorized_repository
import base64
from unittest.mock import Mock


@patch("secretshield.github_scanner.list_installation_repositories")
@patch("secretshield.github_scanner.create_installation_access_token")
@patch("secretshield.github_scanner.get_installation_for_account")
def test_authorized_repository_is_returned(
    mock_installation,
    mock_token,
    mock_repositories,
):
    mock_installation.return_value = {
        "installation_id": 123,
        "account_login": "Kamalinithangaraj",
    }
    mock_token.return_value = "fake-installation-token"
    mock_repositories.return_value = [
        {
            "name": "secretshield-dummy-test",
            "full_name": "Kamalinithangaraj/secretshield-dummy-test",
            "private": True,
            "default_branch": "main",
        }
    ]

    repository, token = get_authorized_repository(
        "Kamalinithangaraj",
        "secretshield-dummy-test",
    )

    assert repository["name"] == "secretshield-dummy-test"
    assert token == "fake-installation-token"

    mock_token.assert_called_once_with(
        123,
        ["secretshield-dummy-test"],
    )


@patch("secretshield.github_scanner.list_installation_repositories")
@patch("secretshield.github_scanner.create_installation_access_token")
@patch("secretshield.github_scanner.get_installation_for_account")
def test_unauthorized_repository_is_rejected(
    mock_installation,
    mock_token,
    mock_repositories,
):
    mock_installation.return_value = {
        "installation_id": 123,
        "account_login": "Kamalinithangaraj",
    }
    mock_token.return_value = "fake-installation-token"
    mock_repositories.return_value = []

    with pytest.raises(RuntimeError, match="not authorized"):
        get_authorized_repository(
            "Kamalinithangaraj",
            "another-repository",
        )

from secretshield.github_scanner import (
    MAX_FILE_SIZE,
    download_repository_file,
)


def test_symlink_is_skipped(tmp_path):
    entry = {
        "type": "blob",
        "mode": "120000",
        "path": "secret-link",
        "size": 20,
        "sha": "fake-sha",
    }

    result = download_repository_file(
        "fake-token",
        "owner",
        "repo",
        entry,
        tmp_path,
    )

    assert result == 0
    assert not (tmp_path / "secret-link").exists()


def test_oversized_file_is_skipped(tmp_path):
    entry = {
        "type": "blob",
        "mode": "100644",
        "path": "large.bin",
        "size": MAX_FILE_SIZE + 1,
        "sha": "fake-sha",
    }

    result = download_repository_file(
        "fake-token",
        "owner",
        "repo",
        entry,
        tmp_path,
    )

    assert result == 0
    assert not (tmp_path / "large.bin").exists()


def test_path_traversal_is_rejected(tmp_path):
    entry = {
        "type": "blob",
        "mode": "100644",
        "path": "../outside.txt",
        "size": 10,
        "sha": "fake-sha",
    }

    with pytest.raises(RuntimeError, match="unsafe file path"):
        download_repository_file(
            "fake-token",
            "owner",
            "repo",
            entry,
            tmp_path,
        )


def test_non_blob_entry_is_skipped(tmp_path):
    entry = {
        "type": "tree",
        "mode": "040000",
        "path": "src",
        "size": 0,
        "sha": "fake-sha",
    }

    result = download_repository_file(
        "fake-token",
        "owner",
        "repo",
        entry,
        tmp_path,
    )

    assert result == 0

@patch("secretshield.github_scanner.httpx.get")
def test_downloads_and_decodes_repository_file(mock_get, tmp_path):
    content = b"API_KEY = 'fake-test-value'"

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "content": base64.b64encode(content).decode("ascii")
    }
    mock_get.return_value = mock_response

    entry = {
        "type": "blob",
        "mode": "100644",
        "path": "src/config.py",
        "size": len(content),
        "sha": "fake-sha",
    }

    result = download_repository_file(
        "fake-token",
        "owner",
        "repo",
        entry,
        tmp_path,
    )

    saved_file = tmp_path / "src" / "config.py"

    assert result == len(content)
    assert saved_file.read_bytes() == content

@patch("secretshield.github_scanner.httpx.get")
def test_truncated_repository_tree_is_rejected(mock_get):
    branch_response = Mock(status_code=200)
    branch_response.json.return_value = {
        "commit": {"sha": "fake-commit"}
    }

    tree_response = Mock(status_code=200)
    tree_response.json.return_value = {
        "truncated": True,
        "tree": [],
    }

    mock_get.side_effect = [
        branch_response,
        tree_response,
    ]

    from secretshield.github_scanner import get_repository_tree

    with pytest.raises(
        RuntimeError,
        match="too large to scan completely",
    ):
        get_repository_tree(
            "fake-token",
            "owner",
            "repo",
            "main",
        )

@patch("secretshield.github_scanner.httpx.get")
def test_repository_exceeding_file_limit_is_rejected(mock_get):
    from secretshield.github_scanner import (
        MAX_FILES,
        get_repository_tree,
    )

    branch_response = Mock(status_code=200)
    branch_response.json.return_value = {
        "commit": {"sha": "fake-commit"}
    }

    tree_response = Mock(status_code=200)
    tree_response.json.return_value = {
        "truncated": False,
        "tree": [{"type": "blob"}] * (MAX_FILES + 1),
    }

    mock_get.side_effect = [
        branch_response,
        tree_response,
    ]

    with pytest.raises(RuntimeError, match="file scan limit"):
        get_repository_tree(
            "fake-token",
            "owner",
            "repo",
            "main",
        )

@patch("secretshield.github_scanner.httpx.get")
def test_invalid_base64_content_is_rejected(mock_get, tmp_path):
    response = Mock(status_code=200)
    response.json.return_value = {
        "content": "not-valid-base64!!!"
    }
    mock_get.return_value = response

    entry = {
        "type": "blob",
        "mode": "100644",
        "path": "config.py",
        "sha": "fake-sha",
        "size": 10,
    }

    with pytest.raises(RuntimeError, match="invalid file content"):
        download_repository_file(
            "fake-token",
            "owner",
            "repo",
            entry,
            tmp_path,
        )