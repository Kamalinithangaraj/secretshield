

import subprocess

from secretshield.git_hook import scan_staged_files, main
from secretshield.scanner import _finding


def git(repo, *args):
    """Run a Git command inside a temporary test repository."""
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def setup_repo(tmp_path, monkeypatch):
    """Create an isolated Git repository for a test."""
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "SecretShield Test")
    git(tmp_path, "config", "user.email", "test@example.com")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def stage_file(repo, filename, content):
    """Create a file and stage its content."""
    file_path = repo / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    git(repo, "add", "--", filename)
    return file_path


def test_blocks_staged_password(tmp_path, monkeypatch):
    repo = setup_repo(tmp_path, monkeypatch)
    fake = "SuperFakePassword123456"

    stage_file(repo, "app.py", f'password = "{fake}"')

    findings = scan_staged_files()

    assert any(
        finding.secret_type == "generic_password_assignment"
        for finding in findings
    )
    assert fake not in str(findings)


def test_allows_safe_staged_file(tmp_path, monkeypatch):
    repo = setup_repo(tmp_path, monkeypatch)

    stage_file(repo, "app.py", 'message = "Hello SecretShield"')

    assert scan_staged_files() == []


def test_ignores_secret_only_in_unstaged_changes(tmp_path, monkeypatch):
    repo = setup_repo(tmp_path, monkeypatch)

    file_path = stage_file(
        repo, "app.py", 'message = "Safe staged content"'
    )

    file_path.write_text(
        "pass" + 'word = "UnstagedFakePassword12345"',
        encoding="utf-8",
    )

    assert scan_staged_files() == []


def test_detects_secret_in_staged_content_even_if_working_copy_is_safe(
    tmp_path, monkeypatch
):
    repo = setup_repo(tmp_path, monkeypatch)

    file_path = stage_file(
        repo,
        "app.py",
        "pass" + 'word = "StagedFakePassword12345"',
    )

    file_path.write_text(
        'message = "Safe working copy"',
        encoding="utf-8",
    )

    findings = scan_staged_files()

    assert any(
        finding.secret_type == "generic_password_assignment"
        for finding in findings
    )


def test_blocks_staged_env_file(tmp_path, monkeypatch):
    repo = setup_repo(tmp_path, monkeypatch)

    stage_file(repo, ".env", "DEMO_MODE=true")

    findings = scan_staged_files()

    assert any(
        finding.secret_type == "sensitive_file"
        for finding in findings
    )


def test_skips_binary_file(tmp_path, monkeypatch):
    repo = setup_repo(tmp_path, monkeypatch)

    file_path = repo / "sample.bin"
    file_path.write_bytes(b"\x00\xff\x01\x02")
    git(repo, "add", "--", "sample.bin")

    assert scan_staged_files() == []


def test_blocks_safely_when_git_scan_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = main()

    output = capsys.readouterr().out

    assert result == 2
    assert "Git scan failed" in output
    assert "blocked" in output.lower()


def test_blocks_binary_env_file(tmp_path, monkeypatch):
    repo = setup_repo(tmp_path, monkeypatch)

    file_path = repo / ".env"
    file_path.write_bytes(b"\x00\xff\x01\x02")
    git(repo, "add", "--", ".env")

    findings = scan_staged_files()

    assert any(
        finding.secret_type == "sensitive_file"
        for finding in findings
    )


def test_fails_closed_when_staged_file_cannot_be_read(
    tmp_path, monkeypatch
):
    import secretshield.git_hook as git_hook

    repo = setup_repo(tmp_path, monkeypatch)
    stage_file(repo, "app.py", 'message = "Safe content"')

    original_run = subprocess.run

    def fake_run(command, **kwargs):
        if command[0] == "git" and command[1] == "show":
            return subprocess.CompletedProcess(
                command,
                1,
                stdout=b"",
                stderr=b"Simulated Git read failure",
            )

        return original_run(command, **kwargs)

    monkeypatch.setattr(git_hook.subprocess, "run", fake_run)

    try:
        scan_staged_files()
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError(
            "Expected scan to fail when Git cannot read staged content"
        )


# New Gitleaks integration tests


def test_includes_unique_gitleaks_finding(
    tmp_path, monkeypatch, capsys
):
    import secretshield.git_hook as git_hook

    setup_repo(tmp_path, monkeypatch)
    monkeypatch.setattr(git_hook, "scan_staged_files", lambda: [])

    fake = "UniqueFakeGitleaksSecret123456"
    finding = _finding(
        "app.py",
        4,
        "gitleaks_test_rule",
        "high",
        fake,
        "Gitleaks test finding.",
    )

    monkeypatch.setattr(
        git_hook,
        "scan_staged_with_gitleaks",
        lambda: [finding],
    )

    result = main()
    output = capsys.readouterr().out

    assert result == 1
    assert "COMMIT BLOCKED" in output
    assert "gitleaks_test_rule" in output
    assert fake not in output


def test_removes_duplicate_findings_from_both_scanners(
    tmp_path, monkeypatch, capsys
):
    import secretshield.git_hook as git_hook

    setup_repo(tmp_path, monkeypatch)

    fake = "DuplicateFakeSecret123456"

    custom_finding = _finding(
        "app.py",
        4,
        "generic_api_key_assignment",
        "medium",
        fake,
        "Custom scanner finding.",
    )

    gitleaks_finding = _finding(
        "app.py",
        4,
        "gitleaks_test_rule",
        "high",
        fake,
        "Gitleaks finding.",
    )

    monkeypatch.setattr(
        git_hook,
        "scan_staged_files",
        lambda: [custom_finding],
    )
    monkeypatch.setattr(
        git_hook,
        "scan_staged_with_gitleaks",
        lambda: [gitleaks_finding],
    )

    result = main()
    output = capsys.readouterr().out

    assert result == 1
    assert output.count("app.py:4") == 1
    assert fake not in output


def test_blocks_commit_when_gitleaks_fails(
    tmp_path, monkeypatch, capsys
):
    import secretshield.git_hook as git_hook

    setup_repo(tmp_path, monkeypatch)

    monkeypatch.setattr(
        git_hook,
        "scan_staged_files",
        lambda: [],
    )

    def fail_gitleaks():
        raise git_hook.GitleaksError("Simulated scan failure")

    monkeypatch.setattr(
        git_hook,
        "scan_staged_with_gitleaks",
        fail_gitleaks,
    )

    result = main()
    output = capsys.readouterr().out

    assert result == 2
    assert "Gitleaks scan failed" in output
    assert "blocked" in output.lower()


def test_warns_and_continues_when_gitleaks_is_missing(
    tmp_path, monkeypatch, capsys
):
    import secretshield.git_hook as git_hook

    setup_repo(tmp_path, monkeypatch)

    monkeypatch.setattr(
        git_hook,
        "scan_staged_files",
        lambda: [],
    )

    def missing_gitleaks():
        raise git_hook.GitleaksNotFound("Not installed")

    monkeypatch.setattr(
        git_hook,
        "scan_staged_with_gitleaks",
        missing_gitleaks,
    )

    result = main()
    output = capsys.readouterr().out

    assert result == 0
    assert "Gitleaks is unavailable" in output
    assert "No potential secrets found" in output


def test_custom_scanner_still_blocks_when_gitleaks_is_missing(
    tmp_path, monkeypatch, capsys
):
    import secretshield.git_hook as git_hook

    setup_repo(tmp_path, monkeypatch)

    fake = "CustomScannerFakePassword123"

    custom_finding = _finding(
        "app.py",
        2,
        "generic_password_assignment",
        "high",
        fake,
        "Custom scanner finding.",
    )

    monkeypatch.setattr(
        git_hook,
        "scan_staged_files",
        lambda: [custom_finding],
    )

    def missing_gitleaks():
        raise git_hook.GitleaksNotFound("Not installed")

    monkeypatch.setattr(
        git_hook,
        "scan_staged_with_gitleaks",
        missing_gitleaks,
    )

    result = main()
    output = capsys.readouterr().out

    assert result == 1
    assert "Gitleaks is unavailable" in output
    assert "COMMIT BLOCKED" in output
    assert fake not in output
