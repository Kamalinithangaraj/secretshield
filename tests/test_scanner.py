from secretshield.scanner import scan_text, scan_path
from secretshield.remediation import remediation_for


def test_detects_fake_github_token_without_exposing_full_value():
    fake = "ghp_" + "A" * 30
    findings = scan_text(f'token = "{fake}"', "app.py")
    assert findings
    assert findings[0].secret_type == "github_token"
    assert fake not in findings[0].masked_value
    assert fake not in str(findings[0].to_dict())
    assert findings[0].risk == "high"


def test_detects_password_assignment():
    findings = scan_text('password = "fake-password-12345"', "settings.py")
    assert any(f.secret_type == "generic_password_assignment" for f in findings)


def test_detects_database_url_and_masks_credentials():
    fake = "postgres://demo_user:dummy-password-123@localhost:5432/demo"
    findings = scan_text(f'DATABASE_URL = "{fake}"', "config.py")
    assert any(f.secret_type == "database_url" for f in findings)
    assert fake not in str(findings)
    assert "dummy-password-123" not in str(findings)


def test_ignores_documented_database_url_placeholder():
    findings = scan_text("DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/demo", ".env.example")
    assert not any(f.secret_type == "database_url" for f in findings)


def test_detects_private_key_header():
    findings = scan_text("-----BEGIN OPENSSH PRIVATE KEY-----", "id_ed25519")
    assert len(findings) == 1
    assert findings[0].secret_type == "private_key"
    assert findings[0].masked_value == "[content hidden]"


def test_sensitive_env_file_is_flagged(tmp_path):
    (tmp_path / ".env").write_text("DEMO_MODE=true", encoding="utf-8")
    findings = scan_path(tmp_path)
    assert any(f.secret_type == "sensitive_file" for f in findings)


def test_env_example_is_not_flagged_as_sensitive(tmp_path):
    (tmp_path / ".env.example").write_text("API_KEY=replace-me", encoding="utf-8")
    findings = scan_path(tmp_path)
    assert not any(f.secret_type == "sensitive_file" for f in findings)


def test_ignores_git_and_dependency_directories(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config.py").write_text('password="dummy-password-123"', encoding="utf-8")
    findings = scan_path(tmp_path)
    assert findings == []


def test_remediation_has_revoke_first_warning_and_github_steps():
    guidance = remediation_for("github_token")
    assert "Revoke" in guidance["type_specific_steps"][0]
    assert "Revoke the old credential first" in guidance["critical_reminder"]


def test_missing_path_raises(tmp_path):
    try:
        scan_path(tmp_path / "does-not-exist")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")


def test_remediation_returns_independent_step_lists():
    first = remediation_for("github_token")
    second = remediation_for("github_token")

    first["common_steps"].append("temporary test")

    assert "temporary test" not in second["common_steps"]


def test_unknown_secret_type_has_fallback_guidance():
    guidance = remediation_for("unknown_secret")

    assert guidance["type_specific_steps"]
    assert "Rotate" in str(guidance["type_specific_steps"])


def test_remediation_does_not_execute_actions():
    guidance = remediation_for("github_token")

    all_steps = str(guidance).lower()

    assert "automatically revoke" not in all_steps
    assert "automatically delete" not in all_steps


def test_sensitive_file_guidance_rotates_all_secrets():
    guidance = remediation_for("sensitive_file")

    assert "all of them" in str(guidance["type_specific_steps"]).lower()
