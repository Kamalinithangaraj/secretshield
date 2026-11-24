from secretshield.remediation import TYPE_STEPS, remediation_for


def test_all_custom_secret_types_have_remediation():
    expected_types = {
        "aws_access_key",
        "github_token",
        "gitlab_token",
        "slack_token",
        "stripe_secret_key",
        "database_url",
        "generic_password_assignment",
        "generic_api_key_assignment",
        "google_api_key",
        "jwt",
        "sensitive_file",
        "private_key",
    }

    assert expected_types.issubset(TYPE_STEPS.keys())

    for secret_type in expected_types:
        result = remediation_for(secret_type)
        assert result["type_specific_steps"]
        assert result["critical_reminder"]


def test_stripe_remediation_is_provider_specific():
    result = remediation_for("stripe_secret_key")
    guidance = " ".join(result["type_specific_steps"]).lower()

    assert "stripe dashboard" in guidance
    assert "revoke" in guidance
    assert "billing" in guidance


def test_gitleaks_findings_receive_specific_fallback():
    result = remediation_for("gitleaks_some_new_rule")
    guidance = " ".join(result["type_specific_steps"]).lower()

    assert "credential type" in guidance
    assert "issuing provider" in guidance
    assert "revoke" in guidance
    assert "audit logs" in guidance


def test_common_remediation_prioritizes_revocation():
    result = remediation_for("github_token")
    steps = result["common_steps"]

    revoke_index = next(
        i for i, step in enumerate(steps)
        if "revoke or disable" in step.lower()
    )
    remove_index = next(
        i for i, step in enumerate(steps)
        if "remove the exposed value" in step.lower()
    )

    assert revoke_index < remove_index
