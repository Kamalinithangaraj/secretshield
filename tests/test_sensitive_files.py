import pytest

from secretshield.scanner import scan_path


@pytest.mark.parametrize(
    "filename",
    [
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "server.key",
        "certificate.pem",
        "keystore.p12",
        "keystore.pfx",
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
    ],
)
def test_sensitive_filenames_are_detected_and_masked(tmp_path, filename):
    test_file = tmp_path / filename
    test_file.write_text("harmless dummy test content", encoding="utf-8")

    findings = scan_path(tmp_path)
    matching = [
        finding for finding in findings
        if finding.secret_type == "sensitive_file"
    ]

    assert matching
    assert matching[0].masked_value == "[content hidden]"


def test_env_example_is_not_flagged_as_sensitive(tmp_path):
    test_file = tmp_path / ".env.example"
    test_file.write_text("API_KEY=your_api_key", encoding="utf-8")

    findings = scan_path(tmp_path)

    assert not any(
        finding.secret_type == "sensitive_file"
        for finding in findings
    )
