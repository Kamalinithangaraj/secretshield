
from secretshield.scanner import Finding
from secretshield.gitleaks_engine import GitleaksError
from secretshield.combined_scanner import scan_project


def make_finding(file, line, kind, masked):
    return Finding(
        file=file,
        line=line,
        secret_type=kind,
        risk="high",
        masked_value=masked,
        message="Test finding",
    )


def test_combined_scanner_removes_duplicate_findings(monkeypatch):
    custom = make_finding("app.py", 2, "github_token", "gh************Aa")
    duplicate = make_finding(
        "app.py", 2, "gitleaks_github-pat", "gh************Aa"
    )
    password_finding = make_finding(
        "app.py", 3, "generic_password_assignment", "fa************45"
    )

    monkeypatch.setattr(
        "secretshield.combined_scanner.scan_path",
        lambda path: [custom, password_finding],
    )
    monkeypatch.setattr(
        "secretshield.combined_scanner.scan_with_gitleaks",
        lambda path: [duplicate],
    )

    findings, warnings = scan_project("fake_project")

    assert len(findings) == 2
    assert findings[0].secret_type == "github_token"
    assert findings[1].secret_type == "generic_password_assignment"
    assert warnings == []


def test_combined_scanner_keeps_unique_gitleaks_findings(monkeypatch):
    custom = make_finding("app.py", 2, "github_token", "gh************Aa")
    extra = make_finding("config.py", 5, "gitleaks_custom-rule", "ab********yz")

    monkeypatch.setattr(
        "secretshield.combined_scanner.scan_path",
        lambda path: [custom],
    )
    monkeypatch.setattr(
        "secretshield.combined_scanner.scan_with_gitleaks",
        lambda path: [extra],
    )

    findings, warnings = scan_project("fake_project")

    assert len(findings) == 2
    assert findings[1].file == "config.py"
    assert warnings == []


def test_combined_scanner_continues_if_gitleaks_fails(monkeypatch):
    custom = make_finding("app.py", 3, "generic_password_assignment", "fa********45")

    monkeypatch.setattr(
        "secretshield.combined_scanner.scan_path",
        lambda path: [custom],
    )

    def fail_gitleaks(path):
        raise GitleaksError("Gitleaks unavailable")

    monkeypatch.setattr(
        "secretshield.combined_scanner.scan_with_gitleaks",
        fail_gitleaks,
    )

    findings, warnings = scan_project("fake_project")

    assert len(findings) == 1
    assert findings[0].secret_type == "generic_password_assignment"
    assert len(warnings) == 1
    assert "custom-scanner findings only" in warnings[0]
