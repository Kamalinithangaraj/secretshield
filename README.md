
# SecretShield

**GitHub Secret Protection and Security Monitoring Tool**

SecretShield helps developers detect exposed credentials, prevent secrets from entering Git commits, and monitor authorized GitHub repositories through a web dashboard.

## Features

### 1. Local Secret Scanning
- Detects common API keys, passwords, access tokens, database URLs and private-key headers.
- Identifies sensitive files such as `.env` and private keys.
- Reports file, line, secret type and risk level.
- Masks detected values. Full secrets are never displayed in findings.


###  Git Pre-commit Protection

SecretShield automatically scans staged files before every Git commit and blocks commits containing potential secrets.

**Install the hook:**

1. Install SecretShield in your Python environment:

   ```powershell
   python -m pip install -e .
   ```

2. Navigate to the Git repository you want to protect:

   ```powershell
   cd path\to\your\project
   ```

3. Install the pre-commit hook:

   ```powershell
   secretshield install-hook
   ```

**What happens during a commit?**

- SecretShield scans staged changes before the commit.
- Safe commits are allowed.
- Commits containing potential secrets are blocked.
- Findings show the file, line, type and risk level.
- Secret values are masked in the output.
- Existing Git hooks are never overwritten.

**Uninstall the hook:**

```powershell
secretshield uninstall-hook
```

The uninstaller removes only hooks managed by SecretShield.

### 3. GitHub Repository Monitoring
- Connects through GitHub OAuth and GitHub App authentication.
- Lists repositories authorized for the installed GitHub App.
- Scans selected repositories only after the user initiates a scan.
- Does not require access to unrelated repositories.

### 4. Security Dashboard
- Displays repository scan findings.
- Shows file, line, secret type, risk and masked value.
- Tracks open and fixed findings.
- Allows users to mark findings fixed or reopen them.
- Displays common and secret-specific remediation guidance.

## Technology Stack

- Python 3.13
- FastAPI
- GitHub OAuth and GitHub Apps
- SQLite
- Gitleaks
- HTML, CSS and JavaScript
- Pytest

## Local Setup (Windows PowerShell)

Clone the repository and enter its directory.

Create a virtual environment:

```powershell
py -3.13 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the project:

```powershell
python -m pip install -e ".[dev]"
```

Run the tests:

```powershell
python -m pytest -q
```

Run a local scan:

```powershell
secretshield scan .\examples\fake_project
```

## Run the Dashboard Locally

1. Copy `.env.example` to `.env`.
2. Configure the GitHub OAuth and GitHub App values.
3. Place the GitHub App private key at the configured path.
4. Start the application:

```powershell
uvicorn secretshield.api:app --reload
```

Open:

- Dashboard: http://127.0.0.1:8000
- Health check: http://127.0.0.1:8000/health

Configure the GitHub OAuth callback URL to match `GITHUB_REDIRECT_URI`.
## Remediation Approach

When a secret is detected:

1. Revoke or disable the exposed credential.
2. Create a replacement with the minimum required permissions.
3. Store the replacement in environment variables or an approved secret manager.
4. Review service activity and logs for suspicious usage.
5. Remove the exposed value from source code.
6. Review Git history cleanup separately. Never rewrite history without explicit approval.

Marking a finding as fixed in the dashboard is a tracking action. It does not automatically revoke credentials or verify that the underlying secret has been removed.

## Security Practices

- Use dummy credentials for tests and demonstrations.
- Scan only repositories you own or are authorized to inspect.
- Never commit `.env` files or private keys.
- Never display or log complete secret values.
- Keep GitHub credentials in environment variables or secure deployment settings.
- Use HTTPS and a strong session secret in production.
- SecretShield does not automatically revoke credentials, delete files or rewrite Git history.

## Tests

Run:

```powershell
python -m pytest -q
```

Latest verified local result: **68 passed, 1 skipped**.

## Limitations

- Repository scans are initiated manually from the dashboard.
- Finding status is manually managed.
- GitHub access is limited to repositories authorized through the GitHub App installation.
- Automatic push-triggered scanning and email notifications are not currently included.

## Project Status

The local scanner, Git commit protection, GitHub integration, repository scanning, dashboard, finding management and remediation guidance have been implemented and tested.

Deployment and final end-to-end verification remain part of the project completion work.
