# SecretShield

**GitHub Secret Protection and Security Monitoring Tool**

SecretShield is a security tool that helps developers detect exposed credentials, prevent secrets from entering Git commits, and monitor authorized GitHub repositories through a web dashboard.

It uses a shared scanning engine for local Git protection and online repository scanning.

## Features

### 1. Shared Secret Scanning Engine

Detects:
- API keys and access tokens
- Password assignments
- Database connection URLs and credentials
- GitHub, GitLab and Slack tokens
- AWS access keys
- Google and Stripe API keys
- JWTs
- Private-key material
- Sensitive files such as `.env` files and private-key files

Findings include the affected file, line, secret type and risk level.

Secret values are masked. Complete secret values are not displayed in findings.

SecretShield combines its custom detection rules with Gitleaks for additional detection coverage.

### 2. Local Git Pre-commit Protection

SecretShield automatically scans staged changes before every Git commit.

**Install:**

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

**During a commit:**
- Safe commits are allowed.
- Commits containing detected secrets are blocked.
- Findings identify the file, line, type and risk.
- Secret values are masked in the output.
- Existing Git hooks are not overwritten.

**Uninstall:**

```powershell
secretshield uninstall-hook
```

The uninstaller removes only hooks managed by SecretShield.

### 3. GitHub Repository Monitoring

- Connects using GitHub OAuth and GitHub App authentication.
- Lists repositories authorized through the GitHub App installation.
- Allows users to select and initiate repository scans from the dashboard.
- Scans only repositories the connected account is authorized to access.
- Supports separate user accounts and isolated findings.

### 4. Security Dashboard

The dashboard provides:
- Repository selection and scanning.
- Security findings with file, line, type, risk and masked value.
- Open and fixed finding status.
- Finding verification through subsequent repository scans.
- Type-specific remediation instructions.
- Security finding summaries.

A finding is treated as fixed after verification confirms that the original finding is no longer present. Merely removing a finding from view does not revoke the exposed credential.

### 5. Remediation Guidance

SecretShield provides common and type-specific remediation instructions.

Examples include:
- Revoking exposed GitHub, GitLab and Slack tokens.
- Rotating AWS access keys.
- Replacing database credentials.
- Rotating Google and Stripe API keys.
- Invalidating affected JWTs.
- Replacing exposed private-key pairs.
- Replacing real `.env` files with safe example files.

Remediation instructions are advisory. SecretShield does not automatically revoke credentials, delete files or rewrite Git history.

## Technology Stack

- Python 3.13
- FastAPI
- GitHub OAuth and GitHub Apps
- SQLite for local storage
- PostgreSQL for deployed persistent storage
- Neon PostgreSQL
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

Install the project and development dependencies:

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

Gitleaks must also be installed and available on the system PATH for the additional scanning engine.

## Run the Dashboard Locally

1. Copy `.env.example` to `.env`.
2. Configure the required GitHub OAuth and GitHub App settings using your own credentials.
3. Configure the GitHub App private-key path securely.
4. Start the application:

```powershell
uvicorn secretshield.api:app --reload
```

Open:

- Dashboard: http://127.0.0.1:8000
- Health check: http://127.0.0.1:8000/health

Configure the GitHub OAuth callback URL to match `GITHUB_REDIRECT_URI`.

Never commit `.env` files, private keys or actual credentials.

## Live Deployment

The deployed dashboard is available at:

**https://secretshield-huva.onrender.com**

The application is hosted on Render and uses Neon PostgreSQL for persistent database storage.

The deployment includes Gitleaks as an additional scanning engine.

Note: The free Render instance may spin down after inactivity, which can cause a delay on the first request.

## Remediation Approach

When a secret is detected:

1. Treat the credential as compromised.
2. Revoke or disable the old credential first.
3. Create a replacement with the minimum required permissions.
4. Store the replacement in environment variables or an approved secret manager.
5. Review service activity, audit logs and billing for suspicious usage.
6. Remove the exposed value from source code and ensure real `.env` files are ignored by Git.
7. Review Git history cleanup separately. Never rewrite history without explicit approval and coordination.

Marking a finding as fixed is a verification and tracking workflow. It does not automatically revoke credentials or perform remediation actions.

## Security Practices

- Use dummy credentials for tests and demonstrations.
- Scan only repositories you own or are authorized to inspect.
- Never commit `.env` files or private keys.
- Never display or log complete secret values.
- Keep GitHub credentials in environment variables or secure deployment settings.
- Use HTTPS and a strong session secret in production.
- Keep the GitHub App permissions limited to what the application needs.
- Never automatically rewrite Git history or delete user files.

## Tests

Run the complete test suite:

```powershell
python -m pytest -q
```

**Latest verified local result: 104 passed, 1 skipped.**

The test suite covers scanning rules, sensitive-file detection, secret masking, remediation guidance, Git hooks, GitHub integration, dashboard behavior and storage workflows.

Three dependency/framework deprecation warnings were reported during the latest run. There were no test failures.

## Limitations and Future Improvements

- Repository scans are initiated manually from the dashboard.
- Automatic push-triggered scanning is not currently included.
- Email notifications are not currently included.
- SecretShield provides remediation guidance but does not automatically revoke credentials.
- Git history rewriting requires separate manual approval and coordination.

## Project Status

The following components have been implemented and tested:

- Shared secret-scanning engine.
- Sensitive-file and private-key detection.
- Local Git pre-commit protection.
- GitHub OAuth and GitHub App integration.
- Authorized GitHub repository scanning.
- Security dashboard and findings management.
- Secret masking and risk classification.
- Type-specific remediation guidance.
- Finding verification workflow.
- SQLite and PostgreSQL storage support.
- Live Render deployment with Neon PostgreSQL persistence.

SecretShield is deployed and has passed its latest complete local test suite with **104 passing tests and 1 skipped test**.
