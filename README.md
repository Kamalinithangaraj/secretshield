# SecretShield

GitHub secret protection and security monitoring tool. SecretShield is being built around one shared Python scanner used by both local commit protection and the online dashboard.

## Current status (Sprint day 1)

Implemented in this foundation increment:
- Local scanning for common GitHub tokens, AWS access-key IDs, password/API-key assignments, database URLs, private-key headers and sensitive filenames.
- Masked findings: the scanner returns file, line, type, risk and a masked hint, never the complete matched value.
- Type-specific remediation guidance, with revocation first and Git-history cleanup explicitly optional.
- CLI entry point (`secretshield scan PATH`).
- FastAPI health endpoint.
- Tests using dummy data only.

Not implemented yet: Gitleaks integration, Git pre-commit installation, GitHub OAuth/repository access, persistent database, web dashboard and deployment. The API intentionally does not expose arbitrary server filesystem scanning.

## Local setup (Windows PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
secretshield scan .\examples\fake_project
```

Run the API locally:

```powershell
uvicorn secretshield.api:app --reload
```

Open `http://127.0.0.1:8000/health`.

## Safety

- Use only fake credentials in tests and demo repositories.
- Scan only repositories you own or are authorized to inspect.
- Never paste real credentials into issues, logs, screenshots or chat.
- Revoking/rotating credentials is a human-approved incident-response action. SecretShield will not revoke credentials, delete files or rewrite Git history automatically.
