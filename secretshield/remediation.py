
"""Type-specific incident guidance.

These are instructions only. SecretShield never performs
credential revocation, deletion, or Git history rewriting.
"""

COMMON_STEPS = [
    "Treat the exposed credential as compromised.",
    "Revoke or disable the old credential before removing it from code.",
    "Create a replacement and store it in environment variables or an approved secret manager.",
    "Review service logs, sign-in history, audit events and billing for suspicious activity.",
    "Remove the exposed value from source code and ensure real .env files are ignored by Git.",
    "Review Git history cleanup separately. Rewrite history only after explicit approval and coordination with collaborators.",
    "Enable local commit protection and the provider's secret-detection features.",
]
TYPE_STEPS = {
    "github_token": [
        "Revoke the exposed token in GitHub settings.",
        "Create a replacement with only the permissions required.",
        "Review GitHub account activity and audit logs.",
    ],
    "gitlab_token": [
        "Revoke the exposed token in GitLab preferences or project/group settings.",
        "Create a replacement with minimum required scopes and an appropriate expiry.",
        "Review GitLab audit events and recent account activity.",
    ],
    "slack_token": [
        "Revoke or rotate the exposed token through the Slack app or token management settings.",
        "Generate a replacement using only the required scopes.",
        "Review app activity and unexpected messages or API usage.",
    ],
    "google_api_key": [
        "Restrict the exposed Google API key to only the required APIs and applications.",
        "Rotate or replace the exposed key using Google Cloud Console.",
        "Review Google Cloud API usage, billing and audit logs for suspicious activity.",
        "Avoid embedding unrestricted API keys in public client-side code.",
    ],
    "stripe_secret_key": [
        "Revoke the exposed secret key in the Stripe Dashboard.",
        "Create a replacement secret key and update the application securely.",
        "Review Stripe API activity, recent events, customers, refunds and billing for suspicious activity.",
        "Check whether the exposed key had live-mode access and restrict permissions where supported.",
    ],
    "jwt": [
        "Identify which application issued and validates the exposed JWT.",
        "If the signing key is compromised, rotate it and update all validating services.",
        "Invalidate affected tokens or sessions where supported.",
        "Review token expiry, issuer, audience and signing algorithm configuration.",
        "Review authentication logs for suspicious token usage.",
    ],
    "aws_access_key": [
        "Deactivate the exposed access key in AWS IAM.",
        "Create a replacement for the required IAM identity with least privilege.",
        "Review CloudTrail events and billing for unexpected activity.",
    ],
    "database_url": [
        "Rotate the database user's password or revoke the exposed credential.",
        "Update the application's secure connection configuration.",
        "Review database connection logs and unexpected data changes.",
        "Restrict network access and account privileges to what is necessary.",
    ],
    "generic_password_assignment": [
        "Change the password at the service where it is used.",
        "Revoke suspicious sessions and enable multi-factor authentication where supported.",
        "Check login history for unauthorized access.",
    ],
    "generic_api_key_assignment": [
        "Revoke the exposed key in the issuing service.",
        "Create a replacement with minimum permissions.",
        "Review API usage, billing and access logs.",
    ],
    "sensitive_file": [
        "Treat every credential in the file as exposed and rotate all of them.",
        "Replace the real file with a safe sample such as .env.example containing dummy values.",
        "Confirm the real file is excluded by .gitignore.",
    ],
    "private_key": [
        "Treat the exposed private key as compromised, even if it is encrypted.",
        "Generate a completely new key pair using an approved secure method.",
        "Remove trust in the old public key or certificate wherever it is used.",
        "Replace the old key across dependent systems and verify access.",
        "Never share or commit the private key or its passphrase.",
    ],
}


def remediation_for(secret_type: str) -> dict[str, list[str] | str]:
    """Return common and type-specific remediation instructions."""

    normalized_type = secret_type.strip().lower()

    if normalized_type.startswith("gitleaks_"):
        type_specific = [
            "Identify the credential type and issuing provider from the Gitleaks rule and affected file.",
            "Revoke or disable the exposed credential with its issuing provider before removing it from code.",
            "Create a replacement with the minimum required permissions and store it securely.",
            "Review the provider's audit logs, usage and billing for suspicious activity.",
            "Remove the exposed value from the affected file and prevent it from being committed again.",
        ]
    else:
        type_specific = TYPE_STEPS.get(
            normalized_type,
            [
                "Identify the service or file owner and determine which credential is exposed.",
                "Rotate the credential using the provider's official instructions after revoking the exposed value.",
                "Review relevant logs for suspicious use.",
            ],
        )
    return {
        "critical_reminder": (
            "Removing a secret from code or Git history does not invalidate it. "
            "Revoke the old credential first."
        ),
        "common_steps": COMMON_STEPS.copy(),
        "type_specific_steps": type_specific.copy(),
    }
