
"""Install and uninstall the SecretShield Git pre-commit hook."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import shlex

HOOK_MARKER = "# SecretShield managed pre-commit hook"


def get_hooks_directory() -> Path:
    """Find the active Git hooks directory."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-path", "hooks"],
        capture_output=True,
        text=True,
        check=True,
    )

    hooks_path = Path(result.stdout.strip())

    if not hooks_path.is_absolute():
        hooks_path = Path.cwd() / hooks_path

    return hooks_path.resolve()


def install_hook() -> int:
    """Install SecretShield in the current Git repository."""
    try:
        hooks_directory = get_hooks_directory()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("SecretShield: current directory is not a Git repository.")
        return 1

    hooks_directory.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_directory / "pre-commit"

    if hook_file.exists():
        existing_content = hook_file.read_text(
            encoding="utf-8",
            errors="replace",
        )

        if HOOK_MARKER in existing_content:
            print("SecretShield pre-commit hook is already installed.")
            return 0

        print(
            f"SecretShield: an existing hook was found at {hook_file}.\n"
            "It was not overwritten. Back it up or configure it manually."
        )
        return 1

    python_executable = Path(sys.executable).as_posix()
    python_command = shlex.quote(python_executable)

    hook_content = (
        "#!/bin/sh\n"
        f"{HOOK_MARKER}\n"
        f"exec {python_command} -m secretshield.git_hook \"$@\"\n"
    )

    hook_file.write_text(hook_content, encoding="utf-8", newline="\n")

    print(f"SecretShield pre-commit hook installed at: {hook_file}")
    return 0


def uninstall_hook() -> int:
    """Remove only a hook managed by SecretShield."""
    try:
        hooks_directory = get_hooks_directory()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("SecretShield: current directory is not a Git repository.")
        return 1

    hook_file = hooks_directory / "pre-commit"

    if not hook_file.exists():
        print("No pre-commit hook is installed.")
        return 0

    existing_content = hook_file.read_text(
        encoding="utf-8",
        errors="replace",
    )

    if HOOK_MARKER not in existing_content:
        print("Existing hook is not managed by SecretShield. It was not removed.")
        return 1

    hook_file.unlink()
    print("SecretShield pre-commit hook removed.")
    return 0
