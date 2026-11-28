"""Correct-shape FAKE secrets for redaction tests (never real credentials).

Built from pieces at import time so this source file itself carries no
literal that a secret scanner (gitleaks, GitHub push protection) would
flag. Not a test module (name does not match ``test_*.py``).
"""

from __future__ import annotations

import os
import shutil
from typing import Dict

from scitex_security._redact._core import SECRET_NAME_RE, find_gitleaks

#: Fine-grained GitHub PAT shape: ``github_pat_`` + 82 word characters.
FAKE_GITHUB_PAT = "github" + "_pat_" + ("A1b2C3d4E5" * 9)[:82]

#: AWS access key id shape: ``AKIA`` + 16 upper-case alphanumerics.
FAKE_AWS_KEY_ID = "AK" + "IA" + "Q7XZ4MPLW2RT6YNB"

_BODY = "".join(chr(65 + (i * 7) % 26) for i in range(64 * 3))

#: PEM private-key block (random-looking letters, not a key).
FAKE_PEM_BLOCK = (
    "-----BEGIN RSA "
    + "PRIVATE KEY-----\n"
    + "\n".join(_BODY[i : i + 64] for i in range(0, len(_BODY), 64))
    + "\n-----END RSA "
    + "PRIVATE KEY-----"
)

#: A credential value of no known format (only exact-value matching finds it).
FAKE_UNFORMATTED_VALUE = "unformatted-live-value-0123456789"

#: Ordinary output that must pass through unchanged.
NORMAL_TEXT = (
    "build succeeded in 3.2s\n"
    "wrote /home/user/my_keyboard_shortcuts.txt\n"
    "MY_COLOR_THEME=dark\n"
    "see ~/.config/app/auth_token_path.conf for details\n"
)

GITLEAKS = find_gitleaks()
GITLEAKS_MISSING_REASON = "gitleaks not installed (PATH or ~/.local/bin)"


def scrubbed_environ(**extra: str) -> Dict[str, str]:
    """Current environment minus every credential-named variable, plus ``extra``."""
    env = {k: v for k, v in os.environ.items() if not SECRET_NAME_RE.search(k)}
    env.update(extra)
    return env


def cli_env(**extra: str) -> Dict[str, "str | None"]:
    """``CliRunner(env=...)`` mapping that unsets real credential vars and sets ``extra``."""
    env: Dict[str, "str | None"] = {
        k: None for k in os.environ if SECRET_NAME_RE.search(k)
    }
    env.update(extra)
    return env


def bash_event(stdout: str, stderr: str = "", tool_name: str = "Bash") -> dict:
    """A Claude Code PostToolUse event for a Bash call."""
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": "whatever"},
        "tool_response": {
            "stdout": stdout,
            "stderr": stderr,
            "interrupted": False,
            "isImage": False,
        },
    }


def has_bash() -> bool:
    """Whether ``/bin/bash`` exists (clean-bash load tests)."""
    return shutil.which("bash") is not None and os.path.exists("/bin/bash")
