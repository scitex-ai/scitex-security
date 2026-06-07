#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/cli.py

"""Hard-error redirect — ``scitex-security`` was renamed to ``scitex-audit github``.

Per ADR-0001 (scitex-dev #139) §"Locked decisions" #1, the legacy
``scitex-security`` console script is preserved in this deprecated
release ONLY as a hard-error redirect per CLI-deprecation skill 11
§5 — NOT as a silent working alias. Soft warnings let stale scripts
persist indefinitely; the hard error forces the fix in one iteration.

Exit code: 2. No subcommand on this surface accepts ``--ignore`` /
``-W ignore`` — the only way forward is to update the caller.
"""

from __future__ import annotations

import sys


_REDIRECT_MESSAGE = (
    "error: `scitex-security` was absorbed into scitex-audit "
    "(ADR-0001, scitex-dev #139).\n"
    "Re-run with: scitex-audit github\n"
    "Migration: pip install scitex-audit>=0.2.0 and use\n"
    "  `scitex-audit github [--repo OWNER/NAME] [--save]`\n"
    "for the equivalent of the old `scitex-security check` / `show-latest`.\n"
)


def main() -> int:
    """Print the redirect and exit 2."""
    sys.stderr.write(_REDIRECT_MESSAGE)
    sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    main()


# EOF
