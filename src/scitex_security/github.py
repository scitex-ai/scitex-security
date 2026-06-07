#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/github.py

"""Thin re-export shim — implementation lives in ``scitex_audit.github``.

Per ADR-0001 (scitex-dev #139), the GitHub-alerts implementation has
moved to scitex-audit. This module exists only so existing
``from scitex_security.github import X`` imports keep resolving for one
transition release. Use ``scitex_audit.github`` directly in new code.
"""

from __future__ import annotations

from scitex_audit.github import (
    GitHubSecurityError,
    check_gh_auth,
    check_github_alerts,
    format_alerts_report,
    get_code_scanning_alerts,
    get_default_alerts_dir,
    get_dependabot_alerts,
    get_latest_alerts_file,
    get_secret_alerts,
    save_alerts_to_file,
)

__all__ = [
    "GitHubSecurityError",
    "check_gh_auth",
    "check_github_alerts",
    "format_alerts_report",
    "get_code_scanning_alerts",
    "get_default_alerts_dir",
    "get_dependabot_alerts",
    "get_latest_alerts_file",
    "get_secret_alerts",
    "save_alerts_to_file",
]


# EOF
