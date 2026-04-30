#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: ~/proj/scitex-code/src/scitex/security/__init__.py

"""scitex-security — GitHub security-alert utilities (standalone).

Usage:
    from scitex_security import check_github_alerts

    alerts = check_github_alerts()
    if alerts:
        print(f"Found {len(alerts)} security alerts!")
"""

from __future__ import annotations

try:
    from importlib.metadata import version as _v, PackageNotFoundError
    try:
        __version__ = _v("scitex-security")
    except PackageNotFoundError:
        __version__ = "0.0.0+local"
    del _v, PackageNotFoundError
except ImportError:  # pragma: no cover — only on ancient Pythons
    __version__ = "0.0.0+local"
from .github import (
    GitHubSecurityError,
    check_github_alerts,
    format_alerts_report,
    get_latest_alerts_file,
    save_alerts_to_file,
)

__all__ = [
    "__version__",
    "check_github_alerts",
    "save_alerts_to_file",
    "get_latest_alerts_file",
    "format_alerts_report",
    "GitHubSecurityError",
]
