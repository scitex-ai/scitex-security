#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/__init__.py

"""scitex-security — unified security scanning for the SciTeX ecosystem.

As of 0.2.0, scitex-security is the unified package that owns the
multi-tool security-audit orchestrator (bandit / shellcheck / pip-audit)
in addition to its original GitHub-alerts checker (Dependabot, secret
scanning, code scanning). The audit orchestrator was absorbed from
``scitex-audit 0.2.0`` per ADR-0002 (scitex-dev #142); future
``scitex-audit`` releases are deprecated thin re-export shims of this
package.

Usage::

    # Multi-tool security sweep (Python + shell + deps + GitHub):
    from scitex_security import audit

    results = audit(".")
    results = audit(".", checks=["python", "shell"])

    # GitHub alerts directly:
    from scitex_security import check_github_alerts

    alerts = check_github_alerts()
    if alerts:
        print(f"Found {len(alerts)} security alerts!")
"""

from __future__ import annotations

import logging as _logging

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _v

    try:
        __version__ = _v("scitex-security")
    except PackageNotFoundError:
        __version__ = "0.0.0+local"
    del _v, PackageNotFoundError
except ImportError:  # pragma: no cover — only on ancient Pythons
    __version__ = "0.0.0+local"

from ._runner import audit
from .github import (
    GitHubSecurityError,
    check_github_alerts,
    format_alerts_report,
    get_latest_alerts_file,
    save_alerts_to_file,
)

# One-shot reverse-migration of ``~/.scitex/audit/github-alerts/`` →
# ``~/.scitex/security/runtime/`` from users who ran scitex-audit 0.2.0
# (the absorbing release that ADR-0001 shipped, before ADR-0002
# reversed the direction). Marker-gated so it only fires once per user.
# Wrapped in try/except — a path-migration glitch must not break
# import. See ADR-0002 §"Locked decisions" for the full design.
try:
    from ._paths import _migrate_legacy_audit_dir as _migrate

    _migrate()
    del _migrate
except Exception:  # pragma: no cover — best-effort migration
    _logging.getLogger(__name__).debug(
        "scitex-security: reverse-migration of ~/.scitex/audit/github-alerts/ "
        "raised; continuing.",
        exc_info=True,
    )

__all__ = [
    "__version__",
    "audit",
    "GitHubSecurityError",
    "check_github_alerts",
    "format_alerts_report",
    "get_latest_alerts_file",
    "save_alerts_to_file",
]


# EOF
