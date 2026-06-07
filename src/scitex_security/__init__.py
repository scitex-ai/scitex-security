#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/__init__.py

"""DEPRECATED — scitex-security has been absorbed into scitex-audit.

Per ADR-0001 (ywatanabe1989/scitex-dev#139, Accepted 2026-06-07), the
GitHub-alerts logic this package previously owned now lives in
``scitex_audit.github``. This package is a deprecated thin re-export
shim for the 0.1.x public surface so existing scripts keep working
through one transition release; it will be yanked from PyPI in the
W3 release wave once ``scitex-dev ecosystem reconcile-versions``
confirms zero downstream pins.

Migration:

* ``from scitex_security import X`` → ``from scitex_audit.github import X``
* ``scitex-security <subcmd>`` (CLI) → ``scitex-audit github`` (the
  legacy script now hard-errors with a redirect, per CLI-deprecation
  skill 11 §5).

Importing this module emits a ``DeprecationWarning`` once per process.
The same-wave consumer migration rule in ADR-0001 §"Locked decisions"
applies to in-tree callers; this shim exists ONLY for external PyPI
users we don't control.
"""

from __future__ import annotations

import warnings as _warnings

_warnings.warn(
    "scitex-security has been absorbed into scitex-audit per ADR-0001 "
    "(scitex-dev #139). Install scitex-audit>=0.2.0 and migrate imports "
    "to `from scitex_audit.github import ...`. This package will be "
    "yanked from PyPI in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

try:
    from importlib.metadata import PackageNotFoundError as _PNFE
    from importlib.metadata import version as _v

    try:
        __version__ = _v("scitex-security")
    except _PNFE:
        __version__ = "0.0.0+local"
    del _v, _PNFE
except ImportError:  # pragma: no cover — only on ancient Pythons
    __version__ = "0.0.0+local"

from .github import (  # noqa: E402 — DeprecationWarning emitted before re-export
    GitHubSecurityError,
    check_github_alerts,
    format_alerts_report,
    get_latest_alerts_file,
    save_alerts_to_file,
)

__all__ = [
    "__version__",
    "GitHubSecurityError",
    "check_github_alerts",
    "format_alerts_report",
    "get_latest_alerts_file",
    "save_alerts_to_file",
]


# EOF
