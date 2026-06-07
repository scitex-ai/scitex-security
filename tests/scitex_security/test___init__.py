#!/usr/bin/env python3
"""Tests for the scitex-security 0.2.0 thin re-export shim (ADR-0001 W1).

Asserts that the 5 absorbed public symbols still resolve via the legacy
``scitex_security.*`` paths (so external consumers don't break in the
transition release) AND that importing the package emits a clear
``DeprecationWarning``. The hard-error CLI redirect is asserted via
subprocess.

PA-307: each test carries the canonical AAA markers each on its own line.
PA-306: no mocks — we exercise the real shim + subprocess.
"""

from __future__ import annotations

import subprocess
import sys
import warnings


def test_check_github_alerts_reachable_via_legacy_path():
    """``from scitex_security import check_github_alerts`` still resolves."""
    # Arrange
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import scitex_security

    # Act
    obj = getattr(scitex_security, "check_github_alerts", None)
    # Assert
    assert callable(obj)


def test_save_alerts_to_file_reachable_via_legacy_path():
    """``from scitex_security import save_alerts_to_file`` still resolves."""
    # Arrange
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import scitex_security

    # Act
    obj = getattr(scitex_security, "save_alerts_to_file", None)
    # Assert
    assert callable(obj)


def test_get_latest_alerts_file_reachable_via_legacy_path():
    """``from scitex_security import get_latest_alerts_file`` still resolves."""
    # Arrange
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import scitex_security

    # Act
    obj = getattr(scitex_security, "get_latest_alerts_file", None)
    # Assert
    assert callable(obj)


def test_format_alerts_report_reachable_via_legacy_path():
    """``from scitex_security import format_alerts_report`` still resolves."""
    # Arrange
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import scitex_security

    # Act
    obj = getattr(scitex_security, "format_alerts_report", None)
    # Assert
    assert callable(obj)


def test_github_security_error_reachable_via_legacy_path():
    """``from scitex_security import GitHubSecurityError`` still resolves."""
    # Arrange
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import scitex_security

    # Act
    obj = getattr(scitex_security, "GitHubSecurityError", None)
    # Assert
    assert isinstance(obj, type) and issubclass(obj, Exception)


def test_check_github_alerts_is_same_object_as_scitex_audit_version():
    """The shim re-exports the SSOT in scitex_audit (no parallel impl)."""
    # Arrange
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from scitex_audit.github import check_github_alerts as native
        from scitex_security import check_github_alerts as legacy

    # Act
    same_object = native is legacy
    # Assert
    assert same_object


def test_import_emits_deprecation_warning():
    """Importing scitex_security fires a ``DeprecationWarning``.

    Runs in a child python so a previous import in this same process
    (which would have already fired the once-per-process warning) does
    not mask the signal.
    """
    # Arrange
    code = (
        "import warnings\n"
        "with warnings.catch_warnings(record=True) as caught:\n"
        "    warnings.simplefilter('always')\n"
        "    import scitex_security  # noqa: F401\n"
        "msgs = [str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)]\n"
        "assert any('absorbed into scitex-audit' in m for m in msgs), msgs\n"
    )
    # Act
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    # Assert
    assert result.returncode == 0, result.stderr


def test_cli_main_hard_errors_with_redirect():
    """``scitex-security`` console-entry exits 2 + prints the redirect."""
    # Arrange
    code = (
        "import sys\n"
        "from scitex_security.cli import main\n"
        "try:\n"
        "    main()\n"
        "except SystemExit as e:\n"
        "    sys.exit(e.code)\n"
    )
    # Act
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    # Assert
    assert result.returncode == 2 and "scitex-audit github" in result.stderr


# EOF
