#!/usr/bin/env python3
"""Tests for the W1-reverse absorption (ADR-0002): scitex_security gained
the multi-tool security-audit orchestrator (bandit / shellcheck / pip-audit
/ github) absorbed from scitex-audit 0.2.0.

Asserts that the new public ``audit`` API + the runner internals + the
reverse-migration helper resolve via the canonical scitex_security paths.

PA-307 test-quality: every test carries the canonical
``# Arrange`` / ``# Act`` / ``# Assert`` markers each on its own line.
PA-306 no-mocks: no patching; we exercise the real module surface.
"""

from __future__ import annotations


def test_top_level_audit_is_importable():
    """``from scitex_security import audit`` resolves."""
    # Arrange
    import scitex_security

    # Act
    has_attr = hasattr(scitex_security, "audit")
    # Assert
    assert callable(getattr(scitex_security, "audit"))
    assert has_attr


def test_audit_in_package_all():
    """``audit`` is exposed in the package ``__all__``."""
    # Arrange
    import scitex_security

    # Act
    in_all = "audit" in scitex_security.__all__
    # Assert
    assert in_all


def test_runner_module_imports_clean():
    """``scitex_security._runner`` imports without raising."""
    # Arrange
    expected_module_name = "scitex_security._runner"

    # Act
    import scitex_security._runner as runner

    # Assert
    assert runner.__name__ == expected_module_name


def test_bandit_runner_is_importable():
    """``scitex_security._bandit.run_bandit`` resolves."""
    # Arrange
    from scitex_security._bandit import run_bandit

    # Act
    is_callable = callable(run_bandit)
    # Assert
    assert is_callable


def test_shellcheck_runner_is_importable():
    """``scitex_security._shellcheck.run_shellcheck`` resolves."""
    # Arrange
    from scitex_security._shellcheck import run_shellcheck

    # Act
    is_callable = callable(run_shellcheck)
    # Assert
    assert is_callable


def test_pip_audit_runner_is_importable():
    """``scitex_security._pip_audit.run_pip_audit`` resolves."""
    # Arrange
    from scitex_security._pip_audit import run_pip_audit

    # Act
    is_callable = callable(run_pip_audit)
    # Assert
    assert is_callable


def test_format_helpers_are_importable():
    """``scitex_security._format`` exposes ``format_json``/``format_text``."""
    # Arrange
    from scitex_security import _format

    # Act
    has_json = hasattr(_format, "format_json")
    # Assert
    assert has_json and hasattr(_format, "format_text")


def test_github_runner_adapter_is_importable():
    """``scitex_security._github_runner.run_github_check`` resolves."""
    # Arrange
    from scitex_security._github_runner import run_github_check

    # Act
    is_callable = callable(run_github_check)
    # Assert
    assert is_callable


def test_legacy_audit_dir_reverse_migration_helper_exists():
    """``_paths._migrate_legacy_audit_dir`` resolves (called from __init__)."""
    # Arrange
    from scitex_security._paths import _migrate_legacy_audit_dir

    # Act
    is_callable = callable(_migrate_legacy_audit_dir)
    # Assert
    assert is_callable


def test_reverse_migration_noops_when_legacy_audit_dir_absent(tmp_path):
    """No-op + no raise when ``~/.scitex/audit/github-alerts/`` doesn't exist.

    PA-306 §3 no-mocks: hand-rolled env save/restore (no monkeypatch).
    """
    # Arrange
    import os

    from scitex_security._paths import _migrate_legacy_audit_dir

    saved_scitex_dir = os.environ.get("SCITEX_DIR")
    os.environ["SCITEX_DIR"] = str(tmp_path)
    try:
        # Act
        _migrate_legacy_audit_dir()  # tmp_path is empty → no legacy dir
        # Assert
        assert not (tmp_path / "security").exists() or not any(
            (tmp_path / "security").iterdir()
        )
    finally:
        if saved_scitex_dir is None:
            os.environ.pop("SCITEX_DIR", None)
        else:
            os.environ["SCITEX_DIR"] = saved_scitex_dir


def test_audit_runner_skips_unavailable_tools(tmp_path):
    """``audit(.)`` returns a results dict and skips unavailable checks.

    PA-306 §3 no-mocks: just calls the real orchestrator on a tmp dir.
    Tools may or may not be installed on the runner; we just assert the
    envelope shape (``{check: {status, findings, summary}, ...}``).
    """
    # Arrange
    from scitex_security import audit

    target = tmp_path
    # Act
    results = audit(str(target), checks=["python"])
    # Assert
    assert isinstance(results, dict)
    assert "python" in results
    assert "status" in results["python"]


# EOF
