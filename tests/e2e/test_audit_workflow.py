"""E2E: run the audit orchestrator against a real directory (no network)."""

import pytest

pytestmark = pytest.mark.e2e


def test_audit_tmp_dir_returns_all_checks(tmp_path):
    # Arrange
    from scitex_security import audit

    target = tmp_path / "sample.py"
    target.write_text("x = 1\n")
    # Act
    results = audit(str(tmp_path))
    # Assert
    assert set(results) == {"python", "shell", "deps", "github"}
