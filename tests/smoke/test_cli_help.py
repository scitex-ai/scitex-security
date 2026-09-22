"""Smoke: scitex-security CLI happy paths (fast, subprocess, every PR)."""

import subprocess
import sys

import pytest

pytestmark = pytest.mark.smoke


def test_security_help_exits_zero():
    # Arrange
    cmd = [sys.executable, "-m", "scitex_security.cli", "--help"]
    # Act
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    # Assert
    assert proc.returncode == 0
