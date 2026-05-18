"""Smoke tests: every example script must run to completion."""

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"
EXAMPLES = sorted(EXAMPLES_DIR.glob("*.py"))


def test_examples_directory_contains_python_scripts():
    # Arrange
    examples_dir = EXAMPLES_DIR
    # Act
    found = list(examples_dir.glob("*.py"))
    # Assert
    assert found, f"no example scripts found in {examples_dir}"


@pytest.mark.parametrize("example_path", EXAMPLES, ids=lambda p: p.name)
def test_example_script_runs_to_zero_exit_code(example_path, tmp_path):
    # Arrange
    cmd = [sys.executable, str(example_path)]
    # Act
    result = subprocess.run(
        cmd,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Assert
    assert result.returncode == 0, f"{example_path.name} failed: {result.stderr}"
