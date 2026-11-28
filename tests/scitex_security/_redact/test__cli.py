"""CLI tests for ``scitex-security redact`` / ``rotate-credential`` (real gitleaks, fakes)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from _secret_fakes import (
    FAKE_GITHUB_PAT,
    FAKE_UNFORMATTED_VALUE,
    GITLEAKS,
    GITLEAKS_MISSING_REASON,
    NORMAL_TEXT,
    bash_event,
    cli_env,
    scrubbed_environ,
)
from click.testing import CliRunner

import scitex_security
from scitex_security._redact._core import MASK
from scitex_security.cli import main

needs_gitleaks = pytest.mark.skipif(GITLEAKS is None, reason=GITLEAKS_MISSING_REASON)

_PKG_PARENT = str(Path(scitex_security.__file__).resolve().parent.parent)


def _run_cli(args, stdin, **env):
    """Run the real CLI in a child interpreter with real credential vars removed."""
    environ = scrubbed_environ(**env)
    environ["PYTHONPATH"] = _PKG_PARENT + os.pathsep + environ.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "scitex_security", *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=environ,
        timeout=60,
    )


@needs_gitleaks
def test_redact_text_mode_masks_fine_grained_pat():
    # Arrange
    runner = CliRunner(env=cli_env())
    # Act
    result = runner.invoke(main, ["redact", "-"], input=f"a {FAKE_GITHUB_PAT} b\n")
    # Assert
    assert result.stdout == f"a {MASK} b\n"


@needs_gitleaks
def test_redact_text_mode_masks_exact_env_value():
    # Arrange
    runner = CliRunner(env=cli_env(FAKE_SERVICE_PASSWORD=FAKE_UNFORMATTED_VALUE))
    # Act
    result = runner.invoke(main, ["redact", "-"], input=f"pw={FAKE_UNFORMATTED_VALUE}")
    # Assert
    assert result.stdout == f"pw={MASK}"


@needs_gitleaks
def test_redact_text_mode_passes_normal_text_byte_for_byte():
    # Arrange
    runner = CliRunner(env=cli_env())
    # Act
    result = runner.invoke(main, ["redact", "-"], input=NORMAL_TEXT)
    # Assert
    assert result.stdout == NORMAL_TEXT


@needs_gitleaks
def test_redact_hook_mode_emits_updated_tool_output():
    # Arrange
    runner = CliRunner(env=cli_env())
    event = json.dumps(bash_event(f"got {FAKE_GITHUB_PAT}"))
    # Act
    result = runner.invoke(
        main, ["redact", "-", "--hook", "claude-post-tool-use"], input=event
    )
    # Assert
    assert (
        json.loads(result.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        == f"got {MASK}"
    )


@needs_gitleaks
def test_redact_hook_mode_prints_nothing_for_clean_output():
    # Arrange
    runner = CliRunner(env=cli_env())
    event = json.dumps(bash_event(NORMAL_TEXT))
    # Act
    result = runner.invoke(
        main, ["redact", "-", "--hook", "claude-post-tool-use"], input=event
    )
    # Assert
    assert result.stdout == ""


def test_redact_hook_mode_reports_unparseable_input_instead_of_failing_silently():
    # Arrange
    runner = CliRunner(env=cli_env())
    # Act
    result = runner.invoke(
        main, ["redact", "-", "--hook", "claude-post-tool-use"], input="{not json"
    )
    # Assert
    assert (
        "NOT redacted"
        in json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    )


def test_redact_hook_mode_exits_zero_on_unparseable_input():
    # Arrange
    runner = CliRunner(env=cli_env())
    # Act
    result = runner.invoke(
        main, ["redact", "-", "--hook", "claude-post-tool-use"], input="{not json"
    )
    # Assert
    assert result.exit_code == 0


def test_redact_text_mode_without_gitleaks_warns_on_stderr(tmp_path):
    # Arrange
    empty = tmp_path / "bin"
    empty.mkdir()
    # Act
    proc = _run_cli(
        ["redact", "-"],
        "plain\n",
        PATH=str(empty),
        HOME=str(tmp_path),
    )
    # Assert
    assert "gitleaks not found" in proc.stderr


def test_redact_text_mode_without_gitleaks_still_masks_env_value(tmp_path):
    # Arrange
    empty = tmp_path / "bin"
    empty.mkdir()
    # Act
    proc = _run_cli(
        ["redact", "-"],
        f"v {FAKE_UNFORMATTED_VALUE}\n",
        PATH=str(empty),
        HOME=str(tmp_path),
        FAKE_DB_DSN=FAKE_UNFORMATTED_VALUE,
    )
    # Assert
    assert proc.stdout == f"v {MASK}\n"


def test_redact_hook_mode_without_gitleaks_warns_in_additional_context(tmp_path):
    # Arrange
    empty = tmp_path / "bin"
    empty.mkdir()
    event = json.dumps(bash_event("plain"))
    # Act
    proc = _run_cli(
        ["redact", "-", "--hook", "claude-post-tool-use"],
        event,
        PATH=str(empty),
        HOME=str(tmp_path),
    )
    # Assert
    assert (
        "gitleaks not found"
        in json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    )
