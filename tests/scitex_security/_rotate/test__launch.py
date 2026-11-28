"""Launcher <-> isolated ``python -I`` worker tests (aborts before any value or key use)."""

import os
import sys

import pytest
from _helpers import raised
from click.testing import CliRunner

from scitex_security._redact._core import SECRET_NAME_RE
from scitex_security._rotate._launch import (
    ENTRY_SCRIPT,
    RotationConfigError,
    load_rotate_settings,
    rotate_credential,
)
from scitex_security._rotate._settings import settings_from_mapping
from scitex_security.cli import main

SYSTEM_PYTHON = "/usr/bin/python3"
needs_system_python = pytest.mark.skipif(
    not os.access(SYSTEM_PYTHON, os.X_OK),
    reason="no /usr/bin/python3 for the -I worker",
)


def _cfg(python=SYSTEM_PYTHON):
    return settings_from_mapping(
        {
            "controller": "ctl",
            "hosts": ["ctl"],
            "issuer_fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
            "github": {"dotfiles_repo": "owner/.dotfiles"},
            "python": python,
        }
    )


def _never_confirm(prompt):
    raise AssertionError("confirmation must not be requested before signing")


def test_entry_script_ships_inside_the_package():
    # Arrange
    path = ENTRY_SCRIPT
    # Act
    exists = path.is_file()
    # Assert
    assert exists is True


@needs_system_python
def test_isolated_worker_aborts_on_invalid_payload_name():
    # Arrange
    cfg = _cfg()
    # Act
    status = rotate_credential(
        "not-a-payload.gpg",
        "GH_TOKEN",
        dry_run=True,
        settings=cfg,
        confirm=_never_confirm,
    )
    # Assert
    assert status == 2


def test_isolated_worker_runs_with_current_interpreter_under_dash_i():
    # Arrange
    cfg = _cfg(python=sys.executable)
    # Act
    status = rotate_credential(
        "bash-config-x.gpg", "lower", dry_run=True, settings=cfg, confirm=_never_confirm
    )
    # Assert
    assert status == 2


def test_missing_rotate_config_is_a_config_error(tmp_path):
    # Arrange
    config = tmp_path / "config.yaml"
    config.write_text("redact: {}\n")
    # Act
    error = raised(load_rotate_settings, config)
    # Assert
    assert isinstance(error, RotationConfigError)


def cli_env(**extra):
    env = {k: None for k in os.environ if SECRET_NAME_RE.search(k)}
    env.update(extra)
    return env


def test_rotate_credential_without_config_reports_missing_hosts(tmp_path):
    # Arrange
    runner = CliRunner(
        env=cli_env(SCITEX_DIR=str(tmp_path), SCITEX_SECURITY_CONFIG=None)
    )
    # Act
    result = runner.invoke(
        main,
        [
            "rotate-credential",
            "bash-config-0123456789abcdef01234567.gpg",
            "GH_TOKEN",
            "--dry-run",
        ],
        catch_exceptions=False,
    )
    # Assert
    assert result.exit_code == 2


def test_rotate_credential_help_states_hidden_prompt_only():
    # Arrange
    runner = CliRunner()
    # Act
    result = runner.invoke(main, ["rotate-credential", "--help"])
    # Assert
    assert "hidden prompt" in result.output
