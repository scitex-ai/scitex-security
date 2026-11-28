"""Tests for scitex_security._redact with the REAL gitleaks binary and fake secrets."""

from pathlib import Path

import pytest
from _helpers import raised
from _secret_fakes import (
    FAKE_AWS_KEY_ID,
    FAKE_GITHUB_PAT,
    FAKE_PEM_BLOCK,
    FAKE_UNFORMATTED_VALUE,
    GITLEAKS,
    GITLEAKS_MISSING_REASON,
    NORMAL_TEXT,
    scrubbed_environ,
)

from scitex_security._redact._core import (
    MASK,
    GitleaksError,
    Redactor,
    build_redactor,
    credential_env_values,
    find_gitleaks,
    gitleaks_secrets,
    packaged_gitleaks_config,
)

needs_gitleaks = pytest.mark.skipif(GITLEAKS is None, reason=GITLEAKS_MISSING_REASON)


def _redactor(**env):
    return build_redactor(environ=scrubbed_environ(**env))


@needs_gitleaks
def test_fine_grained_github_pat_is_masked():
    # Arrange
    redactor = _redactor()
    # Act
    result = redactor.redact(f"token: {FAKE_GITHUB_PAT}\n")
    # Assert
    assert result.text == f"token: {MASK}\n"


@needs_gitleaks
def test_aws_access_key_id_is_masked():
    # Arrange
    redactor = _redactor()
    # Act
    result = redactor.redact(f"key {FAKE_AWS_KEY_ID} here")
    # Assert
    assert FAKE_AWS_KEY_ID not in result.text


@needs_gitleaks
def test_pem_private_key_block_is_masked():
    # Arrange
    redactor = _redactor()
    # Act
    result = redactor.redact(f"before\n{FAKE_PEM_BLOCK}\nafter\n")
    # Assert
    assert result.text == f"before\n{MASK}\nafter\n"


@needs_gitleaks
def test_exact_env_value_of_unformatted_shape_is_masked():
    # Arrange
    redactor = _redactor(FAKE_SERVICE_TOKEN=FAKE_UNFORMATTED_VALUE)
    # Act
    result = redactor.redact(f"the value is {FAKE_UNFORMATTED_VALUE} here")
    # Assert
    assert result.text == f"the value is {MASK} here"


@needs_gitleaks
def test_normal_text_and_paths_pass_through_unchanged():
    # Arrange
    redactor = _redactor()
    # Act
    result = redactor.redact(NORMAL_TEXT)
    # Assert
    assert result.text == NORMAL_TEXT


@needs_gitleaks
def test_normal_text_reports_no_change():
    # Arrange
    redactor = _redactor()
    # Act
    result = redactor.redact(NORMAL_TEXT)
    # Assert
    assert result.changed is False


@needs_gitleaks
def test_real_gitleaks_run_emits_no_warning():
    # Arrange
    redactor = _redactor()
    # Act
    result = redactor.redact(f"x {FAKE_GITHUB_PAT}")
    # Assert
    assert result.warnings == []


@needs_gitleaks
def test_redact_many_masks_a_secret_in_each_text_from_one_scan():
    # Arrange
    redactor = _redactor()
    # Act
    results = redactor.redact_many([f"out {FAKE_GITHUB_PAT}", f"err {FAKE_GITHUB_PAT}"])
    # Assert
    assert [r.text for r in results] == [f"out {MASK}", f"err {MASK}"]


def test_missing_gitleaks_still_masks_exact_env_value():
    # Arrange
    redactor = Redactor(gitleaks_bin=None, env_values={FAKE_UNFORMATTED_VALUE})
    # Act
    result = redactor.redact(f"v={FAKE_UNFORMATTED_VALUE}")
    # Assert
    assert result.text == f"v={MASK}"


def test_missing_gitleaks_emits_a_warning():
    # Arrange
    redactor = Redactor(gitleaks_bin=None)
    # Act
    result = redactor.redact("some output")
    # Assert
    assert result.warnings == ["gitleaks not found; only exact-value redaction ran"]


def test_failing_gitleaks_binary_emits_a_warning(tmp_path):
    # Arrange
    broken = tmp_path / "gitleaks"
    broken.write_text("#!/bin/sh\nexit 3\n")
    broken.chmod(0o755)
    redactor = Redactor(gitleaks_bin=str(broken))
    # Act
    result = redactor.redact("some output")
    # Assert
    assert result.warnings == [
        "gitleaks failed (exit status 3); only exact-value redaction ran"
    ]


def test_gitleaks_secrets_raises_on_unreadable_report(tmp_path):
    # Arrange
    noisy = tmp_path / "gitleaks"
    noisy.write_text("#!/bin/sh\necho not-json\n")
    noisy.chmod(0o755)
    # Act
    error = raised(gitleaks_secrets, "text", str(noisy))
    # Assert
    assert isinstance(error, GitleaksError) and str(error) == "unreadable report"


def test_find_gitleaks_returns_none_without_path_or_local_bin(tmp_path):
    # Arrange
    environ = {"PATH": str(tmp_path), "HOME": str(tmp_path)}
    # Act
    found = find_gitleaks(environ=environ)
    # Assert
    assert found is None


def test_find_gitleaks_falls_back_to_home_local_bin(tmp_path):
    # Arrange
    local = tmp_path / ".local" / "bin"
    local.mkdir(parents=True)
    (local / "gitleaks").write_text("#!/bin/sh\n")
    (local / "gitleaks").chmod(0o755)
    environ = {"PATH": str(tmp_path / "empty"), "HOME": str(tmp_path)}
    # Act
    found = find_gitleaks(environ=environ)
    # Assert
    assert found == str(local / "gitleaks")


def test_credential_env_values_selects_credential_named_vars():
    # Arrange
    environ = {
        "FAKE_API_KEY": FAKE_UNFORMATTED_VALUE,
        "COLOR_THEME": FAKE_UNFORMATTED_VALUE + "x",
    }
    # Act
    values = credential_env_values(environ)
    # Assert
    assert values == {FAKE_UNFORMATTED_VALUE}


def test_credential_env_values_skips_short_values():
    # Arrange
    environ = {"FAKE_TOKEN": "short-value"}
    # Act
    values = credential_env_values(environ)
    # Assert
    assert values == set()


def test_credential_env_values_skips_paths():
    # Arrange
    environ = {
        "HF_TOKEN_FILE": "/home/user/.cache/token-file",
        "X_SECRET_DIR": "~/secret-directory",
    }
    # Act
    values = credential_env_values(environ)
    # Assert
    assert values == set()


def test_packaged_gitleaks_config_keeps_upstream_rules():
    # Arrange
    path = packaged_gitleaks_config()
    # Act
    text = Path(path).read_text()
    # Assert
    assert "useDefault = true" in text


def test_build_redactor_uses_gitleaks_config_from_config_chain(tmp_path):
    # Arrange
    toml = tmp_path / "custom.toml"
    toml.write_text("[extend]\nuseDefault = true\n")
    config = tmp_path / "config.yaml"
    config.write_text(f"redact:\n  gitleaks_config: {toml}\n")
    # Act
    redactor = build_redactor(
        environ=scrubbed_environ(SCITEX_SECURITY_CONFIG=str(config))
    )
    # Assert
    assert redactor.gitleaks_config == toml


def test_explicit_gitleaks_config_beats_config_chain(tmp_path):
    # Arrange
    chained, explicit = tmp_path / "chained.toml", tmp_path / "explicit.toml"
    config = tmp_path / "config.yaml"
    config.write_text(f"redact:\n  gitleaks_config: {chained}\n")
    # Act
    redactor = build_redactor(
        gitleaks_config=explicit,
        environ=scrubbed_environ(SCITEX_SECURITY_CONFIG=str(config)),
    )
    # Assert
    assert redactor.gitleaks_config == explicit


@needs_gitleaks
def test_custom_rule_in_gitleaks_config_extends_detection(tmp_path):
    # Arrange
    toml = tmp_path / "custom.toml"
    toml.write_text(
        "[extend]\nuseDefault = true\n\n[[rules]]\nid = 'fake-internal'\n"
        "regex = '''zzint_[a-z0-9]{24}'''\n"
    )
    token = "zzint_" + "abcdefghij0123456789wxyz"
    redactor = Redactor(gitleaks_bin=GITLEAKS, gitleaks_config=toml)
    # Act
    result = redactor.redact(f"internal {token}")
    # Assert
    assert result.text == f"internal {MASK}"
