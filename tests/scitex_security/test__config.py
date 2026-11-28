"""Tests for the scitex-security config chain."""

from _helpers import raised

from scitex_security._config import (
    ConfigError,
    config_section,
    find_config_path,
    load_config,
)


def _write(path, text="redact: {}\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_explicit_path_beats_env_var(tmp_path):
    # Arrange
    explicit = _write(tmp_path / "a.yaml")
    env = {"SCITEX_SECURITY_CONFIG": str(_write(tmp_path / "b.yaml"))}
    # Act
    found = find_config_path(explicit, environ=env, cwd=tmp_path)
    # Assert
    assert found == explicit


def test_env_var_beats_project_scope(tmp_path):
    # Arrange
    (tmp_path / ".git").mkdir()
    _write(tmp_path / ".scitex" / "security" / "config.yaml")
    env_file = _write(tmp_path / "env.yaml")
    # Act
    found = find_config_path(
        environ={"SCITEX_SECURITY_CONFIG": str(env_file)}, cwd=tmp_path
    )
    # Assert
    assert found == env_file


def test_project_scope_beats_user_scope(tmp_path):
    # Arrange
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    project = _write(tmp_path / "repo" / ".scitex" / "security" / "config.yaml")
    _write(tmp_path / "home" / "security" / "config.yaml")
    # Act
    found = find_config_path(
        environ={"SCITEX_DIR": str(tmp_path / "home")}, cwd=tmp_path / "repo"
    )
    # Assert
    assert found == project


def test_user_scope_honours_scitex_dir(tmp_path):
    # Arrange
    user = _write(tmp_path / "home" / "security" / "config.yaml")
    # Act
    found = find_config_path(
        environ={"SCITEX_DIR": str(tmp_path / "home")}, cwd=tmp_path
    )
    # Assert
    assert found == user


def test_no_config_anywhere_loads_empty_defaults(tmp_path):
    # Arrange
    env = {"SCITEX_DIR": str(tmp_path / "nothing")}
    # Act
    config = load_config(environ=env, cwd=tmp_path)
    # Assert
    assert config == {}


def test_missing_explicit_path_is_an_error(tmp_path):
    # Arrange
    missing = tmp_path / "missing.yaml"
    # Act
    error = raised(find_config_path, missing, environ={}, cwd=tmp_path)
    # Assert
    assert isinstance(error, ConfigError)


def test_non_mapping_yaml_is_an_error(tmp_path):
    # Arrange
    path = _write(tmp_path / "list.yaml", "- a\n- b\n")
    # Act
    error = raised(load_config, path, environ={}, cwd=tmp_path)
    # Assert
    assert isinstance(error, ConfigError)


def test_config_section_rejects_non_mapping_section():
    # Arrange
    config = {"redact": ["not", "a", "mapping"]}
    # Act
    error = raised(config_section, config, "redact")
    # Assert
    assert isinstance(error, ConfigError)
