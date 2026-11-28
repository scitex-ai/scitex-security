"""Tests for rotate-credential settings validation (no hardcoded fleet)."""

from _helpers import raised

from scitex_security._rotate._common import Abort
from scitex_security._rotate._settings import settings_from_dict, settings_from_mapping

FPR = "0123456789ABCDEF0123456789ABCDEF01234567"


def _section(**overrides):
    section = {
        "controller": "ctl",
        "hosts": ["ctl", "worker-01"],
        "issuer_fingerprint": FPR,
        "github": {"dotfiles_repo": "owner/.dotfiles"},
    }
    section.update(overrides)
    return section


def test_valid_section_yields_configured_hosts():
    # Arrange
    section = _section()
    # Act
    cfg = settings_from_mapping(section)
    # Assert
    assert cfg.hosts == ["ctl", "worker-01"]


def test_missing_hosts_is_rejected():
    # Arrange
    section = _section(hosts=[])
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_empty_section_is_rejected_no_builtin_fleet():
    # Arrange
    section = {}
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_controller_must_be_a_configured_host():
    # Arrange
    section = _section(controller="elsewhere")
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_malformed_fingerprint_is_rejected():
    # Arrange
    section = _section(issuer_fingerprint="ABC")
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_fingerprint_spaces_and_case_are_normalised():
    # Arrange
    spaced = " ".join(FPR.lower()[i : i + 4] for i in range(0, 40, 4))
    # Act
    cfg = settings_from_mapping(_section(issuer_fingerprint=spaced))
    # Assert
    assert cfg.issuer_fingerprint == FPR


def test_unknown_key_is_rejected():
    # Arrange
    section = _section(hostz=["typo"])
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_shell_metacharacters_in_host_are_rejected():
    # Arrange
    section = _section(hosts=["ctl", "x;rm -rf ~"])
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_pr_token_variable_must_be_a_variable_name():
    # Arrange
    section = _section(
        github={"dotfiles_repo": "owner/.dotfiles", "pr_token_variable": "not a name"}
    )
    # Act
    error = raised(settings_from_mapping, section)
    # Assert
    assert isinstance(error, Abort)


def test_settings_round_trip_through_worker_json():
    # Arrange
    cfg = settings_from_mapping(
        _section(
            skipped_hosts={"hpc": "no admin"},
            expected_recipient_count=3,
            payload_dir="/srv/pw",
        )
    )
    # Act
    back = settings_from_dict(cfg.to_dict())
    # Assert
    assert back == cfg
