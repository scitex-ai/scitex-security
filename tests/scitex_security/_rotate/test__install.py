"""Tests for the generated per-host installer (rendering only; nothing is installed)."""

import subprocess

from scitex_security._rotate._install import (
    readiness_probe,
    render_installer,
    shell_path,
)
from scitex_security._rotate._settings import settings_from_mapping

FPR = "0123456789ABCDEF0123456789ABCDEF01234567"
OLD = "bash-config-" + "0" * 24 + ".gpg"
NEW = "bash-config-" + "a" * 24 + ".gpg"


def _cfg(**overrides):
    section = {
        "controller": "ctl",
        "hosts": ["ctl"],
        "issuer_fingerprint": FPR,
        "github": {"dotfiles_repo": "owner/.dotfiles"},
    }
    section.update(overrides)
    return settings_from_mapping(section)


def _render(cfg=None):
    return render_installer(cfg or _cfg(), NEW, OLD, "1" * 64, "2" * 64)


def test_shell_path_expands_home_on_the_host():
    # Arrange
    path = "~/.pw"
    # Act
    word = shell_path(path)
    # Assert
    assert word == '"$HOME"/.pw'


def test_shell_path_quotes_spaces():
    # Arrange
    path = "/srv/with space"
    # Act
    word = shell_path(path)
    # Assert
    assert word == "'/srv/with space'"


def test_installer_leaves_no_placeholder():
    # Arrange
    cfg = _cfg()
    # Act
    script = _render(cfg)
    # Assert
    assert "__" not in script.replace("__FUNCS__", "")


def test_installer_pins_configured_fingerprint():
    # Arrange
    cfg = _cfg()
    # Act
    script = _render(cfg)
    # Assert
    assert f"FPR={FPR}\n" in script


def test_installer_uses_configured_trust_dir():
    # Arrange
    cfg = _cfg(trust_dir="/etc/other-trust")
    # Act
    script = _render(cfg)
    # Assert
    assert "T=/etc/other-trust;" in script


def test_installer_is_valid_bash():
    # Arrange
    script = _render()
    # Act
    proc = subprocess.run(["bash", "-n"], input=script.encode(), capture_output=True)
    # Assert
    assert proc.returncode == 0


def test_readiness_probe_reports_missing_trust_dir_locally(tmp_path):
    # Arrange
    cfg = _cfg(trust_dir=str(tmp_path / "absent"), verifier=str(tmp_path / "absent.py"))
    # Act
    out = subprocess.run(
        ["bash", "-c", readiness_probe(cfg)], capture_output=True, text=True
    ).stdout
    # Assert
    assert out.strip() == "SCITEX_TRUST_MISSING"


def test_readiness_probe_reports_ready_when_trust_dir_and_verifier_exist(tmp_path):
    # Arrange
    (tmp_path / "trust").mkdir()
    (tmp_path / "verifier.py").write_text("")
    cfg = _cfg(
        trust_dir=str(tmp_path / "trust"), verifier=str(tmp_path / "verifier.py")
    )
    # Act
    out = subprocess.run(
        ["bash", "-c", readiness_probe(cfg)], capture_output=True, text=True
    ).stdout
    # Assert
    assert out.strip() == "SCITEX_TRUST_READY"
