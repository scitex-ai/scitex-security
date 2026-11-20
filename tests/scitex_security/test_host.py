"""Patch posture is assessed from observations, not a hardcoded kernel version."""

from scitex_security.host import audit_host, evaluate_host_snapshot


def snapshot():
    return {
        "os": {"ID": "ubuntu", "VERSION_ID": "24.04"},
        "kernel": "example-generic",
        "reboot_required": False,
        "is_wsl": False,
        "apt_update_age_days": 1,
        "apparmor_kernel_enabled": "Y",
        "probes": {
            "apt_simulation": {"returncode": 0, "stdout": ""},
            "apt_config": {
                "returncode": 0,
                "stdout": 'APT::Periodic::Unattended-Upgrade "1";',
            },
            "apparmor_service": {"returncode": 0, "stdout": "active"},
            "failed_units": {"returncode": 0, "stdout": ""},
            "critical_services": {"returncode": 0, "stdout": ""},
        },
    }


def test_pending_updates_and_reboot_are_distinct():
    # Arrange
    data = snapshot()
    data["reboot_required"] = True
    data["probes"]["apt_simulation"]["stdout"] = (
        "Inst linux-image-generic [old] (new Ubuntu:24.04/noble-security)\n"
    )
    # Act
    result = evaluate_host_snapshot(data)
    # Assert
    assert {f["code"] for f in result["findings"]} == {
        "HOST_REBOOT_REQUIRED",
        "HOST_PENDING_UPDATES",
    }
    assert result["facts"]["pending_packages"] == ["linux-image-generic"]
    assert result["coverage"]["cve_applicability"] == "not_checked"


def test_wsl_reports_independent_kernel_review():
    # Arrange
    data = snapshot()
    data["is_wsl"] = True
    # Act
    result = evaluate_host_snapshot(data)
    # Assert
    assert any(f["code"] == "HOST_WSL_KERNEL" for f in result["findings"])


def test_missing_apt_observation_is_never_ok():
    # Arrange
    data = snapshot()
    data["probes"].pop("apt_simulation")
    # Act
    result = evaluate_host_snapshot(data)
    # Assert
    assert result["status"] == "error"
    assert "apt_simulation" in result["facts"]["unknown_checks"]


def test_synthetic_root_does_not_probe_running_host(tmp_path):
    # Arrange
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    # Act
    result = audit_host(str(tmp_path))
    # Assert
    assert result["facts"]["kernel"] is None
    assert "apt_simulation" in result["facts"]["unknown_checks"]


def test_other_os_is_skipped(tmp_path):
    # Arrange
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=rocky\n")
    # Act
    result = audit_host(str(tmp_path))
    # Assert
    assert result["status"] == "skipped"
