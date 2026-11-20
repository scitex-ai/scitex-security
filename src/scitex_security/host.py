"""Read-only Ubuntu/WSL patch observations, without upgrade or reboot actions."""

from __future__ import annotations

import datetime as dt
import os
import platform
import re
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path


def _probe(command):
    try:
        # Commands come from the internal read-only inventory; no shell.
        run = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
        return {"returncode": run.returncode, "stdout": run.stdout}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": None, "error_type": type(exc).__name__, "stdout": ""}


def collect_host_snapshot(root: str = "/") -> dict:
    """Gather bounded local facts; synthetic roots never execute host commands."""
    base = Path(root).resolve()
    real = base == Path("/")

    def read(name):
        try:
            return (base / name.lstrip("/")).read_text().strip()
        except OSError:
            return None

    release = {}
    for line in (read("/etc/os-release") or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in {"ID", "VERSION_ID", "PRETTY_NAME"}:
                release[key] = value.strip('"')
    kernel = read("/proc/sys/kernel/osrelease") or (
        platform.release() if real else None
    )
    snapshot = {
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "os": release,
        "kernel": kernel,
        "is_wsl": bool(kernel and "microsoft" in kernel.lower()),
        "reboot_required": (base / "var/run/reboot-required").exists(),
        "apparmor_kernel_enabled": read("/sys/module/apparmor/parameters/enabled"),
        "probes": {},
    }
    # A success stamp is stronger evidence than a directory mtime. An absent
    # stamp stays unknown; do not infer freshness from an arbitrary cache file.
    stamp = base / "var/lib/apt/periodic/update-success-stamp"
    snapshot["apt_update_age_days"] = (
        max(0.0, (time.time() - stamp.stat().st_mtime) / 86400)
        if stamp.is_file()
        else None
    )
    if not real or release.get("ID") != "ubuntu":
        return snapshot
    probes = snapshot["probes"]
    commands = {
        "apt_simulation": ["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"],
        "apt_config": ["apt-config", "dump"],
        "apparmor_service": ["systemctl", "is-active", "apparmor"],
        "failed_units": ["systemctl", "--failed", "--no-legend", "--plain"],
        "critical_services": [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
        ],
    }
    for name, command in commands.items():
        probes[name] = (
            _probe(command)
            if shutil.which(command[0])
            else {"returncode": None, "stdout": "", "error_type": "missing_tool"}
        )
    if shutil.which("dpkg-query"):
        probes["package_versions"] = _probe(
            [
                "dpkg-query",
                "-W",
                "-f=${binary:Package}\t${Version}\n",
                "linux-image-*-generic",
                "apparmor",
                "snapd",
                "systemd",
                "containerd",
                "apptainer",
            ]
        )
    return snapshot


def evaluate_host_snapshot(snapshot: dict) -> dict:
    """Assess observed facts, keeping unknown/skipped probes distinct from OK."""
    facts = {k: v for k, v in snapshot.items() if k != "probes"}
    if facts.get("os", {}).get("ID") != "ubuntu":
        return {
            "status": "skipped",
            "findings": [],
            "summary": "Ubuntu-specific checks do not apply or OS identity is unavailable.",
            "facts": facts,
        }
    findings, unknown = [], []

    def finding(code, message, severity="warning"):
        findings.append({"code": code, "severity": severity, "message": message})

    if facts.get("reboot_required"):
        finding(
            "HOST_REBOOT_REQUIRED",
            "A reboot-required marker exists; coordinate a maintenance window before restarting.",
        )
    if facts.get("is_wsl"):
        finding(
            "HOST_WSL_KERNEL",
            "Check WSL/Windows updates separately; Ubuntu kernel packages do not establish WSL kernel patch status.",
            "info",
        )
    age = facts.get("apt_update_age_days")
    if age is None:
        unknown.append("apt_update_freshness")
    elif age > 7:
        finding(
            "HOST_APT_CACHE_AGE",
            "The last successful APT update stamp is over seven days old; refresh metadata before making patch decisions.",
        )
    probes = snapshot.get("probes", {})
    apt = probes.get("apt_simulation", {})
    if apt.get("returncode") == 0:
        pending = re.findall(r"^Inst ([A-Za-z0-9.+:-]+) ", apt.get("stdout", ""), re.M)
        removals = re.findall(r"^Remv ([A-Za-z0-9.+:-]+)", apt.get("stdout", ""), re.M)
        facts["pending_packages"] = pending
        facts["proposed_removals"] = removals
        if pending:
            finding(
                "HOST_PENDING_UPDATES",
                f"APT simulation proposes {len(pending)} package updates; this is not a CVE applicability assessment.",
            )
        if removals:
            finding(
                "HOST_PROPOSED_REMOVALS",
                "APT simulation proposes package removals; review the transaction before applying updates.",
                "high",
            )
    else:
        unknown.append("apt_simulation")
    config = probes.get("apt_config", {})
    if config.get("returncode") == 0:
        selected = {}
        for key in [
            "APT::Periodic::Update-Package-Lists",
            "APT::Periodic::Unattended-Upgrade",
            "Unattended-Upgrade::Automatic-Reboot",
        ]:
            value = re.search(
                re.escape(key) + r'\s+"([^"\n]*)";', config.get("stdout", "")
            )
            selected[key] = value[1] if value else None
        facts["automatic_update_settings"] = selected
        if selected["APT::Periodic::Unattended-Upgrade"] == "0":
            finding(
                "HOST_UNATTENDED_DISABLED",
                "APT periodic unattended upgrades are explicitly disabled.",
            )
        elif selected["APT::Periodic::Unattended-Upgrade"] is None:
            unknown.append("unattended_upgrade_policy")
        if selected["Unattended-Upgrade::Automatic-Reboot"] == "true":
            finding(
                "HOST_AUTOMATIC_REBOOT",
                "Automatic reboot is enabled; verify that this matches CI and research-job maintenance policy.",
            )
    else:
        unknown.append("apt_config")
    apparmor = facts.get("apparmor_kernel_enabled")
    if apparmor in {"N", "n"}:
        finding(
            "HOST_APPARMOR_DISABLED",
            "The kernel AppArmor parameter reports disabled.",
            "high",
        )
    elif apparmor not in {"Y", "y"}:
        unknown.append("apparmor_kernel_state")
    service = probes.get("apparmor_service", {})
    if service.get("returncode") == 0:
        facts["apparmor_service"] = "active"
    elif service.get("stdout", "").strip() in {"inactive", "failed"}:
        facts["apparmor_service"] = service["stdout"].strip()
        finding(
            "HOST_APPARMOR_SERVICE",
            "The AppArmor service is not active; inspect loaded/enforcing profiles separately.",
        )
    else:
        unknown.append("apparmor_service")
    for name in ["failed_units", "critical_services"]:
        probe = probes.get(name, {})
        if probe.get("returncode") == 0:
            units = [
                line.split()[0]
                for line in probe.get("stdout", "").splitlines()
                if line.strip() and ".service" in line.split()[0]
            ]
            if name == "critical_services":
                units = [
                    unit
                    for unit in units
                    if any(
                        term in unit
                        for term in [
                            "actions.runner",
                            "docker",
                            "containerd",
                            "apptainer",
                            "ssh.",
                        ]
                    )
                ]
            facts[name] = units
            if name == "failed_units" and units:
                finding(
                    "HOST_FAILED_SERVICES",
                    f"{len(units)} failed service units were observed.",
                )
        else:
            unknown.append(name)
    versions = probes.get("package_versions", {})
    facts["installed_packages"] = {}
    for line in versions.get("stdout", "").splitlines():
        if "\t" in line:
            package, version = line.split("\t", 1)
            if re.fullmatch(r"[A-Za-z0-9.+:-]+", package) and version:
                facts["installed_packages"][package] = version
    facts["unknown_checks"] = unknown
    return {
        "status": "error" if unknown else "findings" if findings else "ok",
        "findings": findings,
        "summary": f"{len(findings)} host findings; {len(unknown)} unverified checks.",
        "facts": facts,
        "coverage": {
            "read_only": True,
            "apt_metadata_refreshed": False,
            "cve_applicability": "not_checked",
            "apparmor_profile_enforcement": "not_checked",
        },
    }


def audit_host(root: str = "/") -> dict:
    """Inspect Ubuntu patch hygiene, WSL distinctions, and service observations."""
    return evaluate_host_snapshot(collect_host_snapshot(root))
