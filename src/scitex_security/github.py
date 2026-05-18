#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: ~/proj/scitex-code/src/scitex/security/github.py

"""
GitHub Security Alerts Module

Fetches and processes security alerts from GitHub.

Collaborator injection
----------------------
Per the SciTeX no-mocks rule (PA-306), the production callables that
talk to external collaborators (the ``subprocess`` module, and the
in-module ``_run_gh_command``/``check_gh_auth``/``get_*_alerts``
helpers) accept keyword-only overrides defaulting to the real module
globals. Tests pass real hand-rolled fakes; production code does not
pass anything.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional


class GitHubSecurityError(Exception):
    """Raised when GitHub security operations fail."""

    pass


def _run_gh_command(
    args: List[str],
    *,
    run: Optional[Callable] = None,
) -> str:
    """Run GitHub CLI command and return output.

    Args:
        args: Arguments to pass to ``gh`` (without the ``gh`` prefix).
        run: ``subprocess.run``-shaped callable. Defaults to the real
            ``subprocess.run``. Override in tests.
    """
    if run is None:
        run = subprocess.run
    try:
        result = run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise GitHubSecurityError(f"GitHub CLI error: {e.stderr}")
    except FileNotFoundError:
        raise GitHubSecurityError(
            "GitHub CLI (gh) not found. Install: https://cli.github.com/"
        )


def check_gh_auth(*, run: Optional[Callable] = None) -> bool:
    """Check if GitHub CLI is authenticated.

    Args:
        run: ``subprocess.run``-shaped callable. Defaults to the real
            ``subprocess.run``. Override in tests.
    """
    if run is None:
        run = subprocess.run
    try:
        run(
            ["gh", "auth", "status"],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_secret_alerts(
    repo: Optional[str] = None,
    *,
    gh_runner: Optional[Callable[[List[str]], str]] = None,
) -> List[Dict]:
    """
    Get secret scanning alerts.

    Args:
        repo: Repository in format 'owner/repo'. If None, uses current repo.
        gh_runner: ``_run_gh_command``-shaped callable. Defaults to
            :func:`_run_gh_command`. Override in tests.

    Returns:
        List of secret scanning alerts
    """
    if gh_runner is None:
        gh_runner = _run_gh_command
    try:
        # Use GitHub REST API for secret scanning
        api_path = "/repos/:owner/:repo/secret-scanning/alerts"
        if repo:
            owner, repo_name = repo.split("/")
            api_path = f"/repos/{owner}/{repo_name}/secret-scanning/alerts"

        output = gh_runner(
            [
                "api",
                api_path,
                "--paginate",
                "--jq",
                ".[] | {state, secretType: .secret_type_display_name, "
                "url: .html_url, "
                "createdAt: .created_at, "
                "path: .first_location_detected.path, "
                "line: .first_location_detected.start_line}",
            ]
        )

        if not output.strip():
            return []

        # Parse line-delimited JSON
        alerts = []
        for line in output.strip().split("\n"):
            if line.strip():
                alerts.append(json.loads(line))
        return alerts
    except GitHubSecurityError:
        return []


def get_dependabot_alerts(
    repo: Optional[str] = None,
    *,
    gh_runner: Optional[Callable[[List[str]], str]] = None,
) -> List[Dict]:
    """
    Get Dependabot vulnerability alerts.

    Args:
        repo: Repository in format 'owner/repo'. If None, uses current repo.
        gh_runner: ``_run_gh_command``-shaped callable. Defaults to
            :func:`_run_gh_command`. Override in tests.

    Returns:
        List of Dependabot alerts
    """
    if gh_runner is None:
        gh_runner = _run_gh_command
    try:
        # Use GitHub API to get Dependabot alerts
        api_path = "/repos/:owner/:repo/dependabot/alerts"
        if repo:
            owner, repo_name = repo.split("/")
            api_path = f"/repos/{owner}/{repo_name}/dependabot/alerts"

        output = gh_runner(
            [
                "api",
                api_path,
                "--paginate",
                "--jq",
                ".[] | {state, severity: .security_advisory.severity, "
                "summary: .security_advisory.summary, "
                "package: .dependency.package.name, "
                "cve: .security_advisory.cve_id, "
                "url: .html_url, "
                "created_at: .created_at}",
            ]
        )

        if not output.strip():
            return []

        # Parse line-delimited JSON
        alerts = []
        for line in output.strip().split("\n"):
            if line.strip():
                alerts.append(json.loads(line))
        return alerts
    except GitHubSecurityError:
        return []


def get_code_scanning_alerts(
    repo: Optional[str] = None,
    *,
    gh_runner: Optional[Callable[[List[str]], str]] = None,
) -> List[Dict]:
    """
    Get code scanning alerts.

    Args:
        repo: Repository in format 'owner/repo'. If None, uses current repo.
        gh_runner: ``_run_gh_command``-shaped callable. Defaults to
            :func:`_run_gh_command`. Override in tests.

    Returns:
        List of code scanning alerts
    """
    if gh_runner is None:
        gh_runner = _run_gh_command
    try:
        # Use GitHub API to get code scanning alerts
        api_path = "/repos/:owner/:repo/code-scanning/alerts"
        if repo:
            owner, repo_name = repo.split("/")
            api_path = f"/repos/{owner}/{repo_name}/code-scanning/alerts"

        output = gh_runner(
            [
                "api",
                api_path,
                "--paginate",
                "--jq",
                ".[] | {state, severity: .rule.severity, "
                "description: .rule.description, "
                "location: .most_recent_instance.location.path, "
                "line: .most_recent_instance.location.start_line, "
                "url: .html_url, "
                "created_at: .created_at}",
            ]
        )

        if not output.strip():
            return []

        # Parse line-delimited JSON
        alerts = []
        for line in output.strip().split("\n"):
            if line.strip():
                alerts.append(json.loads(line))
        return alerts
    except GitHubSecurityError:
        return []


def check_github_alerts(
    repo: Optional[str] = None,
    *,
    auth_check: Optional[Callable[[], bool]] = None,
    secrets_fn: Optional[Callable] = None,
    dependabot_fn: Optional[Callable] = None,
    code_scanning_fn: Optional[Callable] = None,
) -> Dict[str, List[Dict]]:
    """
    Check all GitHub security alerts.

    Args:
        repo: Repository in format 'owner/repo'. If None, uses current repo.
        auth_check: ``check_gh_auth``-shaped callable. Override in tests.
        secrets_fn: ``get_secret_alerts``-shaped callable. Override in tests.
        dependabot_fn: ``get_dependabot_alerts``-shaped callable. Override in
            tests.
        code_scanning_fn: ``get_code_scanning_alerts``-shaped callable.
            Override in tests.

    Returns:
        Dictionary with keys: 'secrets', 'dependabot', 'code_scanning'

    Raises:
        GitHubSecurityError: If GitHub CLI is not installed or not authenticated
    """
    if auth_check is None:
        auth_check = check_gh_auth
    if secrets_fn is None:
        secrets_fn = get_secret_alerts
    if dependabot_fn is None:
        dependabot_fn = get_dependabot_alerts
    if code_scanning_fn is None:
        code_scanning_fn = get_code_scanning_alerts

    if not auth_check():
        raise GitHubSecurityError(
            "Not authenticated with GitHub CLI. Run: gh auth login"
        )

    return {
        "secrets": secrets_fn(repo),
        "dependabot": dependabot_fn(repo),
        "code_scanning": code_scanning_fn(repo),
    }


def format_alerts_report(alerts: Dict[str, List[Dict]]) -> str:
    """
    Format alerts into a readable text report.

    Args:
        alerts: Dictionary of alerts from check_github_alerts()

    Returns:
        Formatted text report
    """
    lines = []
    lines.append("=" * 50)
    lines.append("GitHub Security Alerts Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 50)
    lines.append("")

    # Secret scanning alerts
    lines.append("### SECRET SCANNING ALERTS ###")
    lines.append("")
    secrets = [s for s in alerts["secrets"] if s.get("state") == "open"]
    if secrets:
        for alert in secrets:
            lines.append(f"- [{alert['state']}] {alert['secretType']}")
            path = alert.get("path", "N/A")
            line_num = alert.get("line", "")
            if path != "N/A" and line_num:
                lines.append(f"  Location: {path}:{line_num}")
            lines.append(f"  Created: {alert.get('createdAt', 'N/A')}")
            lines.append(f"  URL: {alert['url']}")
            lines.append("")
    else:
        lines.append("No open secret scanning alerts")
        lines.append("")

    lines.append("=" * 50)
    lines.append("")

    # Dependabot alerts
    lines.append("### DEPENDABOT VULNERABILITY ALERTS ###")
    lines.append("")
    dependabot = [d for d in alerts["dependabot"] if d.get("state") == "open"]
    if dependabot:
        for alert in dependabot:
            severity = alert.get("severity", "unknown").upper()
            lines.append(f"- [{alert['state']}] {severity}: {alert['summary']}")
            lines.append(f"  Package: {alert['package']}")
            lines.append(f"  CVE: {alert.get('cve') or 'N/A'}")
            lines.append(f"  URL: {alert['url']}")
            lines.append("")
    else:
        lines.append("No open Dependabot alerts")
        lines.append("")

    lines.append("=" * 50)
    lines.append("")

    # Code scanning alerts
    lines.append("### CODE SCANNING ALERTS ###")
    lines.append("")
    code_scanning = [c for c in alerts["code_scanning"] if c.get("state") == "open"]
    if code_scanning:
        for alert in code_scanning:
            severity = alert.get("severity", "unknown").upper()
            lines.append(f"- [{alert['state']}] {severity}: {alert['description']}")
            location = alert.get("location", "N/A")
            line_num = alert.get("line", "")
            if line_num:
                location = f"{location}:{line_num}"
            lines.append(f"  Location: {location}")
            lines.append(f"  URL: {alert['url']}")
            lines.append("")
    else:
        lines.append("No open code scanning alerts")
        lines.append("")

    lines.append("=" * 50)
    lines.append("")

    # Summary
    total = len(secrets) + len(dependabot) + len(code_scanning)
    lines.append("### SUMMARY ###")
    lines.append("")
    lines.append(f"Total open alerts: {total}")
    lines.append(f"  - Secrets: {len(secrets)}")
    lines.append(f"  - Dependabot: {len(dependabot)}")
    lines.append(f"  - Code Scanning: {len(code_scanning)}")
    lines.append("")

    if total > 0:
        lines.append("⚠️  ACTION REQUIRED: Security issues found!")
    else:
        lines.append("✓ No open security alerts")

    return "\n".join(lines)


def save_alerts_to_file(
    alerts: Dict[str, List[Dict]],
    output_dir: Optional[Path] = None,
    create_symlink: bool = True,
) -> Path:
    """
    Save alerts to a timestamped file.

    Args:
        alerts: Dictionary of alerts from check_github_alerts()
        output_dir: Directory to save file. Defaults to ./logs/security
        create_symlink: If True, create 'security-latest.txt' symlink

    Returns:
        Path to saved file
    """
    if output_dir is None:
        output_dir = Path.cwd() / "logs" / "security"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"security-{timestamp}.txt"

    report = format_alerts_report(alerts)
    output_file.write_text(report)

    # Create symlink to latest
    if create_symlink:
        latest_link = output_dir / "security-latest.txt"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(output_file.name)

    return output_file


def get_latest_alerts_file(security_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Get path to the latest security alerts file.

    Args:
        security_dir: Directory containing security files. Defaults to ./logs/security

    Returns:
        Path to latest file, or None if not found
    """
    if security_dir is None:
        security_dir = Path.cwd() / "logs" / "security"
    else:
        security_dir = Path(security_dir)

    latest_link = security_dir / "security-latest.txt"
    if latest_link.exists():
        return latest_link

    # Fallback: find most recent file
    files = sorted(security_dir.glob("security-*.txt"), reverse=True)
    return files[0] if files else None
