#!/usr/bin/env python3
# File: tests/scitex_security/test_github.py

"""Tests for scitex_security.github module.

No mocks (PA-306): all collaborators are passed in via the keyword
injection parameters added to the production functions, with real
hand-rolled fakes defined in ``tests/_helpers.py``. Module-attribute
overrides (e.g. on ``scitex_security.github``) use the
``swap_attrs`` context manager — pure attribute assignment, no
``unittest.mock`` and no ``monkeypatch``.

One assertion per test (PA-307 STX-TQ007). Tests follow the AAA
marker convention (PA-307 STX-TQ002) and descriptive 3+ word names
(PA-307 STX-TQ003).
"""

import json
import os

import pytest

from _helpers import (
    FakeAlertFn,
    FakeAuthCheck,
    FakeGhRunner,
    FakeRun,
    make_called_process_error,
    swap_attrs,
)
from scitex_security import github as github_module
from scitex_security.github import (
    GitHubSecurityError,
    _run_gh_command,
    check_gh_auth,
    check_github_alerts,
    format_alerts_report,
    get_code_scanning_alerts,
    get_dependabot_alerts,
    get_latest_alerts_file,
    get_secret_alerts,
    save_alerts_to_file,
)

# ---------------------------------------------------------------------------
# GitHubSecurityError
# ---------------------------------------------------------------------------


class TestGitHubSecurityError:
    """Tests for the GitHubSecurityError exception class."""

    def test_error_can_be_raised_with_message(self):
        # Arrange
        ctx = pytest.raises(GitHubSecurityError)
        # Act
        # (the raise is performed under the Assert context manager,
        # per the test-quality skill's `pytest.raises` AAA template)
        # Assert
        with ctx:
            raise GitHubSecurityError("Test error")

    def test_error_message_preserved_in_match(self):
        # Arrange
        ctx = pytest.raises(GitHubSecurityError, match="Custom error message")
        # Act
        # Assert
        with ctx:
            raise GitHubSecurityError("Custom error message")

    def test_error_class_inherits_from_builtin_exception(self):
        # Arrange
        error = GitHubSecurityError("test")
        # Act
        is_exc = isinstance(error, Exception)
        # Assert
        assert is_exc


# ---------------------------------------------------------------------------
# _run_gh_command
# ---------------------------------------------------------------------------


class TestRunGhCommand:
    """Tests for ``_run_gh_command``."""

    def test_returns_stdout_from_successful_run(self):
        # Arrange
        fake_run = FakeRun(stdout="command output", returncode=0)
        # Act
        result = _run_gh_command(["auth", "status"], run=fake_run)
        # Assert
        assert result == "command output"

    def test_passes_gh_prefix_to_subprocess(self):
        # Arrange
        fake_run = FakeRun(stdout="output", returncode=0)
        # Act
        _run_gh_command(["api", "/repos/owner/repo"], run=fake_run)
        # Assert
        assert fake_run.calls[0][0] == ("gh", "api", "/repos/owner/repo")

    def test_called_process_error_raises_security_error(self):
        # Arrange
        err = make_called_process_error(returncode=1, stderr="error message")
        fake_run = FakeRun(side_effect=err)
        ctx = pytest.raises(GitHubSecurityError, match="GitHub CLI error")
        # Act
        # Assert
        with ctx:
            _run_gh_command(["auth", "status"], run=fake_run)

    def test_file_not_found_raises_security_error(self):
        # Arrange
        fake_run = FakeRun(side_effect=FileNotFoundError("gh not found"))
        ctx = pytest.raises(GitHubSecurityError, match="GitHub CLI .* not found")
        # Act
        # Assert
        with ctx:
            _run_gh_command(["auth", "status"], run=fake_run)


# ---------------------------------------------------------------------------
# check_gh_auth
# ---------------------------------------------------------------------------


class TestCheckGhAuth:
    """Tests for ``check_gh_auth``."""

    def test_authenticated_user_returns_true(self):
        # Arrange
        fake_run = FakeRun(returncode=0)
        # Act
        result = check_gh_auth(run=fake_run)
        # Assert
        assert result is True

    def test_called_process_error_returns_false(self):
        # Arrange
        fake_run = FakeRun(side_effect=make_called_process_error())
        # Act
        result = check_gh_auth(run=fake_run)
        # Assert
        assert result is False

    def test_file_not_found_returns_false(self):
        # Arrange
        fake_run = FakeRun(side_effect=FileNotFoundError())
        # Act
        result = check_gh_auth(run=fake_run)
        # Assert
        assert result is False


# ---------------------------------------------------------------------------
# get_secret_alerts
# ---------------------------------------------------------------------------


class TestGetSecretAlerts:
    """Tests for ``get_secret_alerts``."""

    def test_returns_single_parsed_alert(self):
        # Arrange
        alert_data = {"state": "open", "secretType": "API Key", "url": "http://test"}
        fake = FakeGhRunner(return_value=json.dumps(alert_data))
        # Act
        alerts = get_secret_alerts("owner/repo", gh_runner=fake)
        # Assert
        assert alerts == [alert_data]

    def test_empty_output_returns_empty_list(self):
        # Arrange
        fake = FakeGhRunner(return_value="")
        # Act
        alerts = get_secret_alerts(gh_runner=fake)
        # Assert
        assert alerts == []

    def test_whitespace_only_output_returns_empty_list(self):
        # Arrange
        fake = FakeGhRunner(return_value="   \n   ")
        # Act
        alerts = get_secret_alerts(gh_runner=fake)
        # Assert
        assert alerts == []

    def test_parses_multiple_line_delimited_alerts(self):
        # Arrange
        alert1 = json.dumps({"state": "open", "secretType": "Key1", "url": "url1"})
        alert2 = json.dumps({"state": "closed", "secretType": "Key2", "url": "url2"})
        fake = FakeGhRunner(return_value=f"{alert1}\n{alert2}")
        # Act
        alerts = get_secret_alerts(gh_runner=fake)
        # Assert
        assert len(alerts) == 2

    def test_security_error_returns_empty_list(self):
        # Arrange
        fake = FakeGhRunner(side_effect=GitHubSecurityError("API error"))
        # Act
        alerts = get_secret_alerts(gh_runner=fake)
        # Assert
        assert alerts == []

    def test_custom_repo_in_api_path(self):
        # Arrange
        fake = FakeGhRunner(return_value="")
        # Act
        get_secret_alerts("myorg/myrepo", gh_runner=fake)
        # Assert
        assert "/repos/myorg/myrepo/" in fake.calls[0][1]


# ---------------------------------------------------------------------------
# get_dependabot_alerts
# ---------------------------------------------------------------------------


class TestGetDependabotAlerts:
    """Tests for ``get_dependabot_alerts``."""

    def test_returns_parsed_severity_field(self):
        # Arrange
        alert_data = {
            "state": "open",
            "severity": "high",
            "summary": "Vulnerability",
            "package": "test-pkg",
            "cve": "CVE-2024-1234",
            "url": "http://test",
            "created_at": "2024-01-01",
        }
        fake = FakeGhRunner(return_value=json.dumps(alert_data))
        # Act
        alerts = get_dependabot_alerts(gh_runner=fake)
        # Assert
        assert alerts[0]["severity"] == "high"

    def test_empty_output_returns_empty_dependabot_list(self):
        # Arrange
        fake = FakeGhRunner(return_value="")
        # Act
        alerts = get_dependabot_alerts(gh_runner=fake)
        # Assert
        assert alerts == []

    def test_security_error_returns_empty_dependabot_list(self):
        # Arrange
        fake = FakeGhRunner(side_effect=GitHubSecurityError("error"))
        # Act
        alerts = get_dependabot_alerts(gh_runner=fake)
        # Assert
        assert alerts == []

    def test_custom_repo_in_dependabot_path(self):
        # Arrange
        fake = FakeGhRunner(return_value="")
        # Act
        get_dependabot_alerts("org/repo", gh_runner=fake)
        # Assert
        assert "/repos/org/repo/" in fake.calls[0][1]


# ---------------------------------------------------------------------------
# get_code_scanning_alerts
# ---------------------------------------------------------------------------


class TestGetCodeScanningAlerts:
    """Tests for ``get_code_scanning_alerts``."""

    def test_returns_parsed_description_field(self):
        # Arrange
        alert_data = {
            "state": "open",
            "severity": "error",
            "description": "SQL Injection",
            "location": "app.py",
            "line": 42,
            "url": "http://test",
            "created_at": "2024-01-01",
        }
        fake = FakeGhRunner(return_value=json.dumps(alert_data))
        # Act
        alerts = get_code_scanning_alerts(gh_runner=fake)
        # Assert
        assert alerts[0]["description"] == "SQL Injection"

    def test_empty_output_returns_empty_code_scanning_list(self):
        # Arrange
        fake = FakeGhRunner(return_value="")
        # Act
        alerts = get_code_scanning_alerts(gh_runner=fake)
        # Assert
        assert alerts == []

    def test_security_error_returns_empty_code_scanning_list(self):
        # Arrange
        fake = FakeGhRunner(side_effect=GitHubSecurityError("error"))
        # Act
        alerts = get_code_scanning_alerts(gh_runner=fake)
        # Assert
        assert alerts == []


# ---------------------------------------------------------------------------
# check_github_alerts
# ---------------------------------------------------------------------------


class TestCheckGithubAlerts:
    """Tests for ``check_github_alerts``."""

    def test_unauthenticated_raises_security_error(self):
        # Arrange
        auth = FakeAuthCheck(return_value=False)
        ctx = pytest.raises(GitHubSecurityError, match="Not authenticated")
        # Act
        # Assert
        with ctx:
            check_github_alerts(auth_check=auth)

    def _build_authenticated_alerts(self, repo=None):
        """Build a populated ``check_github_alerts`` result for the
        success-path tests below. Shared by several tests, each of
        which then asserts a single property of the returned dict."""
        auth = FakeAuthCheck(return_value=True)
        secrets = FakeAlertFn(return_value=[{"type": "secret"}])
        dependabot = FakeAlertFn(return_value=[{"type": "dependabot"}])
        code = FakeAlertFn(return_value=[{"type": "code"}])
        result = check_github_alerts(
            repo,
            auth_check=auth,
            secrets_fn=secrets,
            dependabot_fn=dependabot,
            code_scanning_fn=code,
        )
        return result, secrets, dependabot, code

    def test_result_contains_secrets_key(self):
        # Arrange
        result, *_ = self._build_authenticated_alerts()
        # Act
        keys = result.keys()
        # Assert
        assert "secrets" in keys

    def test_result_contains_dependabot_key(self):
        # Arrange
        result, *_ = self._build_authenticated_alerts()
        # Act
        keys = result.keys()
        # Assert
        assert "dependabot" in keys

    def test_result_contains_code_scanning_key(self):
        # Arrange
        result, *_ = self._build_authenticated_alerts()
        # Act
        keys = result.keys()
        # Assert
        assert "code_scanning" in keys

    def test_result_carries_secrets_list_length(self):
        # Arrange
        result, *_ = self._build_authenticated_alerts()
        # Act
        n = len(result["secrets"])
        # Assert
        assert n == 1

    def test_repo_argument_passed_to_secrets_fn(self):
        # Arrange
        _, secrets, _, _ = self._build_authenticated_alerts("test/repo")
        # Act
        last_call = secrets.calls[-1]
        # Assert
        assert last_call == "test/repo"

    def test_repo_argument_passed_to_dependabot_fn(self):
        # Arrange
        _, _, dependabot, _ = self._build_authenticated_alerts("test/repo")
        # Act
        last_call = dependabot.calls[-1]
        # Assert
        assert last_call == "test/repo"

    def test_repo_argument_passed_to_code_scanning_fn(self):
        # Arrange
        _, _, _, code = self._build_authenticated_alerts("test/repo")
        # Act
        last_call = code.calls[-1]
        # Assert
        assert last_call == "test/repo"


# ---------------------------------------------------------------------------
# format_alerts_report
# ---------------------------------------------------------------------------


class TestFormatAlertsReport:
    """Tests for ``format_alerts_report`` (pure function — no fakes
    needed)."""

    @staticmethod
    def _empty():
        return {"secrets": [], "dependabot": [], "code_scanning": []}

    def test_empty_report_includes_header_title(self):
        # Arrange
        alerts = self._empty()
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "GitHub Security Alerts Report" in report

    def test_empty_report_announces_no_secrets(self):
        # Arrange
        alerts = self._empty()
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "No open secret scanning alerts" in report

    def test_empty_report_announces_no_dependabot(self):
        # Arrange
        alerts = self._empty()
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "No open Dependabot alerts" in report

    def test_empty_report_announces_no_code_scanning(self):
        # Arrange
        alerts = self._empty()
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "No open code scanning alerts" in report

    def test_empty_report_total_is_zero(self):
        # Arrange
        alerts = self._empty()
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "Total open alerts: 0" in report

    def test_empty_report_states_no_open_alerts(self):
        # Arrange
        alerts = self._empty()
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "No open security alerts" in report

    def test_open_secret_alert_name_appears_in_report(self):
        # Arrange
        alerts = {
            "secrets": [
                {
                    "state": "open",
                    "secretType": "AWS Key",
                    "url": "http://example.com",
                    "path": "config.py",
                    "line": 10,
                    "createdAt": "2024-01-01",
                }
            ],
            "dependabot": [],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "AWS Key" in report

    def test_open_secret_alert_location_appears_in_report(self):
        # Arrange
        alerts = {
            "secrets": [
                {
                    "state": "open",
                    "secretType": "AWS Key",
                    "url": "http://example.com",
                    "path": "config.py",
                    "line": 10,
                    "createdAt": "2024-01-01",
                }
            ],
            "dependabot": [],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "config.py:10" in report

    def test_open_secret_alert_increments_total(self):
        # Arrange
        alerts = {
            "secrets": [
                {
                    "state": "open",
                    "secretType": "AWS Key",
                    "url": "http://example.com",
                    "path": "config.py",
                    "line": 10,
                    "createdAt": "2024-01-01",
                }
            ],
            "dependabot": [],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "Total open alerts: 1" in report

    def test_open_dependabot_severity_uppercased_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [
                {
                    "state": "open",
                    "severity": "high",
                    "summary": "XSS vulnerability",
                    "package": "lodash",
                    "cve": "CVE-2024-9999",
                    "url": "http://example.com",
                }
            ],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "HIGH" in report

    def test_open_dependabot_summary_appears_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [
                {
                    "state": "open",
                    "severity": "high",
                    "summary": "XSS vulnerability",
                    "package": "lodash",
                    "cve": "CVE-2024-9999",
                    "url": "http://example.com",
                }
            ],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "XSS vulnerability" in report

    def test_open_dependabot_package_name_appears_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [
                {
                    "state": "open",
                    "severity": "high",
                    "summary": "XSS vulnerability",
                    "package": "lodash",
                    "cve": "CVE-2024-9999",
                    "url": "http://example.com",
                }
            ],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "lodash" in report

    def test_open_dependabot_cve_appears_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [
                {
                    "state": "open",
                    "severity": "high",
                    "summary": "XSS vulnerability",
                    "package": "lodash",
                    "cve": "CVE-2024-9999",
                    "url": "http://example.com",
                }
            ],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "CVE-2024-9999" in report

    def test_open_code_scanning_severity_uppercased_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [],
            "code_scanning": [
                {
                    "state": "open",
                    "severity": "error",
                    "description": "SQL Injection vulnerability",
                    "location": "app.py",
                    "line": 50,
                    "url": "http://example.com",
                }
            ],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "ERROR" in report

    def test_open_code_scanning_description_appears_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [],
            "code_scanning": [
                {
                    "state": "open",
                    "severity": "error",
                    "description": "SQL Injection vulnerability",
                    "location": "app.py",
                    "line": 50,
                    "url": "http://example.com",
                }
            ],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "SQL Injection" in report

    def test_open_code_scanning_location_with_line_in_report(self):
        # Arrange
        alerts = {
            "secrets": [],
            "dependabot": [],
            "code_scanning": [
                {
                    "state": "open",
                    "severity": "error",
                    "description": "SQL Injection vulnerability",
                    "location": "app.py",
                    "line": 50,
                    "url": "http://example.com",
                }
            ],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "app.py:50" in report

    def test_closed_alerts_excluded_from_total(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "closed", "secretType": "Key", "url": "http://x"}],
            "dependabot": [],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "Total open alerts: 0" in report

    def test_missing_optional_fields_still_total_alerts(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "open", "secretType": "Key", "url": "http://x"}],
            "dependabot": [
                {
                    "state": "open",
                    "summary": "Bug",
                    "package": "pkg",
                    "url": "http://x",
                }
            ],
            "code_scanning": [
                {"state": "open", "description": "Issue", "url": "http://x"}
            ],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "Total open alerts: 3" in report

    def test_open_alerts_trigger_action_required_banner(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "open", "secretType": "Key", "url": "http://x"}],
            "dependabot": [],
            "code_scanning": [],
        }
        # Act
        report = format_alerts_report(alerts)
        # Assert
        assert "ACTION REQUIRED" in report


# ---------------------------------------------------------------------------
# save_alerts_to_file
# ---------------------------------------------------------------------------


class TestSaveAlertsToFile:
    """Tests for ``save_alerts_to_file``."""

    @staticmethod
    def _empty():
        return {"secrets": [], "dependabot": [], "code_scanning": []}

    def test_saved_file_is_created_on_disk(self, tmp_path):
        # Arrange
        alerts = self._empty()
        # Act
        output_file = save_alerts_to_file(alerts, tmp_path)
        # Assert
        assert output_file.exists()

    def test_saved_file_contains_report_header(self, tmp_path):
        # Arrange
        alerts = self._empty()
        # Act
        output_file = save_alerts_to_file(alerts, tmp_path)
        # Assert
        assert "GitHub Security Alerts Report" in output_file.read_text()

    def test_creates_nested_output_directory_when_missing(self, tmp_path):
        # Arrange
        output_dir = tmp_path / "new" / "nested" / "dir"
        alerts = self._empty()
        # Act
        save_alerts_to_file(alerts, output_dir)
        # Assert
        assert output_dir.exists()

    def test_creates_security_latest_symlink_in_output_dir(self, tmp_path):
        # Arrange
        alerts = self._empty()
        # Act
        save_alerts_to_file(alerts, tmp_path)
        # Assert
        assert (tmp_path / "security-latest.txt").is_symlink()

    def test_latest_symlink_points_to_most_recent_save(self, tmp_path):
        # Arrange
        alerts = self._empty()
        save_alerts_to_file(alerts, tmp_path)
        # Act
        second_file = save_alerts_to_file(alerts, tmp_path)
        # Assert
        assert (tmp_path / "security-latest.txt").resolve() == second_file

    def test_no_symlink_when_create_symlink_false(self, tmp_path):
        # Arrange
        alerts = self._empty()
        # Act
        save_alerts_to_file(alerts, tmp_path, create_symlink=False)
        # Assert
        assert not (tmp_path / "security-latest.txt").exists()

    def test_filename_starts_with_security_prefix(self, tmp_path):
        # Arrange
        alerts = self._empty()
        # Act
        output_file = save_alerts_to_file(alerts, tmp_path)
        # Assert
        assert output_file.name.startswith("security-")

    def test_filename_has_txt_suffix(self, tmp_path):
        # Arrange
        alerts = self._empty()
        # Act
        output_file = save_alerts_to_file(alerts, tmp_path)
        # Assert
        assert output_file.suffix == ".txt"


# ---------------------------------------------------------------------------
# get_latest_alerts_file
# ---------------------------------------------------------------------------


class TestGetLatestAlertsFile:
    """Tests for ``get_latest_alerts_file``."""

    def test_empty_directory_returns_none(self, tmp_path):
        # Arrange
        target_dir = tmp_path
        # Act
        result = get_latest_alerts_file(target_dir)
        # Assert
        assert result is None

    def test_returns_security_latest_symlink_when_present(self, tmp_path):
        # Arrange
        real_file = tmp_path / "security-20240101_120000.txt"
        real_file.write_text("test content")
        latest_link = tmp_path / "security-latest.txt"
        latest_link.symlink_to(real_file.name)
        # Act
        result = get_latest_alerts_file(tmp_path)
        # Assert
        assert result == latest_link

    def test_returns_most_recent_filename_without_symlink(self, tmp_path):
        # Arrange
        (tmp_path / "security-20240101_100000.txt").write_text("old")
        (tmp_path / "security-20240102_100000.txt").write_text("middle")
        (tmp_path / "security-20240103_100000.txt").write_text("newest")
        # Act
        result = get_latest_alerts_file(tmp_path)
        # Assert
        assert result.name == "security-20240103_100000.txt"

    def test_directory_with_only_non_security_files_returns_none(self, tmp_path):
        # Arrange
        (tmp_path / "other-file.txt").write_text("not a security file")
        # Act
        result = get_latest_alerts_file(tmp_path)
        # Assert
        assert result is None

    def test_default_directory_used_when_argument_is_none(self, tmp_path):
        # Arrange — change CWD to an empty dir, with try/finally restore
        # so we never leak global state. No ``monkeypatch`` (PA-306).
        previous_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            # Act
            result = get_latest_alerts_file(None)
        finally:
            os.chdir(previous_cwd)
        # Assert
        assert result is None


# ---------------------------------------------------------------------------
# Module-attribute swap smoke test (defensive: confirms swap_attrs works)
# ---------------------------------------------------------------------------


class TestSwapAttrs:
    """A defensive test that the ``swap_attrs`` helper actually
    restores the original attribute even when the body raises. Other
    tests rely on this property."""

    def test_swap_attrs_restores_original_after_exception(self):
        # Arrange
        original = github_module.check_gh_auth

        def _sentinel():
            return "sentinel"

        # Act
        try:
            with swap_attrs(github_module, check_gh_auth=_sentinel):
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        restored = github_module.check_gh_auth
        # Assert
        assert restored is original


if __name__ == "__main__":
    import os

    pytest.main([os.path.abspath(__file__)])
