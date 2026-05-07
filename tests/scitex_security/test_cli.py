#!/usr/bin/env python3
"""Tests for scitex_security.cli — Click-based CLI surface.

All subcommands depend on `ctx.obj` set by the parent `main` group, so we
invoke them through `main` (e.g. `["check", "owner/repo"]`) rather than
calling the subcommand functions directly.
"""

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from scitex_security.cli import main
from scitex_security.github import GitHubSecurityError

# --- check ----------------------------------------------------------------


class TestCheckCommand:
    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_no_alerts_exits_zero(self, mock_check, mock_format):
        mock_check.return_value = {"secrets": [], "dependabot": [], "code_scanning": []}
        mock_format.return_value = "No alerts"

        result = CliRunner().invoke(main, ["check", "owner/repo"])
        assert result.exit_code == 0

    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_open_alerts_exits_one(self, mock_check, mock_format):
        mock_check.return_value = {
            "secrets": [{"state": "open"}],
            "dependabot": [],
            "code_scanning": [],
        }
        mock_format.return_value = "Found alerts"

        result = CliRunner().invoke(main, ["check", "owner/repo"])
        assert result.exit_code == 1
        assert "Found 1 open security alert" in result.output

    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_passes_repo_argument(self, mock_check, mock_format):
        mock_check.return_value = {"secrets": [], "dependabot": [], "code_scanning": []}
        mock_format.return_value = "Report"

        CliRunner().invoke(main, ["check", "owner/repo"])
        mock_check.assert_called_once_with("owner/repo")

    @patch("scitex_security.cli.save_alerts_to_file")
    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_save_option_calls_save_function(self, mock_check, mock_format, mock_save):
        mock_check.return_value = {"secrets": [], "dependabot": [], "code_scanning": []}
        mock_format.return_value = "Report"
        mock_save.return_value = Path("/tmp/security-test.txt")

        CliRunner().invoke(main, ["check", "owner/repo", "--save"])
        mock_save.assert_called_once()

    @patch("scitex_security.cli.save_alerts_to_file")
    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_output_dir_passed_to_save(self, mock_check, mock_format, mock_save):
        mock_check.return_value = {"secrets": [], "dependabot": [], "code_scanning": []}
        mock_format.return_value = "Report"
        mock_save.return_value = Path("/custom/dir/security.txt")

        CliRunner().invoke(
            main, ["check", "owner/repo", "--save", "--output-dir", "/custom/dir"]
        )
        # save_alerts_to_file(alerts, out_path) — out_path is positional arg index 1
        assert mock_save.call_args[0][1] == Path("/custom/dir")

    @patch("scitex_security.cli.check_github_alerts")
    def test_github_security_error_exits_two(self, mock_check):
        # cli.py exits 2 on GitHubSecurityError; old (argparse) test expected 1.
        mock_check.side_effect = GitHubSecurityError("Auth failed")

        result = CliRunner().invoke(main, ["check", "owner/repo"])
        assert result.exit_code == 2
        assert "Auth failed" in result.output

    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_counts_multiple_alert_types(self, mock_check, mock_format):
        mock_check.return_value = {
            "secrets": [{"state": "open"}],
            "dependabot": [{"state": "open"}, {"state": "open"}],
            "code_scanning": [{"state": "open"}],
        }
        mock_format.return_value = "Report"

        result = CliRunner().invoke(main, ["check", "owner/repo"])
        assert result.exit_code == 1
        assert "Found 4 open security alert" in result.output

    @patch("scitex_security.cli.format_alerts_report")
    @patch("scitex_security.cli.check_github_alerts")
    def test_ignores_closed_alerts(self, mock_check, mock_format):
        mock_check.return_value = {
            "secrets": [{"state": "closed"}],
            "dependabot": [{"state": "dismissed"}],
            "code_scanning": [],
        }
        mock_format.return_value = "Report"

        result = CliRunner().invoke(main, ["check", "owner/repo"])
        assert result.exit_code == 0

    def test_dot_repo_translates_to_none(self):
        with (
            patch("scitex_security.cli.check_github_alerts") as mock_check,
            patch("scitex_security.cli.format_alerts_report") as mock_format,
        ):
            mock_check.return_value = {
                "secrets": [],
                "dependabot": [],
                "code_scanning": [],
            }
            mock_format.return_value = "ok"

            CliRunner().invoke(main, ["check", "."])
            mock_check.assert_called_once_with(None)


# --- show-latest ----------------------------------------------------------


class TestLatestCommand:
    @patch("scitex_security.cli.get_latest_alerts_file")
    def test_displays_file_content(self, mock_get_latest, tmp_path):
        test_file = tmp_path / "security-latest.txt"
        test_file.write_text("Security Report Content")
        mock_get_latest.return_value = test_file

        result = CliRunner().invoke(
            main, ["show-latest", "--security-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Security Report Content" in result.output

    @patch("scitex_security.cli.get_latest_alerts_file")
    def test_no_file_exits_one(self, mock_get_latest):
        mock_get_latest.return_value = None

        result = CliRunner().invoke(main, ["show-latest"])
        assert result.exit_code == 1

    @patch("scitex_security.cli.get_latest_alerts_file")
    def test_passes_security_dir(self, mock_get_latest, tmp_path):
        mock_get_latest.return_value = None

        CliRunner().invoke(main, ["show-latest", "--security-dir", str(tmp_path)])
        mock_get_latest.assert_called_once_with(Path(str(tmp_path)))

    @patch("scitex_security.cli.get_latest_alerts_file")
    def test_exception_exits_two(self, mock_get_latest):
        # cli.py exits 2 on generic exceptions; old (argparse) test expected 1.
        mock_get_latest.side_effect = Exception("File error")

        result = CliRunner().invoke(main, ["show-latest"])
        assert result.exit_code == 2


# --- main (root group) ----------------------------------------------------


class TestMain:
    def test_no_command_prints_help(self):
        # Root group is invoke_without_command=True, prints help, exit 0.
        result = CliRunner().invoke(main, [])
        assert result.exit_code == 0
        assert "scitex-security" in result.output

    def test_help_recursive_flag(self):
        result = CliRunner().invoke(main, ["--help-recursive"])
        assert result.exit_code == 0
        assert "check" in result.output
        assert "show-latest" in result.output


if __name__ == "__main__":
    import os

    import pytest

    pytest.main([os.path.abspath(__file__)])
