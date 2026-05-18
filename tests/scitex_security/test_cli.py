#!/usr/bin/env python3
"""Tests for scitex_security.cli — Click-based CLI surface.

All subcommands depend on ``ctx.obj`` set by the parent ``main`` group,
so we invoke them through ``main`` (e.g. ``["check", "owner/repo"]``)
rather than calling the subcommand functions directly.

No mocks (PA-306): the CLI imports its collaborators at module load
time via ``from .github import ...``, so we swap them on the cli
module namespace with the ``swap_attrs`` context manager from
``tests/_helpers.py``. Each test asserts exactly one property.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from _helpers import (
    FakeAlertFn,
    FakeFormatReport,
    FakeLatestPath,
    FakeSavePath,
    swap_attrs,
)
from scitex_security import cli as cli_module
from scitex_security.cli import main
from scitex_security.github import GitHubSecurityError


def _no_alerts():
    return {"secrets": [], "dependabot": [], "code_scanning": []}


# ---------------------------------------------------------------------------
# main check ...
# ---------------------------------------------------------------------------


class TestCheckCommand:
    """Tests for the ``check`` subcommand."""

    def test_no_alerts_path_exits_zero(self):
        # Arrange
        check_fn = FakeAlertFn(return_value=_no_alerts())
        fmt_fn = FakeFormatReport(return_value="No alerts")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert result.exit_code == 0

    def test_open_alerts_path_exits_one(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "open"}],
            "dependabot": [],
            "code_scanning": [],
        }
        check_fn = FakeAlertFn(return_value=alerts)
        fmt_fn = FakeFormatReport(return_value="Found alerts")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert result.exit_code == 1

    def test_open_alerts_message_reports_count(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "open"}],
            "dependabot": [],
            "code_scanning": [],
        }
        check_fn = FakeAlertFn(return_value=alerts)
        fmt_fn = FakeFormatReport(return_value="Found alerts")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert "Found 1 open security alert" in result.output

    def test_repo_argument_is_forwarded_to_check(self):
        # Arrange
        check_fn = FakeAlertFn(return_value=_no_alerts())
        fmt_fn = FakeFormatReport(return_value="Report")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert check_fn.calls == ["owner/repo"]

    def test_save_flag_invokes_save_alerts_function(self):
        # Arrange
        check_fn = FakeAlertFn(return_value=_no_alerts())
        fmt_fn = FakeFormatReport(return_value="Report")
        save_fn = FakeSavePath(return_value=Path("/tmp/security-test.txt"))
        # Act
        with swap_attrs(
            cli_module,
            check_github_alerts=check_fn,
            format_alerts_report=fmt_fn,
            save_alerts_to_file=save_fn,
        ):
            CliRunner().invoke(main, ["check", "owner/repo", "--save"])
        # Assert
        assert len(save_fn.calls) == 1

    def test_output_dir_option_forwarded_to_save(self):
        # Arrange
        check_fn = FakeAlertFn(return_value=_no_alerts())
        fmt_fn = FakeFormatReport(return_value="Report")
        save_fn = FakeSavePath(return_value=Path("/custom/dir/security.txt"))
        # Act
        with swap_attrs(
            cli_module,
            check_github_alerts=check_fn,
            format_alerts_report=fmt_fn,
            save_alerts_to_file=save_fn,
        ):
            CliRunner().invoke(
                main,
                ["check", "owner/repo", "--save", "--output-dir", "/custom/dir"],
            )
        # Assert — save_fn signature: (alerts, output_dir, create_symlink)
        assert save_fn.calls[0][1] == Path("/custom/dir")

    def test_github_security_error_exits_two(self):
        # Arrange
        check_fn = FakeAlertFn()

        def _raise(repo=None):  # honest fake — matches FakeAlertFn shape
            check_fn.calls.append(repo)
            raise GitHubSecurityError("Auth failed")

        # Act
        with swap_attrs(cli_module, check_github_alerts=_raise):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert result.exit_code == 2

    def test_github_security_error_message_in_stderr(self):
        # Arrange
        def _raise(repo=None):
            raise GitHubSecurityError("Auth failed")

        # Act
        with swap_attrs(cli_module, check_github_alerts=_raise):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert "Auth failed" in result.output

    def test_counts_open_alerts_across_all_categories(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "open"}],
            "dependabot": [{"state": "open"}, {"state": "open"}],
            "code_scanning": [{"state": "open"}],
        }
        check_fn = FakeAlertFn(return_value=alerts)
        fmt_fn = FakeFormatReport(return_value="Report")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert "Found 4 open security alert" in result.output

    def test_closed_alerts_yield_zero_exit_code(self):
        # Arrange
        alerts = {
            "secrets": [{"state": "closed"}],
            "dependabot": [{"state": "dismissed"}],
            "code_scanning": [],
        }
        check_fn = FakeAlertFn(return_value=alerts)
        fmt_fn = FakeFormatReport(return_value="Report")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            result = CliRunner().invoke(main, ["check", "owner/repo"])
        # Assert
        assert result.exit_code == 0

    def test_dot_repo_translates_to_none_argument(self):
        # Arrange
        check_fn = FakeAlertFn(return_value=_no_alerts())
        fmt_fn = FakeFormatReport(return_value="ok")
        # Act
        with swap_attrs(
            cli_module, check_github_alerts=check_fn, format_alerts_report=fmt_fn
        ):
            CliRunner().invoke(main, ["check", "."])
        # Assert
        assert check_fn.calls == [None]


# ---------------------------------------------------------------------------
# main show-latest ...
# ---------------------------------------------------------------------------


class TestShowLatestCommand:
    """Tests for the ``show-latest`` subcommand."""

    def test_displays_content_of_latest_file(self, tmp_path):
        # Arrange
        test_file = tmp_path / "security-latest.txt"
        test_file.write_text("Security Report Content")
        latest_fn = FakeLatestPath(return_value=test_file)
        # Act
        with swap_attrs(cli_module, get_latest_alerts_file=latest_fn):
            result = CliRunner().invoke(
                main, ["show-latest", "--security-dir", str(tmp_path)]
            )
        # Assert
        assert "Security Report Content" in result.output

    def test_missing_file_exits_one(self):
        # Arrange
        latest_fn = FakeLatestPath(return_value=None)
        # Act
        with swap_attrs(cli_module, get_latest_alerts_file=latest_fn):
            result = CliRunner().invoke(main, ["show-latest"])
        # Assert
        assert result.exit_code == 1

    def test_security_dir_option_forwarded_to_lookup(self, tmp_path):
        # Arrange
        latest_fn = FakeLatestPath(return_value=None)
        # Act
        with swap_attrs(cli_module, get_latest_alerts_file=latest_fn):
            CliRunner().invoke(
                main, ["show-latest", "--security-dir", str(tmp_path)]
            )
        # Assert
        assert latest_fn.calls == [Path(str(tmp_path))]

    def test_unexpected_exception_exits_two(self):
        # Arrange
        latest_fn = FakeLatestPath(side_effect=Exception("File error"))
        # Act
        with swap_attrs(cli_module, get_latest_alerts_file=latest_fn):
            result = CliRunner().invoke(main, ["show-latest"])
        # Assert
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# main (root group)
# ---------------------------------------------------------------------------


class TestMainGroup:
    """Tests for the root ``main`` Click group."""

    def test_no_subcommand_exits_zero_after_help(self):
        # Arrange
        runner = CliRunner()
        # Act
        result = runner.invoke(main, [])
        # Assert
        assert result.exit_code == 0

    def test_no_subcommand_help_mentions_program_name(self):
        # Arrange
        runner = CliRunner()
        # Act
        result = runner.invoke(main, [])
        # Assert
        assert "scitex-security" in result.output

    def test_help_recursive_flag_exits_zero(self):
        # Arrange
        runner = CliRunner()
        # Act
        result = runner.invoke(main, ["--help-recursive"])
        # Assert
        assert result.exit_code == 0

    def test_help_recursive_includes_check_subcommand(self):
        # Arrange
        runner = CliRunner()
        # Act
        result = runner.invoke(main, ["--help-recursive"])
        # Assert
        assert "check" in result.output

    def test_help_recursive_includes_show_latest_subcommand(self):
        # Arrange
        runner = CliRunner()
        # Act
        result = runner.invoke(main, ["--help-recursive"])
        # Assert
        assert "show-latest" in result.output


if __name__ == "__main__":
    import os

    pytest.main([os.path.abspath(__file__)])
