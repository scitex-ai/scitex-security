"""Tests for ``scitex-security domains`` (no network: ``candidates`` only).

``watch`` is exercised through the Python API with fakes in
tests/scitex_security/domains/test__watch.py; here we check the CLI wiring.
"""

import json

from click.testing import CliRunner

from scitex_security.cli import main


def test_domains_group_is_wired():
    # Arrange
    runner = CliRunner()
    # Act
    result = runner.invoke(main, ["domains", "--help"])
    # Assert
    assert "watch" in result.output


def test_candidates_json_lists_punycode():
    # Arrange
    runner = CliRunner()
    # Act
    result = runner.invoke(
        main, ["domains", "candidates", "example.ai", "--kind", "homoglyph", "--json"]
    )
    # Assert
    assert any(
        row["ascii"].startswith("xn--")
        for row in json.loads(result.output)["candidates"]
    )


def test_candidates_rejects_unknown_kind():
    # Arrange
    runner = CliRunner()
    # Act
    result = runner.invoke(main, ["domains", "candidates", "example.ai", "--kind", "x"])
    # Assert
    assert result.exit_code != 0
