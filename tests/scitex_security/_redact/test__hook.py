"""Tests for the Claude Code PostToolUse adapter (real gitleaks, fake secrets)."""

import pytest
from _secret_fakes import (
    FAKE_GITHUB_PAT,
    FAKE_UNFORMATTED_VALUE,
    GITLEAKS,
    GITLEAKS_MISSING_REASON,
    NORMAL_TEXT,
    bash_event,
    scrubbed_environ,
)

from scitex_security._redact._core import MASK, Redactor, build_redactor
from scitex_security._redact._hook import (
    CLAUDE_TOOL_ADAPTERS,
    handle_claude_post_tool_use,
)

needs_gitleaks = pytest.mark.skipif(GITLEAKS is None, reason=GITLEAKS_MISSING_REASON)


def _redactor():
    return build_redactor(environ=scrubbed_environ())


@needs_gitleaks
def test_bash_stdout_secret_is_replaced_in_updated_tool_output():
    # Arrange
    event = bash_event(f"got: {FAKE_GITHUB_PAT}\n")
    # Act
    out = handle_claude_post_tool_use(event, _redactor())
    # Assert
    assert out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == f"got: {MASK}\n"


@needs_gitleaks
def test_bash_stderr_secret_is_replaced_in_updated_tool_output():
    # Arrange
    event = bash_event("ok\n", stderr=f"curl: header {FAKE_GITHUB_PAT}")
    # Act
    out = handle_claude_post_tool_use(event, _redactor())
    # Assert
    assert (
        out["hookSpecificOutput"]["updatedToolOutput"]["stderr"]
        == f"curl: header {MASK}"
    )


@needs_gitleaks
def test_updated_tool_output_keeps_bash_response_flags():
    # Arrange
    event = bash_event(FAKE_GITHUB_PAT)
    event["tool_response"]["interrupted"] = True
    # Act
    out = handle_claude_post_tool_use(event, _redactor())
    # Assert
    assert out["hookSpecificOutput"]["updatedToolOutput"]["interrupted"] is True


@needs_gitleaks
def test_redacted_output_names_the_post_tool_use_event():
    # Arrange
    event = bash_event(FAKE_GITHUB_PAT)
    # Act
    out = handle_claude_post_tool_use(event, _redactor())
    # Assert
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"


@needs_gitleaks
def test_clean_bash_output_produces_no_hook_output():
    # Arrange
    event = bash_event(NORMAL_TEXT)
    # Act
    out = handle_claude_post_tool_use(event, _redactor())
    # Assert
    assert out is None


def test_unregistered_tool_type_is_left_alone():
    # Arrange
    event = bash_event(FAKE_GITHUB_PAT, tool_name="NotARegisteredTool")
    # Act
    out = handle_claude_post_tool_use(event, Redactor(gitleaks_bin=None))
    # Assert
    assert out is None


def test_only_bash_adapter_is_registered_today():
    # Arrange
    registered = CLAUDE_TOOL_ADAPTERS
    # Act
    names = sorted(registered)
    # Assert
    assert names == ["Bash"]


def test_gitleaks_absent_clean_output_warns_via_additional_context():
    # Arrange
    event = bash_event("plain output")
    # Act
    out = handle_claude_post_tool_use(event, Redactor(gitleaks_bin=None))
    # Assert
    assert "gitleaks not found" in out["hookSpecificOutput"]["additionalContext"]


def test_gitleaks_absent_clean_output_does_not_rewrite_tool_output():
    # Arrange
    event = bash_event("plain output")
    # Act
    out = handle_claude_post_tool_use(event, Redactor(gitleaks_bin=None))
    # Assert
    assert "updatedToolOutput" not in out["hookSpecificOutput"]


def test_gitleaks_absent_exact_env_value_is_still_redacted():
    # Arrange
    event = bash_event(f"value {FAKE_UNFORMATTED_VALUE}")
    redactor = Redactor(gitleaks_bin=None, env_values={FAKE_UNFORMATTED_VALUE})
    # Act
    out = handle_claude_post_tool_use(event, redactor)
    # Assert
    assert out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == f"value {MASK}"


def test_gitleaks_absent_redaction_notes_the_degradation():
    # Arrange
    event = bash_event(f"value {FAKE_UNFORMATTED_VALUE}")
    redactor = Redactor(gitleaks_bin=None, env_values={FAKE_UNFORMATTED_VALUE})
    # Act
    out = handle_claude_post_tool_use(event, redactor)
    # Assert
    assert "gitleaks not found" in out["hookSpecificOutput"]["additionalContext"]
