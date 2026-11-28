#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_redact/_hook.py

"""Agent-hook adapters around :mod:`scitex_security._redact._core`.

``claude-post-tool-use`` implements the Claude Code PostToolUse contract:
the hook event JSON arrives on stdin; when a secret was masked the hook
prints ``hookSpecificOutput.updatedToolOutput`` (what the model and the
session transcript see from then on). ``updatedToolOutput`` does not undo
the tool call and does not scrub telemetry that already captured the raw
output -- it closes the transcript exposure, the durable half.

Each tool type has its own :class:`ToolOutputAdapter` (which response
fields carry text, and how to rebuild the response). Only ``Bash`` is
registered today; Read / Grep / WebFetch adapters slot into
:data:`CLAUDE_TOOL_ADAPTERS` without touching the dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

from ._core import Redactor, unique

#: Hook name accepted by ``scitex-security redact --hook``.
HOOK_CLAUDE_POST_TOOL_USE = "claude-post-tool-use"

_HOOK_EVENT = "PostToolUse"
_CONTEXT_REDACTED = (
    "A secret-shaped value in this tool's output was redacted by "
    "`scitex-security redact` before being added to the conversation. If you "
    "need the real value for a legitimate reason, confirm the variable is set "
    "without printing it, or ask the operator directly -- do not try to work "
    "around the redaction."
)


@dataclass(frozen=True)
class ToolOutputAdapter:
    """How to redact one tool type's ``tool_response``.

    Attributes
    ----------
    text_fields : tuple of str
        Keys of ``tool_response`` whose string values are redacted.
    rebuild : callable
        ``rebuild(tool_response, redacted_fields) -> updatedToolOutput``.
    """

    text_fields: tuple
    rebuild: Callable[[Mapping[str, Any], Dict[str, str]], Dict[str, Any]]


def _rebuild_bash(resp: Mapping[str, Any], redacted: Dict[str, str]) -> Dict[str, Any]:
    return {
        "stdout": redacted["stdout"],
        "stderr": redacted["stderr"],
        "interrupted": resp.get("interrupted", False),
        "isImage": resp.get("isImage", False),
    }


#: Registered adapters, keyed by Claude Code ``tool_name``.
CLAUDE_TOOL_ADAPTERS: Dict[str, ToolOutputAdapter] = {
    "Bash": ToolOutputAdapter(text_fields=("stdout", "stderr"), rebuild=_rebuild_bash),
}


def _context_only(message: str) -> Dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": _HOOK_EVENT,
            "additionalContext": message,
        }
    }


def warning_output(warnings: List[str]) -> Dict[str, Any]:
    """Hook output that tells the agent redaction ran degraded (no rewrite)."""
    return _context_only("scitex-security redact: " + "; ".join(unique(warnings)))


def handle_claude_post_tool_use(
    event: Mapping[str, Any], redactor: Redactor
) -> Optional[Dict[str, Any]]:
    """Apply redaction to one Claude Code PostToolUse event.

    Parameters
    ----------
    event : mapping
        The decoded hook JSON (``tool_name``, ``tool_response``, ...).
    redactor : Redactor
        Detection engine (see :func:`scitex_security.build_redactor`).

    Returns
    -------
    dict or None
        Hook output to print as JSON, or ``None`` to leave the output as is
        (tool not handled, nothing found, no warnings).
    """
    adapter = CLAUDE_TOOL_ADAPTERS.get(str(event.get("tool_name", "")))
    resp = event.get("tool_response")
    if adapter is None or not isinstance(resp, Mapping):
        return None
    texts = [
        resp.get(k) if isinstance(resp.get(k), str) else "" for k in adapter.text_fields
    ]
    results = redactor.redact_many(texts)
    warnings = results[0].warnings if results else []
    if not any(r.changed for r in results):
        return warning_output(warnings) if warnings else None
    redacted = {k: r.text for k, r in zip(adapter.text_fields, results)}
    context = _CONTEXT_REDACTED
    if warnings:
        context += " Note: " + "; ".join(unique(warnings)) + "."
    return {
        "hookSpecificOutput": {
            "hookEventName": _HOOK_EVENT,
            "additionalContext": context,
            "updatedToolOutput": adapter.rebuild(resp, redacted),
        }
    }


#: Dispatch table for ``scitex-security redact --hook NAME``.
HOOKS: Dict[str, Callable[[Mapping[str, Any], Redactor], Optional[Dict[str, Any]]]] = {
    HOOK_CLAUDE_POST_TOOL_USE: handle_claude_post_tool_use,
}


# EOF
