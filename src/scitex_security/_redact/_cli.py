#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_redact/_cli.py

"""``scitex-security redact SOURCE``."""

from __future__ import annotations

import json

import click
import scitex_logging as _logging

from ._core import build_redactor
from ._hook import HOOKS, warning_output

_log = _logging.getLogger(__name__)
_out = _logging.getPlainConsole(__name__)


def _run_hook(name: str, raw: str, gitleaks_config) -> None:
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("hook input is not a JSON object")
        redactor = build_redactor(gitleaks_config=gitleaks_config)
        output = HOOKS[name](event, redactor)
    except (
        Exception
    ) as exc:  # the hook must never break the tool call, nor fail silently
        output = warning_output(
            [
                f"redaction hook failed ({type(exc).__name__}); this output was NOT redacted"
            ]
        )
    if output is not None:
        _out.emit(json.dumps(output))


@click.command("redact")
@click.argument("source", type=click.File("r", encoding="utf-8"))
@click.option(
    "--hook",
    type=click.Choice(sorted(HOOKS)),
    default=None,
    help="Read an agent-hook event JSON on stdin and emit the hook's JSON reply.",
)
@click.option(
    "--config",
    "gitleaks_config",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help=(
        "gitleaks TOML. Default: redact.gitleaks_config from the scitex-security "
        "config chain, else the packaged config (all upstream rules)."
    ),
)
def redact_cmd(source, hook: "str | None", gitleaks_config: "str | None") -> None:
    """Mask secrets in SOURCE (a file, or - for stdin): gitleaks + exact credential env values.

    \b
    Detection = gitleaks findings  UNION  the live values of env vars whose
    names look like credentials (*TOKEN*, *SECRET*, *API_KEY*, *PASSWORD*,
    ...; values >= 12 chars that are not paths). Every hit becomes
    ***REDACTED***. If gitleaks is missing or fails, exact-value redaction
    still runs and a warning is emitted (stderr in text mode, the hook's
    additionalContext in hook mode) -- never a silent fail-open.

    \b
    Modes:
      (default)                      SOURCE text -> redacted text on stdout
      --hook claude-post-tool-use    Claude Code PostToolUse JSON in SOURCE ->
                                     hookSpecificOutput.updatedToolOutput
                                     (Bash stdout/stderr; nothing printed when
                                     nothing was found). Always exits 0.

    \b
    gitleaks binary: redact.gitleaks_bin, else PATH, else ~/.local/bin.
    Config chain: $SCITEX_SECURITY_CONFIG -> <project>/.scitex/security/config.yaml
                  -> ~/.scitex/security/config.yaml -> defaults

    \b
    Example:
      $ some-command 2>&1 | scitex-security redact -
      $ scitex-security redact build.log --config my-gitleaks.toml
      $ scitex-security redact - --hook claude-post-tool-use < event.json
    """
    raw = source.read()
    if hook:
        _run_hook(hook, raw, gitleaks_config)
        return
    result = build_redactor(gitleaks_config=gitleaks_config).redact(raw)
    for warning in result.warnings:
        _log.warning("scitex-security redact: %s", warning)
    click.echo(result.text, nl=False)


# EOF
