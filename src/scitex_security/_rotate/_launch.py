#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_launch.py

"""Launcher of the isolated credential-rotation worker.

This process resolves the SciTeX config chain and renders progress; it
never sees the credential, and is never imported by the worker. The
worker (:mod:`scitex_security._rotate._main`)
runs under ``<python> -I`` and reads the value itself from a hidden
``/dev/tty`` prompt. The two talk over the worker's stdin/stdout pipes
with line-delimited JSON events carrying names, statuses and hashes.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Optional

import scitex_logging as _logging

from .._config import config_section, load_config
from ._common import (
    EVENT_ABORT,
    EVENT_CONFIRM,
    EVENT_READY_FOR_SECRET,
    EVENT_SAY,
    Abort,
)
from ._settings import RotateSettings, settings_from_mapping

_log = _logging.getLogger(__name__)
_out = _logging.getPlainConsole(__name__)

#: Worker bootstrap script, run as ``<python> -I _entry.py <request-json>``.
ENTRY_SCRIPT = Path(__file__).resolve().parent / "_entry.py"


class RotationConfigError(Exception):
    """The ``rotate_credential`` config section is missing or invalid."""


def load_rotate_settings(
    config_path: "str | os.PathLike[str] | None" = None,
) -> RotateSettings:
    """Validated ``rotate_credential`` settings from the scitex-security config chain.

    Raises
    ------
    RotationConfigError
        If a required key is missing or a value is malformed.
    """
    section = config_section(load_config(config_path), "rotate_credential")
    try:
        return settings_from_mapping(section)
    except Abort as exc:
        raise RotationConfigError(str(exc)) from None


def _default_confirm(prompt: str) -> str:
    import click

    # audit-cli: interactive-ok -- the operator-required typed `install` confirmation
    return click.prompt(prompt, default="", show_default=False)


def rotate_credential(
    payload: str,
    variables: str,
    *,
    dry_run: bool = False,
    kind: Optional[str] = None,
    config_path: "str | os.PathLike[str] | None" = None,
    settings: Optional[RotateSettings] = None,
    confirm: Callable[[str], str] = _default_confirm,
) -> int:
    """Rotate VARS inside the signed encrypted PAYLOAD (operator-run, interactive).

    The new value is read by the isolated worker from a hidden prompt on
    the controlling terminal -- never from argv, environment, a file or a
    pipe -- and is never logged. ``dry_run`` performs every step up to
    signing in a temporary directory it removes.

    Parameters
    ----------
    payload : str
        Ciphertext file name, e.g. ``bash-config-<24 hex>.gpg``.
    variables : str
        Comma-separated variable names to replace inside the payload.
    dry_run : bool
        Stop before signing; install and commit nothing.
    kind : str, optional
        ``github-pat`` or ``generic``; inferred from the names by default.
    config_path : path-like, optional
        scitex-security ``config.yaml`` (top of the config chain).
    settings : RotateSettings, optional
        Pre-validated settings (skips the config chain).
    confirm : callable
        Asks the operator for the typed ``install`` confirmation.

    Returns
    -------
    int
        0 success, 1 some host failed, 2 aborted, 130 interrupted.

    Example
    -------
    $ scitex-security rotate-credential bash-config-<hex>.gpg GH_TOKEN --dry-run
    """
    cfg = settings or load_rotate_settings(config_path)
    request = {
        "settings": cfg.to_dict(),
        "payload": payload,
        "variables": variables,
        "dry_run": dry_run,
        "kind": kind,
    }
    proc = subprocess.Popen(
        [cfg.python, "-I", str(ENTRY_SCRIPT), json.dumps(request)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    if proc.stdin is None or proc.stdout is None:  # pragma: no cover - PIPE always set
        raise RuntimeError("worker pipes not created")
    for raw in proc.stdout:
        try:
            event = json.loads(raw)
        except ValueError:
            _log.error("rotate-credential: unreadable worker event; stopping")
            proc.kill()
            break
        kind_ = event.get("event")
        if kind_ == EVENT_SAY:
            _out.emit(str(event.get("text", "")))
        elif kind_ == EVENT_ABORT:
            _log.error("ABORT: %s", event.get("message", ""))
        elif kind_ == EVENT_READY_FOR_SECRET:
            proc.stdin.write(b"go\n")
            proc.stdin.flush()
        elif kind_ == EVENT_CONFIRM:
            answer = confirm(str(event.get("prompt", ""))).replace("\n", " ")
            proc.stdin.write(answer.encode() + b"\n")
            proc.stdin.flush()
        else:
            _log.error("rotate-credential: unknown worker event %r; stopping", kind_)
            proc.kill()
            break
    proc.stdin.close()
    return proc.wait()


# EOF
