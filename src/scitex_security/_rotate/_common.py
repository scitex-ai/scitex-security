#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_common.py

"""Shared helpers for rotate-credential (stdlib only; runs under ``python -I``).

The isolated worker never writes to a console itself. It reports to the
launching ``scitex-security`` process through a line-delimited JSON
event channel on its stdout/stdin pipes (:class:`Channel`); the launcher
renders events with scitex-logging and answers the non-secret requests
(the typed ``install`` confirmation). Events carry names, statuses and
hashes only -- never a credential value or plaintext.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

#: Event names of the worker -> launcher protocol.
EVENT_SAY = "say"
EVENT_ABORT = "abort"
EVENT_READY_FOR_SECRET = "ready-for-secret"
EVENT_CONFIRM = "confirm"


class Abort(Exception):
    """Stop without changing anything further; the message never contains values."""


class Channel:
    """Line-delimited JSON events to the launcher (``out_fd``), replies from it (``in_fd``)."""

    def __init__(self, out_fd: int = 1, in_fd: int = 0) -> None:
        self.out_fd = out_fd
        self.in_fd = in_fd

    def emit(self, event: str, **fields: Any) -> None:
        """Send one event."""
        line = json.dumps(dict(fields, event=event), sort_keys=True) + "\n"
        data = line.encode()
        while data:
            data = data[os.write(self.out_fd, data) :]

    def request(self, event: str, **fields: Any) -> str:
        """Send one event and block for the launcher's one-line reply."""
        self.emit(event, **fields)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = os.read(self.in_fd, 1)
            if not chunk:
                raise Abort("launcher closed the channel")
            buf += chunk
        return buf.decode().rstrip("\n")


#: Process-wide channel used by :func:`say`.
CHANNEL = Channel()


def say(*parts: object) -> None:
    """Report a status line (names, statuses, hashes -- never values)."""
    CHANNEL.emit(EVENT_SAY, text=" ".join(str(p) for p in parts))


def safe_env(home: "Path | str") -> dict:
    """Minimal environment for subprocesses that receive plaintext on stdin."""
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(home)}


def run(
    args: Sequence[str],
    data: Optional[bytes] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout: float = 60,
    check: bool = True,
    what: str = "command",
) -> subprocess.CompletedProcess:
    """Run ``args`` capturing output; plaintext only ever goes in via ``data`` (stdin).

    ``env`` defaults to :func:`safe_env` for the current home.
    """
    proc = subprocess.run(
        list(args),
        input=data,
        capture_output=True,
        timeout=timeout,
        env=dict(env) if env is not None else safe_env(Path.home()),
    )
    if check and proc.returncode:
        raise Abort(f"{what} failed (rc={proc.returncode})")
    return proc


def sha256(data: bytes) -> str:
    """Hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


# EOF
