#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_redact/_core.py

"""Secret redaction of text (agent tool output, logs, anything on stdin).

Detection is the union of two independent checks:

1. **gitleaks** -- the maintained upstream rule set (~150 formats) run
   in ``gitleaks stdin`` mode. Its JSON report goes to this process,
   never to the caller; it is only used to learn which exact strings to
   mask. Extend or allowlist detection in a gitleaks TOML config (the
   packaged one keeps every upstream rule via ``[extend] useDefault``),
   never in code.
2. **exact values** -- the live value of every credential-named
   environment variable (``*TOKEN*``, ``*SECRET*``, ``*API_KEY*``, ...)
   is masked wherever it appears, whatever its format. This is the one
   check no public tool can do: it catches a credential whose shape no
   rule knows.

If gitleaks is missing or fails, (2) still runs and the result carries
a warning -- the redactor never fails open silently.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .._config import config_section, load_config

#: Replacement written in place of every detected secret.
MASK = "***REDACTED***"

#: Environment-variable names whose values are treated as credentials.
SECRET_NAME_RE = re.compile(
    r"(?i)(API_?KEY|SECRET|TOKEN|BEARER|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|DSN|AUTH)"
)

#: Shorter env values are skipped so ordinary words are never mangled.
ENV_VALUE_MIN_LENGTH = 12

#: Shorter gitleaks matches are ignored (same reason).
FINDING_MIN_LENGTH = 8

#: Seconds before a gitleaks run is abandoned (and reported as failed).
GITLEAKS_TIMEOUT_S = 20


class GitleaksError(Exception):
    """gitleaks could not produce a report; the message names why (never values)."""


def packaged_gitleaks_config() -> Path:
    """Return the gitleaks TOML shipped with scitex-security.

    It keeps every maintained upstream rule (``[extend] useDefault =
    true``) and is the place to add SciTeX-specific rules or allowlists.
    """
    return Path(str(resources.files("scitex_security._redact") / "gitleaks.toml"))


def find_gitleaks(
    explicit: "str | None" = None, *, environ: Optional[Mapping[str, str]] = None
) -> Optional[str]:
    """Locate the gitleaks binary: ``explicit``, then ``PATH``, then ``~/.local/bin``.

    Returns ``None`` when gitleaks is not installed (callers must then
    report that only exact-value redaction ran).
    """
    env = os.environ if environ is None else environ
    if explicit:
        path = Path(explicit).expanduser()
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None
    found = shutil.which("gitleaks", path=env.get("PATH"))
    if found:
        return found
    home = env.get("HOME") or str(Path.home())
    local = Path(home) / ".local" / "bin" / "gitleaks"
    return str(local) if local.is_file() and os.access(local, os.X_OK) else None


def credential_env_values(
    environ: Optional[Mapping[str, str]] = None,
    *,
    min_length: int = ENV_VALUE_MIN_LENGTH,
) -> Set[str]:
    """Return the values of credential-named env vars worth masking.

    A variable qualifies when its name matches :data:`SECRET_NAME_RE`,
    its value is at least ``min_length`` characters, and the value is not
    a filesystem path (``/...`` or ``~...``, e.g. ``*_TOKEN_FILE``).
    """
    env = os.environ if environ is None else environ
    return {
        value
        for name, value in env.items()
        if SECRET_NAME_RE.search(name)
        and len(value) >= min_length
        and not value.startswith(("/", "~"))
    }


def gitleaks_secrets(
    text: str,
    gitleaks_bin: str,
    config_path: "Path | str | None" = None,
    *,
    timeout: float = GITLEAKS_TIMEOUT_S,
) -> List[str]:
    """Run ``gitleaks stdin`` on ``text`` and return the secret strings it found.

    Raises
    ------
    GitleaksError
        If gitleaks exits non-zero, times out, or emits an unreadable report.
    """
    cmd = [
        gitleaks_bin,
        "stdin",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
        "--exit-code",
        "0",
        "--log-level",
        "error",
    ]
    if config_path:
        cmd += ["--config", str(config_path)]
    try:
        proc = subprocess.run(
            cmd,
            input=text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitleaksError(type(exc).__name__) from None
    if proc.returncode != 0:
        raise GitleaksError(f"exit status {proc.returncode}")
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        raise GitleaksError("unreadable report") from None
    if not isinstance(report, list):
        raise GitleaksError("unexpected report shape")
    return [f.get("Secret", "") for f in report if isinstance(f, dict)]


@dataclass
class RedactionResult:
    """Outcome of redacting one text.

    Attributes
    ----------
    text : str
        The text with every detected secret replaced by :data:`MASK`.
    changed : bool
        Whether anything was masked.
    warnings : list of str
        Degradations (e.g. gitleaks missing); never contains secret values.
    """

    text: str
    changed: bool
    warnings: List[str] = field(default_factory=list)


@dataclass
class Redactor:
    """Mask secrets found by gitleaks and by exact credential env values.

    Build one with :func:`build_redactor` (config chain + gitleaks lookup)
    unless you need full control.

    Parameters
    ----------
    gitleaks_bin : str or None
        Path to gitleaks; ``None`` means not installed (warning emitted).
    gitleaks_config : Path or None
        gitleaks TOML; ``None`` uses gitleaks' own defaults.
    env_values : set of str
        Exact values to mask (see :func:`credential_env_values`).
    finding_min_length : int
        gitleaks matches shorter than this are ignored.
    """

    gitleaks_bin: Optional[str]
    gitleaks_config: "Path | None" = None
    env_values: Set[str] = field(default_factory=set)
    finding_min_length: int = FINDING_MIN_LENGTH
    timeout: float = GITLEAKS_TIMEOUT_S

    def secrets_in(self, texts: Sequence[str]) -> Tuple[Set[str], List[str]]:
        """Return ``(secret strings, warnings)`` for ``texts`` (one gitleaks run)."""
        warnings: List[str] = []
        found: Set[str] = set(self.env_values)
        joined = "\n".join(t for t in texts if t)
        if not joined:
            return found, warnings
        if self.gitleaks_bin is None:
            warnings.append("gitleaks not found; only exact-value redaction ran")
            return found, warnings
        try:
            hits = gitleaks_secrets(
                joined, self.gitleaks_bin, self.gitleaks_config, timeout=self.timeout
            )
        except GitleaksError as exc:
            warnings.append(f"gitleaks failed ({exc}); only exact-value redaction ran")
            return found, warnings
        found.update(s for s in hits if len(s) >= self.finding_min_length)
        return found, warnings

    def redact_many(self, texts: Sequence[str]) -> List[RedactionResult]:
        """Redact several related texts (e.g. stdout and stderr) together."""
        secrets, warnings = self.secrets_in(texts)
        ordered = sorted(secrets, key=len, reverse=True)
        results = []
        for text in texts:
            out = text or ""
            for value in ordered:
                if value and value in out:
                    out = out.replace(value, MASK)
            results.append(
                RedactionResult(
                    text=out, changed=out != (text or ""), warnings=warnings
                )
            )
        return results

    def redact(self, text: str) -> RedactionResult:
        """Redact one text."""
        return self.redact_many([text])[0]


def build_redactor(
    *,
    gitleaks_config: "str | os.PathLike[str] | None" = None,
    config_path: "str | os.PathLike[str] | None" = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Redactor:
    """Build a :class:`Redactor` from the SciTeX config chain.

    gitleaks config precedence: ``gitleaks_config`` argument >
    ``redact.gitleaks_config`` in the selected scitex-security
    ``config.yaml`` > the packaged :func:`packaged_gitleaks_config`.
    gitleaks binary: ``redact.gitleaks_bin`` > ``PATH`` > ``~/.local/bin``.

    Parameters
    ----------
    gitleaks_config : path-like, optional
        gitleaks TOML overriding config and packaged default.
    config_path : path-like, optional
        scitex-security ``config.yaml`` (top of the config chain).
    environ : mapping, optional
        Environment whose credential values are masked (default ``os.environ``).

    Example
    -------
    >>> build_redactor().redact("nothing secret here").changed  # doctest: +SKIP
    False
    """
    env = os.environ if environ is None else environ
    section = config_section(load_config(config_path, environ=env), "redact")
    toml = gitleaks_config or section.get("gitleaks_config")
    toml_path = Path(toml).expanduser() if toml else packaged_gitleaks_config()
    min_env = int(section.get("env_value_min_length", ENV_VALUE_MIN_LENGTH))
    return Redactor(
        gitleaks_bin=find_gitleaks(section.get("gitleaks_bin"), environ=env),
        gitleaks_config=toml_path,
        env_values=credential_env_values(env, min_length=min_env),
        finding_min_length=int(section.get("finding_min_length", FINDING_MIN_LENGTH)),
    )


def redact_text(
    text: str,
    *,
    gitleaks_config: "str | os.PathLike[str] | None" = None,
    config_path: "str | os.PathLike[str] | None" = None,
    environ: Optional[Mapping[str, str]] = None,
) -> RedactionResult:
    """Redact secrets from ``text`` using gitleaks plus exact env values.

    Parameters
    ----------
    text : str
        Text to redact.
    gitleaks_config, config_path, environ
        See :func:`build_redactor`.

    Returns
    -------
    RedactionResult
        Redacted text, whether anything changed, and any warnings.

    Example
    -------
    >>> from scitex_security import redact_text
    >>> redact_text("build ok").text                      # doctest: +SKIP
    'build ok'
    """
    redactor = build_redactor(
        gitleaks_config=gitleaks_config, config_path=config_path, environ=environ
    )
    return redactor.redact(text)


def unique(items: Iterable[str]) -> List[str]:
    """Order-preserving de-duplication (for warning lists)."""
    return list(dict.fromkeys(items))


# EOF
