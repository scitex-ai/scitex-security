#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_config.py

"""SciTeX config chain for scitex-security.

Precedence (highest first; the first file that exists wins, files are
not merged):

1. an explicit path (a ``--config``-style CLI argument)
2. ``$SCITEX_SECURITY_CONFIG``
3. ``<project>/.scitex/security/config.yaml`` (nearest ``.git`` upward)
4. ``~/.scitex/security/config.yaml`` (``$SCITEX_DIR`` relocates ``~/.scitex``)
5. built-in defaults (an empty mapping; each consumer owns its defaults)

A path given explicitly (1 or 2) that does not exist is an error, not a
silent fall-through to the next scope.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Optional

import yaml

#: Environment variable naming an explicit config file.
ENV_CONFIG = "SCITEX_SECURITY_CONFIG"

#: Canonical config filename inside a ``.scitex/security/`` scope.
CONFIG_FILENAME = "config.yaml"


class ConfigError(Exception):
    """The selected config file is missing or is not a YAML mapping."""


def _project_config(cwd: Path) -> Optional[Path]:
    for parent in [cwd] + list(cwd.parents):
        if (parent / ".git").exists():
            return parent / ".scitex" / "security" / CONFIG_FILENAME
    return None


def _user_config(environ: Mapping[str, str]) -> Path:
    root = environ.get("SCITEX_DIR") or str(Path.home() / ".scitex")
    return Path(root).expanduser() / "security" / CONFIG_FILENAME


def find_config_path(
    explicit: "str | os.PathLike[str] | None" = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    cwd: Optional[Path] = None,
) -> Optional[Path]:
    """Return the config file the precedence chain selects, or ``None``.

    Parameters
    ----------
    explicit : path-like, optional
        Highest-precedence path (e.g. a ``--config`` argument).
    environ : mapping, optional
        Environment to read ``$SCITEX_SECURITY_CONFIG`` / ``$SCITEX_DIR``
        from (defaults to ``os.environ``).
    cwd : Path, optional
        Directory the project-scope search starts from (defaults to cwd).

    Raises
    ------
    ConfigError
        If an explicit or ``$SCITEX_SECURITY_CONFIG`` path does not exist.
    """
    env = os.environ if environ is None else environ
    for given in (explicit, env.get(ENV_CONFIG)):
        if given:
            path = Path(given).expanduser()
            if not path.is_file():
                raise ConfigError(f"config file not found: {path}")
            return path
    project = _project_config((cwd or Path.cwd()).resolve())
    if project is not None and project.is_file():
        return project
    user = _user_config(env)
    return user if user.is_file() else None


def load_config(
    explicit: "str | os.PathLike[str] | None" = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    cwd: Optional[Path] = None,
) -> dict:
    """Load the scitex-security config selected by the precedence chain.

    Returns an empty dict when no config file exists (defaults apply).

    Example
    -------
    >>> cfg = load_config()                      # doctest: +SKIP
    >>> cfg.get("redact", {}).get("gitleaks_config")  # doctest: +SKIP
    """
    path = find_config_path(explicit, environ=environ, cwd=cwd)
    if path is None:
        return {}
    data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"config file is not a YAML mapping: {path}")
    return data


def config_section(config: Mapping[str, Any], name: str) -> dict:
    """Return ``config[name]`` as a dict (empty when absent).

    Raises
    ------
    ConfigError
        If the section exists but is not a mapping.
    """
    section = config.get(name)
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise ConfigError(f"config section {name!r} is not a mapping")
    return dict(section)


# EOF
