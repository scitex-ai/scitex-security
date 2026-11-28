#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_cli.py

"""``scitex-security rotate-credential`` (launcher side; never imported by the worker)."""

from __future__ import annotations

import click
import scitex_logging as _logging

from .._config import ConfigError
from ._logic import SHAPES

_log = _logging.getLogger(__name__)


@click.command("rotate-credential")
@click.argument("payload")
@click.argument("variables")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Do everything up to signing; install and commit nothing.",
)
@click.option(
    "--kind",
    type=click.Choice(sorted(SHAPES)),
    default=None,
    help="Value shape to require (default: inferred from the variable names).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="scitex-security config.yaml (overrides the config chain).",
)
@click.pass_context
def rotate_credential_cmd(
    ctx: click.Context,
    payload: str,
    variables: str,
    dry_run: bool,
    kind: "str | None",
    config_path: "str | None",
) -> None:
    """Rotate VARIABLES inside the signed encrypted shell PAYLOAD (operator-run).

    \b
    PAYLOAD    ciphertext name, e.g. bash-config-<24 hex>.gpg
    VARIABLES  comma-separated names, e.g. GH_TOKEN,GITHUB_TOKEN

    \b
    The new value is read ONCE from a hidden prompt on the controlling
    terminal -- never argv, environment, a file or a pipe -- inside an
    isolated `python -I` worker; output is names, statuses and hashes only.
    The worker proves the loaded environment changed in exactly VARIABLES,
    re-encrypts to the same recipients, builds the installed manifest + 1
    entry, and only after you type `install` signs it with the issuer key,
    installs it on every configured host (hosts without the trust dir are
    skipped with a reason) and opens a dotfiles PR (never merged).

    \b
    Fleet facts come from the `rotate_credential` section of the config:
      --config -> $SCITEX_SECURITY_CONFIG -> <project>/.scitex/security/config.yaml
               -> ~/.scitex/security/config.yaml

    \b
    Example:
      $ scitex-security rotate-credential bash-config-0123456789abcdef01234567.gpg GH_TOKEN --dry-run
      $ scitex-security rotate-credential bash-config-0123456789abcdef01234567.gpg GH_TOKEN,GITHUB_TOKEN
    """
    from ._launch import RotationConfigError, rotate_credential

    try:
        status = rotate_credential(
            payload, variables, dry_run=dry_run, kind=kind, config_path=config_path
        )
    except (RotationConfigError, ConfigError) as exc:
        _log.error("rotate-credential: %s", exc)
        ctx.exit(2)
        return
    ctx.exit(status)


# EOF
