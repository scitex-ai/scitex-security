#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_settings.py

"""Configuration of rotate-credential (stdlib only).

Built by the launcher from the ``rotate_credential`` section of the
scitex-security config chain, validated there, and handed to the
isolated worker as JSON. Fleet facts (hosts, controller, issuer
fingerprint, dotfiles repository, which variables are GitHub tokens) are
REQUIRED config -- nothing about a particular fleet is hardcoded. Paths
default to the signed-manifest design's documented locations.

Example ``~/.scitex/security/config.yaml``::

    rotate_credential:
      controller: my-controller-host
      hosts: [my-controller-host, worker-01, worker-02]
      skipped_hosts:
        hpc-login: no noninteractive administrator installation
      issuer_fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
      expected_recipient_count: 3
      github:
        dotfiles_repo: owner/.dotfiles
        pat_variables: [GH_TOKEN, GITHUB_TOKEN]
        pat_variable_prefixes: [SCITEX_GH_TOKEN]
        pr_token_variable: SCITEX_GH_TOKEN_OWNER
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List, Mapping, Optional

from ._common import Abort

_FPR_RE = re.compile(r"[0-9A-F]{40}")
_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_VAR_RE = re.compile(r"[A-Z_][A-Z0-9_]*")
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class GitHubRouting:
    """Which variables are GitHub tokens, and where the dotfiles PR goes."""

    dotfiles_repo: str
    base_branch: str = "develop"
    pat_variables: List[str] = field(
        default_factory=lambda: ["GH_TOKEN", "GITHUB_TOKEN"]
    )
    pat_variable_prefixes: List[str] = field(default_factory=list)
    #: Env var whose token opens the PR. If it is among the rotated
    #: variables, the NEW value is used (the old one may be revoked).
    #: ``None``: ``gh`` uses its own ambient authentication.
    pr_token_variable: Optional[str] = None


@dataclass(frozen=True)
class RotateSettings:
    """Validated rotate-credential settings (see module docstring)."""

    controller: str
    hosts: List[str]
    issuer_fingerprint: str
    github: GitHubRouting
    skipped_hosts: Dict[str, str] = field(default_factory=dict)
    expected_recipient_count: Optional[int] = None
    trust_dir: str = "/etc/scitex-secrets"
    verifier: str = "/opt/scitex-secrets/verified_payload.py"
    signing_home: str = "/var/lib/scitex-secrets-signing"
    gpgv: str = "/usr/bin/gpgv"
    python: str = "/usr/bin/python3"
    payload_dir: str = "~/.pw"
    payload_prefix: str = "bash-config-"
    dotfiles_dir: str = "~/.dotfiles"
    dotfiles_payload_subdir: str = "src/.pw"
    dotfiles_shim_subdir: str = "src/.bash.d"
    dotfiles_secrets_subdir: str = "src/.bash.d/secrets"
    recipient_fingerprints_glob: str = "src/.gnupg.d/*/fingerprint"
    override_dir: str = "~/.local/share/scitex-credentials/overrides"
    runtime_dir: str = "~/.scitex/security/runtime"

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable form (handed to the isolated worker)."""
        return asdict(self)

    @property
    def payload_re(self) -> "re.Pattern[str]":
        """Accepted payload file names: ``<prefix><24 hex>.gpg``."""
        return re.compile(re.escape(self.payload_prefix) + r"[0-9a-f]{24}\.gpg")


def _require(section: Mapping[str, Any], key: str) -> Any:
    value = section.get(key)
    if value in (None, "", [], {}):
        raise Abort(
            f"rotate_credential.{key} is required in the scitex-security config"
        )
    return value


def _str_list(value: Any, key: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise Abort(f"rotate_credential.{key} must be a list of strings")
    return list(value)


def settings_from_mapping(section: Mapping[str, Any]) -> RotateSettings:
    """Validate a ``rotate_credential`` config section into :class:`RotateSettings`.

    Raises
    ------
    Abort
        On a missing required key or a malformed value (message names the key).
    """
    known = {f.name for f in fields(RotateSettings)}
    unknown = sorted(set(section) - known)
    if unknown:
        raise Abort(f"unknown rotate_credential keys: {unknown}")
    hosts = _str_list(_require(section, "hosts"), "hosts")
    controller = str(_require(section, "controller"))
    for host in hosts + [controller] + list(section.get("skipped_hosts") or {}):
        if not _HOST_RE.fullmatch(host):
            raise Abort(f"invalid host name in rotate_credential: {host!r}")
    if controller not in hosts:
        raise Abort(
            "rotate_credential.controller must be one of rotate_credential.hosts"
        )
    fpr = str(_require(section, "issuer_fingerprint")).replace(" ", "").upper()
    if not _FPR_RE.fullmatch(fpr):
        raise Abort("rotate_credential.issuer_fingerprint must be 40 hex characters")
    gh = dict(_require(section, "github"))
    repo = str(gh.get("dotfiles_repo") or "")
    if not _REPO_RE.fullmatch(repo):
        raise Abort("rotate_credential.github.dotfiles_repo must be 'owner/name'")
    gh_known = {f.name for f in fields(GitHubRouting)}
    if set(gh) - gh_known:
        raise Abort(
            f"unknown rotate_credential.github keys: {sorted(set(gh) - gh_known)}"
        )
    routing = GitHubRouting(
        dotfiles_repo=repo,
        base_branch=str(gh.get("base_branch", "develop")),
        pat_variables=_str_list(
            gh.get("pat_variables", ["GH_TOKEN", "GITHUB_TOKEN"]),
            "github.pat_variables",
        ),
        pat_variable_prefixes=_str_list(
            gh.get("pat_variable_prefixes", []), "github.pat_variable_prefixes"
        ),
        pr_token_variable=gh.get("pr_token_variable"),
    )
    if routing.pr_token_variable is not None and not _VAR_RE.fullmatch(
        str(routing.pr_token_variable)
    ):
        raise Abort("rotate_credential.github.pr_token_variable is not a variable name")
    count = section.get("expected_recipient_count")
    if count is not None and (not isinstance(count, int) or count < 1):
        raise Abort(
            "rotate_credential.expected_recipient_count must be a positive integer"
        )
    rest = {
        k: str(v)
        for k, v in section.items()
        if k
        not in {
            "hosts",
            "controller",
            "issuer_fingerprint",
            "github",
            "skipped_hosts",
            "expected_recipient_count",
        }
    }
    return RotateSettings(
        controller=controller,
        hosts=hosts,
        issuer_fingerprint=fpr,
        github=routing,
        skipped_hosts={
            str(k): str(v) for k, v in (section.get("skipped_hosts") or {}).items()
        },
        expected_recipient_count=count,
        **rest,
    )


def settings_from_dict(data: Mapping[str, Any]) -> RotateSettings:
    """Inverse of :meth:`RotateSettings.to_dict` (worker side)."""
    return settings_from_mapping(data)


# EOF
