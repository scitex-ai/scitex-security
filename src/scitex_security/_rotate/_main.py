#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_main.py

"""The isolated rotation worker (runs under ``python -I`` via :mod:`._entry`)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence

from . import _crypto as crypto
from ._common import CHANNEL, EVENT_ABORT, EVENT_CONFIRM, Abort, say, sha256
from ._dotfiles import open_pr
from ._install import install_all, render_installer
from ._logic import (
    check_env_diff,
    infer_kind,
    manifest_delta_is_plus_one,
    manifest_plus_one,
    parse_variables,
    payload_tag,
    replace_values,
    shape_ok,
)
from ._settings import RotateSettings, settings_from_dict

#: Files sent to each host; ``None`` is replaced by the new payload name.
_BUNDLE: List[Optional[str]] = [
    "manifest.json",
    "manifest.json.sig",
    None,
    "install_on_host.sh",
]

#: Exact reply the operator must type to sign and install.
CONFIRM_WORD = "install"


def _intake(names: Sequence[str], kind: str, dry_run: bool):
    value = crypto.read_value(names)
    ok = shape_ok(value, kind)
    say("shape check:", "ok" if ok else "FAILED", f"({kind}, {len(value)} chars)")
    if not ok:
        raise Abort("value does not match the expected shape")
    login = None
    if kind == "github-pat":
        status, login = crypto.check_github_pat(value)
        say("liveness: GET /user HTTP", status, "login", login)
        if status != 200 and not dry_run:
            raise Abort("token is not live; nothing changed")
    else:
        say("liveness: no provider check for kind", kind)
    return value, login


def _release(
    cfg: RotateSettings,
    payload: str,
    names,
    value,
    login,
    work: Path,
    new_name: str,
    stamp: str,
    dry_run: bool,
) -> int:
    old_plain, old_cipher = crypto.decrypt_current(cfg, payload)
    new_plain = replace_values(old_plain.decode(), names, value).encode()
    old_env, new_env = crypto.load_env(old_plain), crypto.load_env(new_plain)
    say("load status old/new:", old_env.status.decode(), new_env.status.decode())
    changed = check_env_diff(old_env, new_env, names, value)
    say("changed exported names:", sorted(changed), "| functions identical: True")
    cipher = crypto.encrypt_same_recipients(cfg, new_plain, old_cipher)
    del old_plain, new_plain, old_env, new_env
    (work / new_name).write_bytes(cipher)
    os.chmod(work / new_name, 0o600)
    installed = crypto.installed_manifest(cfg)
    manifest = manifest_plus_one(installed, payload, new_name, sha256(cipher))
    if not manifest_delta_is_plus_one(installed, json.loads(manifest), new_name):
        raise Abort("candidate manifest is not installed + exactly one entry")
    say("new payload:", new_name)
    say("ciphertext sha256:", sha256(cipher))
    say("candidate manifest sha256:", sha256(manifest), "(installed + 1 entry)")
    if dry_run:
        say("issuer key available for signing:", crypto.signer_available(cfg))
        say("DRY-RUN complete: nothing signed, installed or committed")
        return 0
    reply = CHANNEL.request(
        EVENT_CONFIRM, prompt=f"Type '{CONFIRM_WORD}' to sign and install fleet-wide"
    )
    if reply.strip() != CONFIRM_WORD:
        raise Abort("not confirmed; nothing signed or installed")
    sig = crypto.sign(cfg, work, manifest)
    say("manifest.json.sig sha256:", sha256(sig))
    (work / "install_on_host.sh").write_text(
        render_installer(cfg, new_name, payload, sha256(manifest), sha256(sig))
    )
    os.chmod(work / "install_on_host.sh", 0o600)
    results = install_all(cfg, work, work.name, [f if f else new_name for f in _BUNDLE])
    for host, res in results.items():
        say(f"{host}: {res}")
    if any(r == "FAIL" for r in results.values()):
        say("Some hosts failed; dotfiles PR not opened. Bundle kept in", work)
        return 1
    open_pr(cfg, payload, new_name, names, work, login, stamp, value)
    say(
        "Next: merge the dotfiles PR, let hosts pull, then revoke the old value at the provider."
    )
    return 0


def rotate(request: Mapping[str, Any]) -> int:
    """Run one rotation described by ``request`` (settings, payload, variables, dry_run, kind)."""
    cfg = settings_from_dict(request["settings"])
    payload = str(request["payload"])
    dry_run = bool(request.get("dry_run"))
    names = parse_variables(payload, str(request["variables"]), cfg.payload_re)
    kind = request.get("kind") or infer_kind(
        names, cfg.github.pat_variables, cfg.github.pat_variable_prefixes
    )
    say(
        "mode:",
        "DRY-RUN" if dry_run else "ROTATE",
        "| payload:",
        payload,
        "| variables:",
        names,
        "| kind:",
        kind,
    )
    value, login = _intake(names, kind, dry_run)
    new_name = cfg.payload_prefix + secrets.token_hex(12) + ".gpg"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    if dry_run:
        work = Path(tempfile.mkdtemp(prefix="rotate-dryrun-"))
    else:
        work = (
            crypto.expand(cfg.runtime_dir)
            / f"rotate-{payload_tag(payload, cfg.payload_prefix)}-{stamp}"
        )
        work.mkdir(mode=0o700, parents=True)
    os.chmod(work, 0o700)
    try:
        return _release(
            cfg, payload, names, value, login, work, new_name, stamp, dry_run
        )
    finally:
        value = None
        if dry_run:
            shutil.rmtree(work, ignore_errors=True)


def main(argv: Sequence[str]) -> int:
    """Worker entry: ``argv[0]`` is the JSON request. Returns the exit status."""
    try:
        return rotate(json.loads(argv[0]))
    except Abort as exc:
        CHANNEL.emit(EVENT_ABORT, message=str(exc))
        return 2
    except KeyboardInterrupt:
        CHANNEL.emit(EVENT_ABORT, message="interrupted")
        return 130


# EOF
