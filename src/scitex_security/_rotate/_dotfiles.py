#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_dotfiles.py

"""Dotfiles topic branch: ciphertext, shim repoint, trust copy, inventory; push + PR (never merge)."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional, Sequence

from ._common import Abort, run, say, sha256
from ._crypto import expand
from ._logic import payload_tag
from ._settings import RotateSettings


def _git(path: Path, *args: str, what: str, timeout: float = 60):
    return run(
        ["git", "-C", str(path), *args],
        env=dict(os.environ),
        what=what,
        timeout=timeout,
    )


def _update_mapping(secrets_dir: Path, old_name: str, new_name: str) -> None:
    path = secrets_dir / "ENCRYPTED_FILES.json"
    doc = json.loads(path.read_text())
    configs = doc["shell_configs"]
    entries = configs.values() if isinstance(configs, dict) else configs
    for entry in entries:
        if entry.get("ciphertext") == old_name:
            entry["ciphertext"], entry["superseded_ciphertext"] = new_name, old_name
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def _update_inventory(
    secrets_dir: Path, old_name: str, new_name: str, login: Optional[str], day: str
) -> None:
    path = secrets_dir / "SECRET_INVENTORY.json"
    doc = json.loads(path.read_text())
    items = doc["items"]
    old = [i for i in items if i["payload"] == old_name]
    if len(old) != 1:
        raise Abort("inventory entry for old payload not found")
    new = dict(old[0], payload=new_name)
    live = f"; live check HTTP 200 as {login}" if login else ""
    new["rotation_status"] = (
        f"rotated {day} via scitex-security rotate-credential; operator-supplied value{live}"
    )
    old[0]["rotation_status"] = (
        f"superseded {day} by {new_name}; revoke the old value at the provider; manifest entry pending removal"
    )
    items.insert(items.index(old[0]) + 1, new)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def open_pr(
    cfg: RotateSettings,
    old_name: str,
    new_name: str,
    names: Sequence[str],
    work: Path,
    login: Optional[str],
    stamp: str,
    value: str,
) -> Optional[str]:
    """Commit the rotation on a dotfiles topic branch, push it, open a PR into the base branch.

    The PR token comes from ``github.pr_token_variable``: the NEW value
    when that variable is being rotated (the old one may already be
    revoked), else its current environment value; with no variable
    configured ``gh`` uses its own authentication. The token reaches
    ``gh`` only through its environment, never argv.
    """
    dotfiles = expand(cfg.dotfiles_dir)
    tag = payload_tag(old_name, cfg.payload_prefix)
    branch = f"rotate/{tag}-{stamp}"
    wt = dotfiles / ".worktrees" / f"rotate-{tag}-{stamp}"
    base = cfg.github.base_branch
    _git(dotfiles, "fetch", "-q", "origin", what="git fetch")
    _git(
        dotfiles,
        "worktree",
        "add",
        "-q",
        "-b",
        branch,
        str(wt),
        f"origin/{base}",
        what="worktree add",
    )
    secrets_dir = wt / cfg.dotfiles_secrets_subdir
    target = wt / cfg.dotfiles_payload_subdir / new_name
    shutil.copyfile(work / new_name, target)
    os.chmod(target, 0o600)
    shims = [
        p
        for p in (wt / cfg.dotfiles_shim_subdir).rglob("*.src")
        if old_name in p.read_text(errors="ignore")
    ]
    if not shims:
        raise Abort("no shim references the old payload")
    for shim in shims:
        shim.write_text(shim.read_text().replace(old_name, new_name))
    shutil.copyfile(work / "manifest.json", secrets_dir / "trust/manifest.json")
    shutil.copyfile(work / "manifest.json.sig", secrets_dir / "trust/manifest.json.sig")
    _update_mapping(secrets_dir, old_name, new_name)
    _update_inventory(secrets_dir, old_name, new_name, login, stamp[:8])
    _git(
        wt,
        "add",
        "-A",
        f"{cfg.dotfiles_payload_subdir}/{new_name}",
        cfg.dotfiles_shim_subdir,
        what="git add",
    )
    title = f"Rotate {','.join(names)} into {new_name}"
    summary = (
        f"Operator-run rotation of {','.join(names)} with `scitex-security rotate-credential`.\n\n"
        f"- New payload {new_name} replaces {old_name} (same recipients; only the named variables changed).\n"
        f"- Shims repointed: {', '.join(str(p.relative_to(wt)) for p in shims)}.\n"
        f"- Signed manifest sha256 {sha256((work / 'manifest.json').read_bytes())[:16]}... installed fleet-wide.\n"
        "- Old manifest entry stays until every host has pulled this change.\n"
        "- Operator: revoke the old value at the provider after hosts load the new shim.\n"
    )
    msg = work / "commit-msg.txt"
    msg.write_text(title + "\n\n" + summary)
    _git(wt, "commit", "-q", "-F", str(msg), what="git commit")
    _git(wt, "push", "-q", "-u", "origin", branch, what="git push", timeout=120)
    env = dict(os.environ)
    var = cfg.github.pr_token_variable
    if var:
        token = value if var in names else os.environ.get(var)
        if not token:
            say(f"PR not opened: {var} unset; branch {branch} pushed")
            return None
        env.update(GH_TOKEN=token, GITHUB_TOKEN=token)
    pr = run(
        [
            "gh",
            "pr",
            "create",
            "-R",
            cfg.github.dotfiles_repo,
            "--base",
            base,
            "--head",
            branch,
            "--title",
            title,
            "--body",
            summary,
        ],
        env=env,
        what="gh pr create",
        timeout=60,
    )
    url = pr.stdout.decode().strip().splitlines()[-1]
    say("PR", url)
    return url


# EOF
