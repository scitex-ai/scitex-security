"""Read-only credential hygiene checks. Reports never include secret values.

This bounded check covers explicit credential paths and credential-like files
tracked in the selected Git repository. It does not inspect Git history,
password managers, process environments, or authenticate to remote services.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404
from pathlib import Path
from typing import Iterable

_MAX_FILES = 5000
_MAX_BYTES = 1024 * 1024
_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?[\w.-]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)[\w.-]*\s*[:=]\s*(.+?)\s*$",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_EXAMPLES = (".example", ".sample", ".template", ".dist")


def _credential_path(path: str) -> bool:
    parts = Path(path).parts
    name = Path(path).name.lower()
    if name.endswith(_EXAMPLES) or name.endswith(".pub"):
        return False
    return (
        any(p.lower() in {"secret", "secrets"} for p in parts)
        or name == ".env"
        or name.startswith(".env.")
        or name in {"credentials", "credentials.json", "hosts.yml"}
        or name.endswith((".pem", ".key"))
        or (".ssh" in parts and name.startswith("id_"))
    )


def _literal_lines(data: bytes) -> list[int]:
    if data.startswith(b"\x00GITCRYPT") or b"\x00" in data:
        return []
    lines = []
    for number, line in enumerate(
        data.decode("utf-8", errors="replace").splitlines(), 1
    ):
        match = _ASSIGNMENT.match(line)
        if not match:
            continue
        value = match[1].strip().strip("\"'")
        # References and explicit placeholders are not credentials. Never
        # execute a shell or expand the file to decide what its value is.
        if (
            not value
            or value.startswith(("$", "<", "{{"))
            or value.lower()
            in {
                "none",
                "null",
                "false",
                "true",
                "changeme",
                "password_here",
                "redacted",
                "***",
            }
        ):
            continue
        lines.append(number)
    return lines


def _private_key_lines(data: bytes) -> list[int]:
    if data.startswith(b"\x00GITCRYPT") or b"\x00" in data:
        return []
    return [
        number
        for number, line in enumerate(
            data.decode("utf-8", errors="replace").splitlines(), 1
        )
        if _PRIVATE_KEY.search(line)
    ]


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    binary = shutil.which("git")
    if binary is None:
        raise FileNotFoundError("git is not installed")
    # Fixed read-only Git subcommands use argv without a shell.
    return subprocess.run(  # nosec B603
        [binary, "-C", str(root), *args],
        capture_output=True,
        timeout=20,
        env={**os.environ, "LC_ALL": "C"},
    )


def audit_credentials(
    path: str = ".", secret_paths: Iterable[str] | None = None
) -> dict:
    """Check permissions and staged/tracked plaintext credentials without mutation.

    ``secret_paths`` names additional sensitive files/directories, relative to
    ``path`` or absolute. Explicit external directories are allowed; discovered
    directory symlinks are never traversed. Git blobs, not decrypted working
    copies, determine whether tracked content contains plaintext credentials.
    A configured encryption filter alone is not treated as proof of encryption.
    """
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Credential audit requires an existing directory.")
    findings = []
    issues = []
    checked = set()
    candidates = set()
    git_state = "skipped_not_repository"
    truncated = False
    index = {}

    def label(target):
        try:
            return str(target.relative_to(root)) or "."
        except ValueError:
            return str(target)

    def issue(code, target):
        issues.append(
            {
                "code": code,
                "file": label(target),
                "severity": "error",
                "message": "Could not complete this check; inspect access and coverage.",
            }
        )

    def permission(target):
        if target in checked:
            return
        checked.add(target)
        try:
            info = target.stat()
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                findings.append(
                    {
                        "code": "CRED_OWNER",
                        "file": label(target),
                        "severity": "warning",
                        "message": "Sensitive path is owned by another user.",
                    }
                )
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o077:
                findings.append(
                    {
                        "code": "CRED_PERMISSIONS",
                        "file": label(target),
                        "severity": "high",
                        "mode": f"{mode:04o}",
                        "message": "Sensitive path allows group or other access.",
                    }
                )
        except OSError:
            issue("CRED_STAT_ERROR", target)

    def discover(target):
        nonlocal truncated
        if len(checked) >= _MAX_FILES:
            truncated = True
            return
        if target.is_symlink():
            # Inspect the explicitly supplied symlink target's permissions, but
            # never recursively follow directory links into another tree.
            if target.exists():
                permission(target)
                if target.is_file():
                    candidates.add(target)
            else:
                issue("CRED_BROKEN_LINK", target)
            return
        if not target.exists():
            return
        if target.is_file():
            if len(candidates) >= _MAX_FILES:
                truncated = True
                return
            candidates.add(target)
            permission(target)
            return
        permission(target)
        try:
            for child in sorted(target.iterdir()):
                if child.is_symlink():
                    continue
                if len(candidates) >= _MAX_FILES:
                    truncated = True
                    break
                discover(child)
        except OSError:
            issue("CRED_LIST_ERROR", target)

    try:
        listed = _git(root, "ls-files", "--stage", "-z")
        if listed.returncode == 0:
            git_state = "checked_index"
            for record in listed.stdout.split(b"\x00"):
                if not record:
                    continue
                meta, name = record.split(b"\t", 1)
                rel = os.fsdecode(name)
                if not _credential_path(rel):
                    continue
                mode, oid, stage = meta.split()
                if stage != b"0":
                    issue("CRED_UNMERGED_INDEX", root / rel)
                    continue
                if mode == b"120000":
                    continue  # The index stores a link name, not its target's bytes.
                if len(index) >= _MAX_FILES:
                    truncated = True
                    break
                index[rel] = oid.decode("ascii")
                target = root / rel
                if target.exists():
                    permission(target)
                    candidates.add(target)
        elif (
            listed.returncode != 128
            or b"not a git repository" not in listed.stderr.lower()
        ):
            git_state = "error"
            issue("CRED_GIT_ERROR", root)
    except (OSError, subprocess.TimeoutExpired):
        git_state = "error"
        issue("CRED_GIT_ERROR", root)

    defaults = [
        root / ".env",
        root / ".bash.d/secrets",
        root / ".ssh",
        root / ".aws/credentials",
    ]
    # Do not classify public SSH keys or SSH configuration as secrets.
    for target in defaults:
        if target.name == ".ssh" and target.is_dir() and not target.is_symlink():
            permission(target)
            try:
                for child in target.iterdir():
                    if _credential_path(str(child)):
                        discover(child)
            except OSError:
                issue("CRED_LIST_ERROR", target)
        else:
            discover(target)
    for name in secret_paths or ():
        target = Path(name).expanduser()
        discover(target if target.is_absolute() else root / target)

    for target in sorted(candidates):
        try:
            if target.stat().st_size > _MAX_BYTES:
                truncated = True
                continue
            data = target.read_bytes()
            if _literal_lines(data):
                findings.append(
                    {
                        "code": "CRED_PLAINTEXT_STORAGE",
                        "file": label(target),
                        "severity": "warning",
                        "message": "Sensitive working file contains a potential literal credential assignment.",
                    }
                )
            if _private_key_lines(data):
                findings.append(
                    {
                        "code": "CRED_PRIVATE_KEY_STORAGE",
                        "file": label(target),
                        "severity": "info",
                        "message": "A private-key container is present; key encryption is not assessed.",
                    }
                )
        except OSError:
            issue("CRED_READ_ERROR", target)

    blobs_checked = 0
    for rel, oid in index.items():
        try:
            size = _git(root, "cat-file", "-s", oid)
            if size.returncode or not size.stdout.strip().isdigit():
                issue("CRED_GIT_BLOB_ERROR", root / rel)
                continue
            if int(size.stdout) > _MAX_BYTES:
                truncated = True
                continue
            blob = _git(root, "cat-file", "blob", oid)
            if blob.returncode:
                issue("CRED_GIT_BLOB_ERROR", root / rel)
                continue
            blobs_checked += 1
            for line in _literal_lines(blob.stdout):
                findings.append(
                    {
                        "code": "CRED_TRACKED_PLAINTEXT",
                        "file": rel,
                        "line": line,
                        "severity": "high",
                        "message": "Git index contains a potential literal credential or private key.",
                    }
                )
            for line in _private_key_lines(blob.stdout):
                findings.append(
                    {
                        "code": "CRED_TRACKED_PRIVATE_KEY",
                        "file": rel,
                        "line": line,
                        "severity": "high",
                        "message": "Git index contains a private-key container; key encryption is not assessed.",
                    }
                )
        except (OSError, subprocess.TimeoutExpired):
            issue("CRED_GIT_BLOB_ERROR", root / rel)
    if truncated:
        issues.append(
            {
                "code": "CRED_COVERAGE_LIMIT",
                "severity": "error",
                "message": "File count or blob size limit reached; the audit is incomplete.",
            }
        )
    return {
        "status": "error"
        if issues
        else "findings"
        if findings
        else "ok"
        if checked or git_state == "checked_index"
        else "skipped",
        "findings": findings + issues,
        "summary": f"{len(findings)} credential hygiene findings; {len(issues)} incomplete checks.",
        "coverage": {
            "permission_paths": len(checked),
            "git_blobs": blobs_checked,
            "git": git_state,
            "git_history": "not_checked",
            "max_files": _MAX_FILES,
            "max_blob_bytes": _MAX_BYTES,
            "truncated": truncated,
            "values_omitted": True,
        },
    }
