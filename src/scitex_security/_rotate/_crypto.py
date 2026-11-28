#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_crypto.py

"""Value intake, verified decrypt, clean-bash load, encryption and signing.

Plaintext and the new value stay in this process's memory; subprocesses
receive them only on stdin. Nothing here reports a value.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from typing import Optional, Set, Tuple

from ._common import CHANNEL, EVENT_READY_FOR_SECRET, Abort, run, safe_env, say
from ._logic import LoadedEnv, parse_probe_output
from ._settings import RotateSettings

_TTY = "/dev/tty"


def _home() -> Path:
    return Path.home()


def expand(path: str) -> Path:
    """``~``-expanded path."""
    return Path(path).expanduser()


def read_value(names) -> str:
    """Read the new value from ONE hidden prompt on the controlling terminal.

    Never argv, environment, a file or a pipe: without a usable
    ``/dev/tty`` (or if getpass would fall back to an echoing stream) the
    rotation aborts.
    """
    try:
        fd = os.open(_TTY, os.O_RDWR | os.O_NOCTTY)
    except OSError:
        raise Abort(
            "no controlling terminal; the value is read from a hidden prompt only"
        ) from None
    os.close(fd)
    CHANNEL.request(EVENT_READY_FOR_SECRET)
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            # audit-cli: interactive-ok -- operator decision: the value comes ONLY from a hidden prompt
            value = getpass.getpass(f"New value for {','.join(names)} (input hidden): ")
        except getpass.GetPassWarning:
            raise Abort("terminal cannot hide input; nothing read") from None
    value = value.strip("\r\n")
    if not value:
        raise Abort("empty value")
    return value


def check_github_pat(value: str) -> Tuple[Optional[int], Optional[str]]:
    """``GET /user`` in-process (the header never reaches argv). Returns ``(status, login)``."""
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": "Bearer " + value,
            "Accept": "application/vnd.github+json",
            "User-Agent": "scitex-rotate-credential",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as err:
        status, body = err.code, b""
    except (urllib.error.URLError, OSError):
        return None, None
    login = None
    if status == 200:
        try:
            login = json.loads(body).get("login")
        except ValueError:
            login = None
    return status, login


def decrypt_current(cfg: RotateSettings, name: str) -> Tuple[bytes, bytes]:
    """Verified decrypt of the current payload via the root-owned verifier."""
    cipher = expand(cfg.payload_dir) / name
    if not cipher.is_file():
        raise Abort(f"ciphertext not found: {cipher}")
    proc = run(
        [cfg.python, "-I", cfg.verifier, name, str(cipher)], what="verified decrypt"
    )
    return proc.stdout, cipher.read_bytes()


_PROBE = (
    'eval "$(cat)" >/dev/null 2>&1; s=$?; printf "%s\\0" "$s"; env -0; '
    'printf "\\0__FUNCS__\\0"; declare -f | sha256sum'
)


def load_env(payload: bytes) -> LoadedEnv:
    """Load a payload in a clean bash; return status, exported env, functions hash."""
    proc = run(
        [
            "/usr/bin/env",
            "-i",
            "HOME=" + str(_home()),
            "PATH=/usr/bin:/bin",
            "LANG=C",
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            _PROBE,
        ],
        data=payload,
        what="bash load",
    )
    return parse_probe_output(proc.stdout)


def keyids(cipher: bytes) -> Set[str]:
    """Recipient key ids of an OpenPGP message."""
    proc = run(["gpg", "--batch", "--list-packets"], data=cipher, check=False)
    return set(
        re.findall(
            r"keyid ([0-9A-F]{16})",
            (proc.stdout + proc.stderr).decode(errors="replace"),
        )
    )


def encrypt_same_recipients(
    cfg: RotateSettings, plain: bytes, old_cipher: bytes
) -> bytes:
    """Encrypt to the dotfiles host recipients; require round-trip and same key set."""
    fprs = [
        p.read_text().strip()
        for p in sorted(expand(cfg.dotfiles_dir).glob(cfg.recipient_fingerprints_glob))
    ]
    if not fprs:
        raise Abort("no host recipient fingerprints found")
    if (
        cfg.expected_recipient_count is not None
        and len(fprs) != cfg.expected_recipient_count
    ):
        raise Abort(
            f"expected {cfg.expected_recipient_count} host recipients, found {len(fprs)}"
        )
    args = ["gpg", "--batch", "--yes", "--armor", "--trust-model", "always"]
    for fpr in fprs:
        args += ["--recipient", fpr]
    env = dict(
        safe_env(_home()),
        GNUPGHOME=os.environ.get("GNUPGHOME", str(_home() / ".gnupg")),
    )
    cipher = run(args + ["--encrypt"], data=plain, env=env, what="encrypt").stdout
    back = run(
        ["gpg", "--batch", "--quiet", "--decrypt"],
        data=cipher,
        env=env,
        what="round-trip decrypt",
    )
    if back.stdout != plain:
        raise Abort("round-trip mismatch")
    if keyids(cipher) != keyids(old_cipher):
        raise Abort("recipient key set differs from current ciphertext")
    say("recipients: same", len(keyids(cipher)), "key ids; round-trip ok")
    return cipher


def installed_manifest(cfg: RotateSettings) -> dict:
    """The manifest currently installed in the root-owned trust directory."""
    return json.loads((Path(cfg.trust_dir) / "manifest.json").read_text())


def signer_available(cfg: RotateSettings) -> bool:
    """Whether the controller-only issuer secret key is usable (non-interactive sudo)."""
    proc = run(
        [
            "sudo",
            "-n",
            "gpg",
            "--homedir",
            cfg.signing_home,
            "--batch",
            "--with-colons",
            "--list-secret-keys",
            cfg.issuer_fingerprint,
        ],
        check=False,
    )
    return proc.returncode == 0


def sign(cfg: RotateSettings, work: Path, manifest: bytes) -> bytes:
    """Detach-sign ``manifest`` with the issuer key and require gpgv VALIDSIG of its primary."""
    (work / "manifest.json").write_bytes(manifest)
    sig = run(
        [
            "sudo",
            "-n",
            "gpg",
            "--homedir",
            cfg.signing_home,
            "--batch",
            "--pinentry-mode",
            "error",
            "--yes",
            "--local-user",
            cfg.issuer_fingerprint,
            "--detach-sign",
            "--output",
            "-",
            str(work / "manifest.json"),
        ],
        what="sign",
    ).stdout
    (work / "manifest.json.sig").write_bytes(sig)
    status = run(
        [
            cfg.gpgv,
            "--keyring",
            str(Path(cfg.trust_dir) / "issuer.gpg"),
            "--status-fd",
            "1",
            str(work / "manifest.json.sig"),
            str(work / "manifest.json"),
        ],
        check=False,
    )
    valid = [
        line.split()[-1]
        for line in status.stdout.decode().splitlines()
        if " VALIDSIG " in line
    ]
    if valid != [cfg.issuer_fingerprint]:
        raise Abort("gpgv VALIDSIG check failed")
    say("VALIDSIG primary", cfg.issuer_fingerprint)
    return sig


# EOF
