#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_logic.py

"""Pure decision logic of rotate-credential (no I/O, no subprocesses).

Kept apart from the side-effecting steps so every safety rule -- value
shape, exact-assignment replacement, "the loaded environment changed in
exactly the named variables", "the manifest grows by exactly one entry"
-- is testable with plain in-memory fixtures.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Set

from ._common import Abort

#: Accepted value shapes per credential kind.
SHAPES: Dict[str, "re.Pattern[str]"] = {
    # Fine-grained GitHub PAT: github_pat_ + 82 word characters.
    "github-pat": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "generic": re.compile(r"[\x21-\x7e]{16,4096}"),
}

_VAR_RE = re.compile(r"[A-Z_][A-Z0-9_]*")

#: Separator between the exported environment and the function hash in
#: the clean-bash probe output (see ``_crypto.load_env``).
FUNCS_MARKER = b"\0__FUNCS__\0"


def parse_variables(
    payload: str, variables: str, payload_re: "re.Pattern[str]"
) -> List[str]:
    """Validate the PAYLOAD / VARS arguments and return the variable names.

    Raises
    ------
    Abort
        If the payload name does not match ``payload_re`` or a name is not
        an upper-case shell identifier.
    """
    names = [n for n in variables.split(",") if n]
    if not payload_re.fullmatch(payload):
        raise Abort(f"payload must match {payload_re.pattern}")
    if not names or not all(_VAR_RE.fullmatch(n) for n in names):
        raise Abort("VARS must be comma-separated upper-case variable names")
    if len(set(names)) != len(names):
        raise Abort("VARS lists a variable twice")
    return names


def infer_kind(
    names: Sequence[str], pat_variables: Iterable[str], pat_prefixes: Iterable[str]
) -> str:
    """``github-pat`` when every name is a configured GitHub-token variable, else ``generic``."""
    exact = set(pat_variables)
    prefixes = tuple(pat_prefixes)
    if all(n in exact or (prefixes and n.startswith(prefixes)) for n in names):
        return "github-pat"
    return "generic"


def shape_ok(value: str, kind: str) -> bool:
    """Whether ``value`` has the expected shape for ``kind``."""
    if kind not in SHAPES:
        raise Abort(f"unknown credential kind: {kind}")
    return bool(SHAPES[kind].fullmatch(value))


def replace_values(text: str, names: Sequence[str], value: str) -> str:
    """Replace the single assignment of each name with ``name=<quoted value>``.

    Keeps an optional leading ``export`` and indentation.

    Raises
    ------
    Abort
        If a name is assigned zero or several times.
    """
    out = text
    for name in names:
        pattern = re.compile(
            r"^(?P<pre>[ \t]*(?:export[ \t]+)?)" + re.escape(name) + r"=.*$",
            re.MULTILINE,
        )
        hits = pattern.findall(out)
        if len(hits) != 1:
            raise Abort(f"{name}: expected exactly one assignment, found {len(hits)}")
        out = pattern.sub(
            lambda m: m.group("pre") + name + "=" + shlex.quote(value), out
        )
    return out


@dataclass(frozen=True)
class LoadedEnv:
    """Result of loading a payload in clean bash (in memory only)."""

    status: bytes
    env: Dict[str, bytes]
    functions_sha256: bytes


def parse_probe_output(stdout: bytes) -> LoadedEnv:
    """Parse ``<status>\\0<env -0>\\0__FUNCS__\\0<sha256sum of declare -f>``."""
    head, _, funcs = stdout.partition(FUNCS_MARKER)
    fields = head.split(b"\0")
    env: Dict[str, bytes] = {}
    for entry in (f for f in fields[1:] if f):
        key, _, val = entry.partition(b"=")
        env[key.decode()] = val
    return LoadedEnv(status=fields[0], env=env, functions_sha256=funcs.strip())


def changed_names(old: Mapping[str, bytes], new: Mapping[str, bytes]) -> Set[str]:
    """Names whose exported value differs (added, removed or changed)."""
    return {k for k in set(old) | set(new) if old.get(k) != new.get(k)}


def check_env_diff(
    old: LoadedEnv, new: LoadedEnv, names: Sequence[str], value: str
) -> Set[str]:
    """Require that loading changed exactly ``names``, to exactly ``value``.

    Returns the changed names (for reporting).

    Raises
    ------
    Abort
        If load status or functions differ, any other variable changed, a
        named variable did not get ``value``, or already had it.
    """
    changed = changed_names(old.env, new.env)
    if old.status != new.status or changed != set(names):
        raise Abort("loaded environment differs beyond the named variables")
    if old.functions_sha256 != new.functions_sha256:
        raise Abort("shell functions differ after replacement")
    encoded = value.encode()
    if any(new.env.get(n) != encoded for n in names):
        raise Abort("new value not loaded exactly")
    if any(old.env.get(n) == encoded for n in names):
        raise Abort("new value equals the current value")
    return changed


def manifest_plus_one(
    installed: Mapping, old_name: str, new_name: str, cipher_sha256: str
) -> bytes:
    """Candidate manifest: ``installed`` plus one entry for ``new_name``.

    The new entry copies the old payload's entry (identity, recipients,
    ...) with the new ciphertext hash. The old entry stays until every
    host has pulled the repointed shim.

    Raises
    ------
    Abort
        If ``old_name`` is absent or ``new_name`` already present.
    """
    doc = json.loads(json.dumps(installed))
    payloads = doc.get("payloads")
    if (
        not isinstance(payloads, dict)
        or old_name not in payloads
        or new_name in payloads
    ):
        raise Abort("manifest state unexpected")
    entry = dict(payloads[old_name])
    entry["ciphertext_sha256"] = cipher_sha256
    payloads[new_name] = entry
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


def manifest_delta_is_plus_one(
    installed: Mapping, candidate: Mapping, new_name: str
) -> bool:
    """True iff ``candidate`` = ``installed`` + exactly the ``new_name`` payload entry.

    Same rule the per-host installer enforces before replacing the
    installed manifest; checked here too before anything is signed.
    """
    a = installed.get("payloads") or {}
    b = candidate.get("payloads") or {}
    other_keys_same = {k: v for k, v in installed.items() if k != "payloads"} == {
        k: v for k, v in candidate.items() if k != "payloads"
    }
    added, removed = set(b) - set(a), set(a) - set(b)
    changed = [k for k in set(a) & set(b) if a[k] != b[k]]
    return other_keys_same and added == {new_name} and not removed and not changed


def payload_tag(name: str, prefix: str) -> str:
    """Short tag for branch / directory names: first 8 hex chars after ``prefix``."""
    return name[len(prefix) : len(prefix) + 8]


# EOF
