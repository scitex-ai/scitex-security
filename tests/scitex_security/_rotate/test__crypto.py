"""Clean-bash load + hidden-prompt intake tests (fake payloads; no keys, no gpg)."""

import os
import subprocess
import sys
from pathlib import Path

import scitex_security
from scitex_security._rotate._crypto import load_env
from scitex_security._rotate._logic import check_env_diff, replace_values

FAKE_VALUE = "fake-new-value-0123456789"
PAYLOAD = (
    "export A=1\n"
    "export GH_TOKEN=fake-old-value-0123456789\n"
    "greet() { echo hi; }\n"
    "export B=2\n"
)


def test_clean_bash_load_reads_exported_variable():
    # Arrange
    payload = PAYLOAD.encode()
    # Act
    loaded = load_env(payload)
    # Assert
    assert loaded.env["A"] == b"1"


def test_real_replacement_changes_exactly_the_named_variable():
    # Arrange
    old = load_env(PAYLOAD.encode())
    new = load_env(replace_values(PAYLOAD, ["GH_TOKEN"], FAKE_VALUE).encode())
    # Act
    changed = check_env_diff(old, new, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert changed == {"GH_TOKEN"}


def test_clean_bash_load_hashes_functions_identically_after_replacement():
    # Arrange
    old = load_env(PAYLOAD.encode())
    # Act
    new = load_env(replace_values(PAYLOAD, ["GH_TOKEN"], FAKE_VALUE).encode())
    # Assert
    assert new.functions_sha256 == old.functions_sha256


def test_value_is_never_read_from_a_pipe_without_a_terminal():
    # Arrange
    pkg_parent = str(Path(scitex_security.__file__).resolve().parent.parent)
    env = {"PATH": os.environ.get("PATH", "/usr/bin"), "PYTHONPATH": pkg_parent}
    code = "from scitex_security._rotate._crypto import read_value; read_value(['GH_TOKEN'])"
    # Act
    proc = subprocess.run(
        [sys.executable, "-c", code],
        input=FAKE_VALUE + "\n",
        capture_output=True,
        text=True,
        env=env,
        start_new_session=True,
        timeout=30,
    )
    # Assert
    assert "no controlling terminal" in proc.stderr
