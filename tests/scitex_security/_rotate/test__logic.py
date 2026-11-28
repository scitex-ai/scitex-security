"""Pure-logic tests for rotate-credential (in-memory fixtures; no keys, no network)."""

import json
import re

from _helpers import raised

from scitex_security._rotate._common import Abort
from scitex_security._rotate._logic import (
    LoadedEnv,
    check_env_diff,
    infer_kind,
    manifest_delta_is_plus_one,
    manifest_plus_one,
    parse_probe_output,
    parse_variables,
    payload_tag,
    replace_values,
    shape_ok,
)

PAYLOAD_RE = re.compile(r"bash-config-[0-9a-f]{24}\.gpg")
OLD = "bash-config-" + "0" * 24 + ".gpg"
NEW = "bash-config-" + "a" * 24 + ".gpg"
# Fake fine-grained PAT shape, assembled so no scanner sees a literal.
FAKE_PAT = "github" + "_pat_" + ("Z9y8X7w6V5" * 9)[:82]
FAKE_VALUE = "fake-new-value-0123456789"


def _installed():
    return {
        "version": 1,
        "payloads": {OLD: {"identity": "shell/x", "ciphertext_sha256": "1" * 64}},
    }


def _env(**values):
    return LoadedEnv(
        status=b"0",
        env={k: v.encode() for k, v in values.items()},
        functions_sha256=b"f" * 64,
    )


# -- argument / shape validation ------------------------------------------


def test_parse_variables_returns_names():
    # Arrange
    variables = "GH_TOKEN,GITHUB_TOKEN"
    # Act
    names = parse_variables(OLD, variables, PAYLOAD_RE)
    # Assert
    assert names == ["GH_TOKEN", "GITHUB_TOKEN"]


def test_parse_variables_rejects_payload_outside_pattern():
    # Arrange
    payload = "../../etc/passwd"
    # Act
    error = raised(parse_variables, payload, "GH_TOKEN", PAYLOAD_RE)
    # Assert
    assert isinstance(error, Abort)


def test_parse_variables_rejects_lower_case_name():
    # Arrange
    variables = "gh_token"
    # Act
    error = raised(parse_variables, OLD, variables, PAYLOAD_RE)
    # Assert
    assert isinstance(error, Abort)


def test_parse_variables_rejects_duplicate_name():
    # Arrange
    variables = "GH_TOKEN,GH_TOKEN"
    # Act
    error = raised(parse_variables, OLD, variables, PAYLOAD_RE)
    # Assert
    assert isinstance(error, Abort)


def test_infer_kind_github_pat_for_configured_names():
    # Arrange
    names = ["GH_TOKEN", "SCITEX_GH_TOKEN_SOMEONE"]
    # Act
    kind = infer_kind(names, ["GH_TOKEN"], ["SCITEX_GH_TOKEN"])
    # Assert
    assert kind == "github-pat"


def test_infer_kind_generic_when_any_name_is_not_a_github_token():
    # Arrange
    names = ["GH_TOKEN", "OPENAI_API_KEY"]
    # Act
    kind = infer_kind(names, ["GH_TOKEN"], [])
    # Assert
    assert kind == "generic"


def test_shape_accepts_fine_grained_pat_of_82_word_chars():
    # Arrange
    value = FAKE_PAT
    # Act
    ok = shape_ok(value, "github-pat")
    # Assert
    assert ok is True


def test_shape_rejects_pat_one_char_short():
    # Arrange
    value = FAKE_PAT[:-1]
    # Act
    ok = shape_ok(value, "github-pat")
    # Assert
    assert ok is False


def test_shape_rejects_generic_value_with_whitespace():
    # Arrange
    value = "has a space inside it ok"
    # Act
    ok = shape_ok(value, "generic")
    # Assert
    assert ok is False


def test_shape_rejects_generic_value_shorter_than_16():
    # Arrange
    value = "x" * 15
    # Act
    ok = shape_ok(value, "generic")
    # Assert
    assert ok is False


# -- payload transform ----------------------------------------------------


def test_replace_values_keeps_export_and_quotes_value():
    # Arrange
    text = "A=1\n  export GH_TOKEN=old\nB=2\n"
    # Act
    out = replace_values(text, ["GH_TOKEN"], "new value'q")
    # Assert
    assert out == "A=1\n  export GH_TOKEN='new value'\"'\"'q'\nB=2\n"


def test_replace_values_aborts_when_name_is_absent():
    # Arrange
    text = "A=1\n"
    # Act
    error = raised(replace_values, text, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


def test_replace_values_aborts_when_name_is_assigned_twice():
    # Arrange
    text = "GH_TOKEN=a\nexport GH_TOKEN=b\n"
    # Act
    error = raised(replace_values, text, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


def test_parse_probe_output_reads_status_env_and_functions():
    # Arrange
    raw = b"0\0A=1\0GH_TOKEN=x=y\0\0__FUNCS__\0" + b"abc  -\n"
    # Act
    loaded = parse_probe_output(raw)
    # Assert
    assert loaded == LoadedEnv(
        status=b"0", env={"A": b"1", "GH_TOKEN": b"x=y"}, functions_sha256=b"abc  -"
    )


# -- env diff must touch exactly the named variables ----------------------


def test_env_diff_accepts_change_of_exactly_the_named_variable():
    # Arrange
    old, new = _env(A="1", GH_TOKEN="old"), _env(A="1", GH_TOKEN=FAKE_VALUE)
    # Act
    changed = check_env_diff(old, new, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert changed == {"GH_TOKEN"}


def test_env_diff_rejects_an_extra_changed_variable():
    # Arrange
    old, new = _env(A="1", GH_TOKEN="old"), _env(A="2", GH_TOKEN=FAKE_VALUE)
    # Act
    error = raised(check_env_diff, old, new, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


def test_env_diff_rejects_a_named_variable_that_did_not_change():
    # Arrange
    old, new = _env(A="old", B="old"), _env(A=FAKE_VALUE, B="old")
    # Act
    error = raised(check_env_diff, old, new, ["A", "B"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


def test_env_diff_rejects_a_value_other_than_the_new_one():
    # Arrange
    old, new = _env(GH_TOKEN="old"), _env(GH_TOKEN="something-else-entirely")
    # Act
    error = raised(check_env_diff, old, new, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


def test_env_diff_rejects_changed_shell_functions():
    # Arrange
    old = _env(GH_TOKEN="old")
    new = LoadedEnv(
        status=b"0", env={"GH_TOKEN": FAKE_VALUE.encode()}, functions_sha256=b"e" * 64
    )
    # Act
    error = raised(check_env_diff, old, new, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


def test_env_diff_rejects_changed_load_status():
    # Arrange
    old = _env(GH_TOKEN="old")
    new = LoadedEnv(
        status=b"1", env={"GH_TOKEN": FAKE_VALUE.encode()}, functions_sha256=b"f" * 64
    )
    # Act
    error = raised(check_env_diff, old, new, ["GH_TOKEN"], FAKE_VALUE)
    # Assert
    assert isinstance(error, Abort)


# -- manifest delta exactly +1 --------------------------------------------


def test_manifest_plus_one_adds_exactly_the_new_entry():
    # Arrange
    installed = _installed()
    # Act
    candidate = json.loads(manifest_plus_one(installed, OLD, NEW, "2" * 64))
    # Assert
    assert manifest_delta_is_plus_one(installed, candidate, NEW) is True


def test_manifest_plus_one_copies_old_entry_with_new_hash():
    # Arrange
    installed = _installed()
    # Act
    candidate = json.loads(manifest_plus_one(installed, OLD, NEW, "2" * 64))
    # Assert
    assert candidate["payloads"][NEW] == {
        "identity": "shell/x",
        "ciphertext_sha256": "2" * 64,
    }


def test_manifest_plus_one_does_not_mutate_installed():
    # Arrange
    installed = _installed()
    # Act
    manifest_plus_one(installed, OLD, NEW, "2" * 64)
    # Assert
    assert installed == _installed()


def test_manifest_plus_one_aborts_when_old_payload_unknown():
    # Arrange
    installed = {"payloads": {}}
    # Act
    error = raised(manifest_plus_one, installed, OLD, NEW, "2" * 64)
    # Assert
    assert isinstance(error, Abort)


def test_delta_rejects_a_modified_existing_entry():
    # Arrange
    candidate = json.loads(manifest_plus_one(_installed(), OLD, NEW, "2" * 64))
    candidate["payloads"][OLD]["ciphertext_sha256"] = "3" * 64
    # Act
    ok = manifest_delta_is_plus_one(_installed(), candidate, NEW)
    # Assert
    assert ok is False


def test_delta_rejects_a_removed_entry():
    # Arrange
    candidate = {"version": 1, "payloads": {NEW: {"identity": "shell/x"}}}
    # Act
    ok = manifest_delta_is_plus_one(_installed(), candidate, NEW)
    # Assert
    assert ok is False


def test_delta_rejects_two_added_entries():
    # Arrange
    candidate = json.loads(manifest_plus_one(_installed(), OLD, NEW, "2" * 64))
    candidate["payloads"]["bash-config-" + "b" * 24 + ".gpg"] = {}
    # Act
    ok = manifest_delta_is_plus_one(_installed(), candidate, NEW)
    # Assert
    assert ok is False


def test_delta_rejects_a_changed_top_level_field():
    # Arrange
    candidate = json.loads(manifest_plus_one(_installed(), OLD, NEW, "2" * 64))
    candidate["version"] = 2
    # Act
    ok = manifest_delta_is_plus_one(_installed(), candidate, NEW)
    # Assert
    assert ok is False


def test_payload_tag_is_first_eight_hex_after_prefix():
    # Arrange
    name = "bash-config-0123456789abcdef01234567.gpg"
    # Act
    tag = payload_tag(name, "bash-config-")
    # Assert
    assert tag == "01234567"
