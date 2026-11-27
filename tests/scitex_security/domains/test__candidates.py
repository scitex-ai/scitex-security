"""Tests for look-alike candidate generation (pure, no network)."""

import pytest

from scitex_security.domains._candidates import (
    adjacent_keys,
    generate_lookalike_domains,
    homoglyph_swaps,
    omissions,
    registrable_domain,
    repetitions,
    split_domain,
    to_ascii,
    transpositions,
)


def _names(domain, **kw):
    return {c.ascii for c in generate_lookalike_domains(domain, **kw)}


def test_split_domain_keeps_two_label_registry_suffix():
    # Arrange
    domain = "www.example.co.jp"
    # Act
    parts = split_domain(domain)
    # Assert
    assert parts == ("example", "co.jp")


def test_split_domain_rejects_single_label():
    # Arrange
    domain = "localhost"
    # Act
    expected = ValueError
    # Assert
    with pytest.raises(expected):
        split_domain(domain)


def test_registrable_domain_strips_wildcard_and_subdomains():
    # Arrange
    name = "*.mail.example-ai.com"
    # Act
    base = registrable_domain(name)
    # Assert
    assert base == "example-ai.com"


def test_omissions_drop_each_character_once():
    # Arrange
    label = "abc"
    # Act
    out = [x for x, _ in omissions(label)]
    # Assert
    assert out == ["bc", "ac", "ab"]


def test_repetitions_double_each_character():
    # Arrange
    label = "ab"
    # Act
    out = [x for x, _ in repetitions(label)]
    # Assert
    assert out == ["aab", "abb"]


def test_transpositions_swap_neighbours():
    # Arrange
    label = "abc"
    # Act
    out = [x for x, _ in transpositions(label)]
    # Assert
    assert out == ["bac", "acb"]


def test_adjacent_keys_use_qwerty_neighbours():
    # Arrange
    label = "s"
    # Act
    out = {x for x, _ in adjacent_keys(label)}
    # Assert
    assert out == {"q", "w", "e", "a", "d", "z", "x", "c"}


def test_homoglyphs_include_cyrillic_single_letter():
    # Arrange
    label = "scitex"
    # Act
    out = {x for x, _ in homoglyph_swaps(label)}
    # Assert
    assert "sсitex" in out  # U+0441 CYRILLIC SMALL LETTER ES


def test_homoglyphs_include_all_cyrillic_spelling():
    # Arrange
    label = "scitex"
    # Act
    out = {x for x, _ in homoglyph_swaps(label)}
    # Assert
    assert "ѕсіtех" in out


def test_homoglyphs_include_ascii_rn_for_m():
    # Arrange
    label = "team"
    # Act
    out = {x for x, _ in homoglyph_swaps(label)}
    # Assert
    assert "tearn" in out


def test_to_ascii_produces_punycode():
    # Arrange
    name = "sсitex.ai"
    # Act
    encoded = to_ascii(name)
    # Assert
    assert encoded == "xn--sitex-1ye.ai"


def test_to_ascii_rejects_leading_hyphen():
    # Arrange
    name = "-example.com"
    # Act
    encoded = to_ascii(name)
    # Assert
    assert encoded is None


def test_generate_never_returns_the_input():
    # Arrange
    domain = "example.ai"
    # Act
    names = _names(domain)
    # Assert
    assert domain not in names


def test_generate_swaps_tlds():
    # Arrange
    domain = "example.ai"
    # Act
    names = _names(domain, kinds=["tld-swap"])
    # Assert
    assert {"example.com", "example.io", "example.co.jp"} <= names


def test_generate_folds_tld_into_label():
    # Arrange
    domain = "example.ai"
    # Act
    names = _names(domain, kinds=["affix"])
    # Assert
    assert {"example-ai.com", "exampleai.com", "getexample.ai"} <= names


def test_generate_hyphenates_inside_label():
    # Arrange
    domain = "example.ai"
    # Act
    names = _names(domain, kinds=["hyphenation"])
    # Assert
    assert "exam-ple.com" in names


def test_generate_rejects_unknown_kind():
    # Arrange
    domain = "example.ai"
    # Act
    expected = ValueError
    # Assert
    with pytest.raises(expected):
        generate_lookalike_domains(domain, kinds=["bitflip"])


def test_generate_deduplicates_on_ascii_form():
    # Arrange
    found = generate_lookalike_domains("example.ai")
    # Act
    asciis = [c.ascii for c in found]
    # Assert
    assert len(asciis) == len(set(asciis))
