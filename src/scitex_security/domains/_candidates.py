#!/usr/bin/env python3
# File: src/scitex_security/domains/_candidates.py

"""Look-alike domain generation: typos, homoglyphs, TLD swaps, affixes.

Pure functions of the input domain. Nothing here touches the network, and
nothing is specific to any one organisation: every word list is a default
argument the caller can replace.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Sequence

#: Registry suffixes made of two labels. A small built-in list keeps the
#: package free of a public-suffix-list dependency; extend it per call.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp",
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "com.br", "com.cn", "com.sg", "co.kr", "co.in", "com.tw",
    }
)  # fmt: skip

#: TLDs tried for every base label.
DEFAULT_TLDS = (
    "ai", "com", "io", "co", "app", "dev", "net", "org", "jp", "co.jp",
)  # fmt: skip

#: Words people put in front of a brand to make a believable domain.
DEFAULT_PREFIXES = (
    "get", "try", "my", "the", "go", "use", "join", "app", "mail", "login",
    "secure", "support", "team",
)  # fmt: skip

#: Words people put after a brand.
DEFAULT_SUFFIXES = (
    "app", "ai", "jp", "hq", "inc", "corp", "team", "mail", "login", "support",
    "help", "official", "account", "billing", "auth", "online",
)  # fmt: skip

#: Single characters that render like a Latin letter. Cyrillic and Greek
#: first (they are what an IDN homograph uses), then accented Latin.
HOMOGLYPHS: dict = {
    "a": "аɑàáâãäåα",
    "b": "Ьḃ",
    "c": "сϲçć",
    "d": "ԁď",
    "e": "еéèêëēė",
    "g": "ġɡ",
    "h": "һ",
    "i": "іıíìïî",
    "j": "ј",
    "k": "κ",
    "l": "ӏĺ",
    "m": "м",
    "n": "ոńñ",
    "o": "оοöóòôõ",
    "p": "рρ",
    "q": "ԛ",
    "r": "г",
    "s": "ѕś",
    "t": "ţť",
    "u": "υüúùû",
    "v": "ν",
    "w": "ԝω",
    "x": "хχ",
    "y": "уý",
    "z": "ż",
}

#: Character groups that pass for one another in plain ASCII.
ASCII_LOOKALIKES = (
    ("m", "rn"), ("w", "vv"), ("d", "cl"), ("l", "1"), ("l", "i"),
    ("i", "1"), ("i", "l"), ("o", "0"), ("g", "q"), ("u", "v"),
)  # fmt: skip

#: Cyrillic letters that are visually identical to a Latin lowercase letter.
CYRILLIC_IDENTICAL = {
    "a": "а", "c": "с", "e": "е", "i": "і", "j": "ј", "o": "о", "p": "р",
    "s": "ѕ", "x": "х", "y": "у", "h": "һ", "d": "ԁ", "q": "ԛ", "w": "ԝ",
}  # fmt: skip

_QWERTY_ROWS = ("1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm")


def _qwerty_neighbours() -> dict:
    grid = {
        ch: (r, c) for r, row in enumerate(_QWERTY_ROWS) for c, ch in enumerate(row)
    }
    out: dict = {}
    for ch, (r, c) in grid.items():
        near = []
        for dr in (-1, 0, 1):
            for dc in (-1, 0, 1):
                if (dr, dc) == (0, 0):
                    continue
                rr, cc = r + dr, c + dc
                if 0 <= rr < len(_QWERTY_ROWS) and 0 <= cc < len(_QWERTY_ROWS[rr]):
                    near.append(_QWERTY_ROWS[rr][cc])
        out[ch] = "".join(near)
    return out


QWERTY_NEIGHBOURS = _qwerty_neighbours()


@dataclass(frozen=True)
class Candidate:
    """One look-alike name.

    ``name`` is what a person sees (may contain non-ASCII); ``ascii`` is
    the IDNA/punycode form DNS uses. ``kind`` names the generator and
    ``detail`` says what it changed.
    """

    name: str
    ascii: str
    kind: str
    detail: str = ""

    @property
    def is_idn(self) -> bool:
        return self.ascii != self.name


def split_domain(
    domain: str, suffixes: Iterable[str] = MULTI_LABEL_SUFFIXES
) -> tuple[str, str]:
    """``"scitex.co.jp"`` -> ``("scitex", "co.jp")``; ``"a.b.ai"`` -> ``("b", "ai")``.

    Only the registrable label is varied; deeper subdomains are dropped.
    """
    labels = domain.strip().strip(".").lower().split(".")
    if len(labels) < 2 or not all(labels):
        raise ValueError(f"not a registrable domain: {domain!r}")
    if len(labels) >= 3 and ".".join(labels[-2:]) in set(suffixes):
        return labels[-3], ".".join(labels[-2:])
    return labels[-2], labels[-1]


def registrable_domain(
    name: str, suffixes: Iterable[str] = MULTI_LABEL_SUFFIXES
) -> Optional[str]:
    """The registrable part of ``name`` (``www.x.co.jp`` -> ``x.co.jp``), or None."""
    name = name.strip().lstrip("*.").rstrip(".").lower()
    try:
        label, tld = split_domain(name, suffixes)
    except ValueError:
        return None
    return f"{label}.{tld}"


def to_ascii(domain: str) -> Optional[str]:
    """IDNA (punycode) form of ``domain``, or None when it is not encodable."""
    try:
        encoded = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    for label in encoded.split("."):
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return None
        if not all(c.isalnum() or c == "-" for c in label):
            return None
    return encoded


# ------------------------------------------------------------ label edits ---


def omissions(label: str) -> Iterator[tuple[str, str]]:
    for i in range(len(label)):
        yield label[:i] + label[i + 1 :], f"drop {label[i]!r} at {i}"


def repetitions(label: str) -> Iterator[tuple[str, str]]:
    for i, ch in enumerate(label):
        if ch != "-":
            yield label[: i + 1] + ch + label[i + 1 :], f"repeat {ch!r} at {i}"


def transpositions(label: str) -> Iterator[tuple[str, str]]:
    for i in range(len(label) - 1):
        a, b = label[i], label[i + 1]
        if a != b:
            yield label[:i] + b + a + label[i + 2 :], f"swap {a!r}{b!r} at {i}"


def adjacent_keys(label: str) -> Iterator[tuple[str, str]]:
    for i, ch in enumerate(label):
        for near in QWERTY_NEIGHBOURS.get(ch, ""):
            yield label[:i] + near + label[i + 1 :], f"{ch!r}->{near!r} at {i}"


def homoglyph_swaps(label: str) -> Iterator[tuple[str, str]]:
    """One character replaced by a Unicode look-alike, plus ASCII look-alikes,
    plus the all-Cyrillic spelling (every letter with an identical Cyrillic
    twin replaced at once)."""
    for i, ch in enumerate(label):
        for glyph in HOMOGLYPHS.get(ch, ""):
            yield (
                label[:i] + glyph + label[i + 1 :],
                f"{ch!r}->U+{ord(glyph):04X} at {i}",
            )
    for latin, fake in ASCII_LOOKALIKES:
        start = label.find(latin)
        while start != -1:
            yield (
                label[:start] + fake + label[start + len(latin) :],
                f"{latin!r}->{fake!r} at {start}",
            )
            start = label.find(latin, start + 1)
    whole = "".join(CYRILLIC_IDENTICAL.get(ch, ch) for ch in label)
    if whole != label:
        yield whole, "all Cyrillic look-alikes"


def hyphenations(label: str) -> Iterator[tuple[str, str]]:
    for i in range(1, len(label)):
        if "-" not in (label[i - 1], label[i]):
            yield label[:i] + "-" + label[i:], f"hyphen at {i}"
    if "-" in label:
        yield label.replace("-", ""), "hyphens removed"


def affixations(
    label: str,
    tld: str,
    prefixes: Sequence[str] = DEFAULT_PREFIXES,
    suffixes: Sequence[str] = DEFAULT_SUFFIXES,
) -> Iterator[tuple[str, str]]:
    """``get`` + label, label + ``app``, with and without a hyphen, and the
    original TLD folded into the label (``example.ai`` -> ``exampleai``,
    ``example-ai``)."""
    for word in prefixes:
        for sep in ("", "-"):
            yield f"{word}{sep}{label}", f"prefix {word!r}"
    for word in dict.fromkeys([*suffixes, tld.replace(".", "")]):
        for sep in ("", "-"):
            yield f"{label}{sep}{word}", f"suffix {word!r}"


#: Generator name -> (function, applies to which TLDs).
#: ``"home"`` = the domain's own TLD plus ``.com``; ``"all"`` = every TLD.
GENERATORS = {
    "omission": (omissions, "home"),
    "repetition": (repetitions, "home"),
    "transposition": (transpositions, "home"),
    "adjacent-key": (adjacent_keys, "home"),
    "homoglyph": (homoglyph_swaps, "home"),
    "hyphenation": (hyphenations, "all"),
    "affix": (None, "all"),
}


def generate_lookalike_domains(
    domain: str,
    *,
    kinds: Optional[Iterable[str]] = None,
    tlds: Sequence[str] = DEFAULT_TLDS,
    prefixes: Sequence[str] = DEFAULT_PREFIXES,
    suffixes: Sequence[str] = DEFAULT_SUFFIXES,
    registry_suffixes: Iterable[str] = MULTI_LABEL_SUFFIXES,
) -> list[Candidate]:
    """Every look-alike of ``domain``, deduplicated on the punycode form.

    ``kinds`` selects generators from :data:`GENERATORS` plus ``"tld-swap"``
    (default: all). Typos and homoglyphs are tried on the domain's own TLD
    and ``.com`` (where a typo pays off); TLD swaps, hyphenation and affixes
    on every TLD in ``tlds``. The input domain itself is never returned.
    """
    label, home_tld = split_domain(domain, registry_suffixes)
    selected = set(kinds) if kinds is not None else {*GENERATORS, "tld-swap"}
    unknown = selected - {*GENERATORS, "tld-swap"}
    if unknown:
        raise ValueError(f"unknown candidate kinds: {sorted(unknown)}")
    all_tlds = list(dict.fromkeys([home_tld, *tlds]))
    home_tlds = list(dict.fromkeys([home_tld, "com"]))
    original = to_ascii(f"{label}.{home_tld}")

    seen: dict = {}

    def add(new_label: str, tld: str, kind: str, detail: str) -> None:
        name = f"{new_label}.{tld}"
        ascii_name = to_ascii(name)
        if ascii_name is None or ascii_name == original or ascii_name in seen:
            return
        seen[ascii_name] = Candidate(name, ascii_name, kind, detail)

    if "tld-swap" in selected:
        for tld in all_tlds:
            if tld != home_tld:
                add(label, tld, "tld-swap", f".{home_tld} -> .{tld}")
    for kind, (func, scope) in GENERATORS.items():
        if kind not in selected:
            continue
        targets = all_tlds if scope == "all" else home_tlds
        edits = list(
            affixations(label, home_tld, prefixes, suffixes)
            if kind == "affix"
            else func(label)
        )
        for tld in targets:
            for new_label, detail in edits:
                if new_label and new_label != label:
                    add(new_label, tld, kind, detail)
    return list(seen.values())


# EOF
