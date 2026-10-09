"""Unicode TR39 'skeleton' for confusable (lookalike) detection.

Two strings are confusable if their skeletons are equal. This is the same idea
Chrome uses to decide when to show punycode instead of a lookalike domain
(docs/research/03_url_intel_libs.md section A.1). confusables.txt is pinned in
app/data (Unicode 18.0.0), so results don't change between runs.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "confusables.txt"

# Extra ASCII lookalikes that confusables.txt maps only partly. Applied after
# the TR39 mapping so that 'rn' -> 'm', '0' -> 'o', etc.
_ASCII_EXTRA = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("|", "l"), ("5", "s"))

# Default_Ignorable_Code_Point subset that matters in hostnames / VPAs.
_IGNORABLE = {"­", "͏", "؜", "ᅟ", "ᅠ", "឴", "឵", "᠋",
              "᠌", "᠍", "᠎", "​", "‌", "‍", "‎", "‏",
              "‪", "‫", "‬", "‭", "‮", "⁠", "⁡", "⁢",
              "⁣", "⁤", "﻿"}


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    with _DATA.open(encoding="utf-8-sig") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) < 2:
                continue
            src = "".join(chr(int(c, 16)) for c in parts[0].split())
            tgt = "".join(chr(int(c, 16)) for c in parts[1].split())
            if len(src) == 1:
                table[src] = tgt
    return table


def skeleton(s: str) -> str:
    table = _table()
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if c not in _IGNORABLE)
    s = "".join(table.get(c, c) for c in s)
    s = unicodedata.normalize("NFD", s).lower()
    # Drop combining marks left over (e.g. accents) for a looser match.
    s = "".join(c for c in s if not unicodedata.combining(c))
    for a, b in _ASCII_EXTRA:
        s = s.replace(a, b)
    return s


def is_mixed_or_non_ascii(s: str) -> bool:
    return not s.isascii()
