"""
Shared character-set modes for classical cipher stages.

Every classical stage that can operate on a subset of characters uses the same
three modes, in the same order, so a pipeline's parameter axes stay predictable:

===== ================= ==========================================
Index Name              Characters affected
===== ================= ==========================================
0     ``alpha``         ASCII letters only (``A-Za-z``)
1     ``alphanumeric``  Letters and digits (``A-Za-z0-9``)
2     ``all``           Every character
===== ================= ==========================================

For **transposition** stages these select which characters take part in the
permutation; characters outside the set keep their original positions.

For **substitution** stages they select the alphabet (and therefore the
modulus) that shifting is performed over.

Index 0 is ``alpha`` so that mode 0 stays the most conservative option and
occupies the start of each stage's search space.

.. note::
   Modes 1 and 2 shift or move base64 padding and symbol characters. When a
   classical stage runs *before* a ``b64`` stage this can corrupt the base64
   structure, which historically produced scoring false positives. Prefer
   ``alpha`` when the payload is a base64 blob.
"""

from __future__ import annotations

CHARSET_ALPHA = 0
CHARSET_ALPHANUMERIC = 1
CHARSET_ALL = 2

N_CHARSET_MODES = 3
CHARSET_MODE_NAMES = ("alpha", "alphanumeric", "all")

# Backward-compatible alias: the original two-mode scheme called mode 0
# "letters only".
CHARSET_LETTERS_ONLY = CHARSET_ALPHA

_ASCII_ALPHA = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_ASCII_ALNUM = frozenset(_ASCII_ALPHA | set("0123456789"))


def is_selected(ch: str, charset_mode: int) -> bool:
    """Return True if `ch` participates under the given charset mode."""
    if charset_mode == CHARSET_ALL:
        return True
    if charset_mode == CHARSET_ALPHANUMERIC:
        return ch in _ASCII_ALNUM
    return ch in _ASCII_ALPHA


def charset_name(charset_mode: int) -> str:
    """Human-readable name for a charset mode, for result metadata."""
    if 0 <= charset_mode < N_CHARSET_MODES:
        return CHARSET_MODE_NAMES[charset_mode]
    return f"unknown-{charset_mode}"


def split_selected(text: str, charset_mode: int) -> tuple[list[str], list[int]]:
    """
    Split `text` into the characters that participate and their positions.

    Returns ``(chars, positions)`` so a stage can permute `chars` and write
    them back into the untouched surrounding text via `positions`.
    """
    chars: list[str] = []
    positions: list[int] = []
    for i, ch in enumerate(text):
        if is_selected(ch, charset_mode):
            chars.append(ch)
            positions.append(i)
    return chars, positions


def merge_selected(text: str, positions: list[int], permuted: str) -> str:
    """Write `permuted` back into `text` at `positions`, keeping the rest."""
    result = list(text)
    for i, pos in enumerate(positions):
        result[pos] = permuted[i]
    return "".join(result)
