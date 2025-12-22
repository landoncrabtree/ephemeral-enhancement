from __future__ import annotations

from typing import Iterator

from .common import Candidate


def _shift_char(ch: str, shift: int) -> str:
    o = ord(ch)
    if 65 <= o <= 90:  # A-Z
        return chr(65 + ((o - 65 + shift) % 26))
    if 97 <= o <= 122:  # a-z
        return chr(97 + ((o - 97 + shift) % 26))
    return ch


def caesar_bruteforce(cands: Iterator[Candidate]) -> Iterator[Candidate]:
    """
    For each text candidate, emit 26 Caesar shifts (letters only).
    """
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)
        for shift in range(26):
            out = "".join(_shift_char(ch, shift) for ch in s)
            meta = dict(c.meta)
            meta["caesar_shift"] = shift
            yield Candidate(out, "text", meta)
