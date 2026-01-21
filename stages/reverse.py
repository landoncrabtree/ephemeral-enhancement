from __future__ import annotations

from typing import Iterator

from .common import Candidate


def reverse_text(text: str) -> str:
    """
    Reverse the order of characters in the text.

    Args:
        text: The text to reverse

    Returns:
        The reversed text
    """
    return text[::-1]


def reverse_bruteforce(cands: Iterator[Candidate]) -> Iterator[Candidate]:
    """
    Reverse each text candidate.

    This stage has no parameters - it simply reverses the text.
    Only one output per input.

    Args:
        cands: Iterator of input candidates

    Yields:
        Candidate objects with reversed text
    """
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)

        out = reverse_text(s)
        meta = dict(c.meta)
        meta["reverse_applied"] = True
        yield Candidate(out, "text", meta)
