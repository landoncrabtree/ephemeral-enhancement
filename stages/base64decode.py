from __future__ import annotations

import base64
from typing import Iterator

from .common import Candidate


def base64_decode(
    cands: Iterator[Candidate], *, validate: bool = True
) -> Iterator[Candidate]:
    """
    Decode base64 text candidates into bytes candidates. Invalid candidates are dropped.
    """
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)
        try:
            raw = base64.b64decode(s, validate=validate)
        except Exception:
            continue
        yield Candidate(raw, "bytes", dict(c.meta))
