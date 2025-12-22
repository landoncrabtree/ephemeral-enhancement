from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, Literal

PayloadKind = Literal["text", "bytes"]


@dataclass(slots=True)
class Candidate:
    payload: str | bytes
    kind: PayloadKind
    meta: Dict[str, Any] = field(default_factory=dict)


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return printable / len(b)


def normalize_base64_alphabet(s: str, alphabet: str) -> str:
    allowed = set(alphabet)
    return "".join(ch for ch in s if ch in allowed)


def take(it: Iterable[Candidate], limit: int) -> Iterator[Candidate]:
    if limit <= 0:
        yield from it
        return
    n = 0
    for x in it:
        yield x
        n += 1
        if n >= limit:
            return
