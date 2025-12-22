from __future__ import annotations

from typing import Iterable, Iterator, Literal

from .common import Candidate

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def build_keyed_square(alphabet: str, key: str, size: int) -> str:
    if len(alphabet) != size * size:
        raise ValueError(f"alphabet must be length {size * size}, got {len(alphabet)}")
    out = []
    seen = set()
    for ch in key:
        if ch in alphabet and ch not in seen:
            out.append(ch)
            seen.add(ch)
    for ch in alphabet:
        if ch not in seen:
            out.append(ch)
            seen.add(ch)
    return "".join(out)


def bifid_decrypt(text: str, square: str, period: int, size: int = 8) -> str:
    if period <= 0:
        raise ValueError("period must be > 0")
    pos = {ch: i for i, ch in enumerate(square)}

    def dec_block(block: str) -> str:
        coords: list[int] = []
        for ch in block:
            idx = pos[ch]
            coords.append(idx // size)
            coords.append(idx % size)
        m = len(block)
        rows = coords[:m]
        cols = coords[m:]
        out = []
        for r, c in zip(rows, cols):
            out.append(square[r * size + c])
        return "".join(out)

    out = []
    for i in range(0, len(text), period):
        out.append(dec_block(text[i : i + period]))
    return "".join(out)


def bifid_encrypt(text: str, square: str, period: int, size: int = 8) -> str:
    if period <= 0:
        raise ValueError("period must be > 0")
    pos = {ch: i for i, ch in enumerate(square)}

    def enc_block(block: str) -> str:
        rows: list[int] = []
        cols: list[int] = []
        for ch in block:
            idx = pos[ch]
            rows.append(idx // size)
            cols.append(idx % size)
        coords = rows + cols
        out = []
        for i in range(0, len(coords), 2):
            r = coords[i]
            c = coords[i + 1]
            out.append(square[r * size + c])
        return "".join(out)

    out = []
    for i in range(0, len(text), period):
        out.append(enc_block(text[i : i + period]))
    return "".join(out)


Direction = Literal["decrypt", "encrypt"]


def bifid_bruteforce(
    cands: Iterator[Candidate],
    keys: Iterable[str],
    *,
    direction: Direction = "decrypt",
) -> Iterator[Candidate]:
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)
        period = len(s)
        for key in keys:
            sq = build_keyed_square(BASE64_ALPHABET, key, size=8)
            out = (
                bifid_decrypt(s, sq, period=period, size=8)
                if direction == "decrypt"
                else bifid_encrypt(s, sq, period=period, size=8)
            )
            meta = dict(c.meta)
            meta["bifid_key"] = key
            meta["bifid_dir"] = direction
            yield Candidate(out, "text", meta)
