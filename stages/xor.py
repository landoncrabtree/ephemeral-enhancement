from __future__ import annotations

from typing import Iterable, Iterator

from .common import Candidate


def repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return b""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def xor_bruteforce(
    cands: Iterator[Candidate], keys: Iterable[str]
) -> Iterator[Candidate]:
    """
    For each bytes candidate, emit repeating-key XOR with each provided key.
    """
    key_bytes = [(k, k.encode("utf-8", "ignore")) for k in keys]
    for c in cands:
        if c.kind != "bytes":
            continue
        data = c.payload
        assert isinstance(data, (bytes, bytearray))
        for k, kb in key_bytes:
            out = repeating_xor(bytes(data), kb)
            meta = dict(c.meta)
            meta["xor_key"] = k
            yield Candidate(out, "bytes", meta)
