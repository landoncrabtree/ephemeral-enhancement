from __future__ import annotations

from typing import Iterator

from .columnar import columnar_decrypt
from .common import Candidate


def double_columnar_decrypt(cipher: str, key1: str, key2: str) -> str:
    # If encryption was: C = col(col(P, key1), key2)
    # then decryption is: P = col_dec(col_dec(C, key2), key1)
    return columnar_decrypt(columnar_decrypt(cipher, key2), key1)


def double_columnar_bruteforce(
    cands: Iterator[Candidate],
    keys: list[str],
) -> Iterator[Candidate]:
    """
    Brute force double-columnar across the provided key list.

    We try:
    - (k, k) for all k
    - for each unordered pair (k1, k2) with k1 != k2, we try BOTH orders:
      (k1, k2) and (k2, k1)
    """
    for c in cands:
        if c.kind != "text":
            continue
        s = c.payload
        assert isinstance(s, str)

        # same key twice
        for k in keys:
            out = double_columnar_decrypt(s, k, k)
            meta = dict(c.meta)
            meta["double_columnar_key1"] = k
            meta["double_columnar_key2"] = k
            yield Candidate(out, "text", meta)

        # unordered pairs, try both orders
        n = len(keys)
        for i in range(n):
            for j in range(i + 1, n):
                k1 = keys[i]
                k2 = keys[j]

                out = double_columnar_decrypt(s, k1, k2)
                meta = dict(c.meta)
                meta["double_columnar_key1"] = k1
                meta["double_columnar_key2"] = k2
                yield Candidate(out, "text", meta)

                out2 = double_columnar_decrypt(s, k2, k1)
                meta2 = dict(c.meta)
                meta2["double_columnar_key1"] = k2
                meta2["double_columnar_key2"] = k1
                yield Candidate(out2, "text", meta2)
