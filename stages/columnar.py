from __future__ import annotations

import math


def _key_order(keyword: str) -> list[int]:
    pairs = sorted(
        [(ch, i) for i, ch in enumerate(keyword)], key=lambda x: (x[0], x[1])
    )
    order: list[int] = [0] * len(keyword)
    for rank, (_, original_i) in enumerate(pairs):
        order[original_i] = rank
    return order


def columnar_decrypt(cipher: str, keyword: str) -> str:
    k = len(keyword)
    if k <= 1:
        return cipher
    n = len(cipher)
    rows = math.ceil(n / k)
    shaded = rows * k - n
    order = _key_order(keyword)

    col_lens = [rows] * k
    for col in range(k - shaded, k):
        if 0 <= col < k:
            col_lens[col] -= 1

    rank_to_col: list[int] = [0] * k
    for col_idx, rank in enumerate(order):
        rank_to_col[rank] = col_idx

    cols = [""] * k
    idx = 0
    for rank in range(k):
        col = rank_to_col[rank]
        clen = col_lens[col]
        cols[col] = cipher[idx : idx + clen]
        idx += clen

    out = []
    for r in range(rows):
        for c in range(k):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)
