"""
AMSCO transposition.

A columnar transposition whose cells hold *alternating* chunk sizes rather than
single characters: filling the grid row by row, cells take 1, 2, 1, 2 ... (or
2, 1, 2, 1 ...) characters, with the alternation continuing across row
boundaries. Columns are then read out in key order.

Used by the Black Ops III DE-7 cipher ("2-1 AMSCO", key 198346572).

Only characters selected by the charset mode take part; everything else keeps
its original position, so a base64 payload stays decodable.
"""

from __future__ import annotations

from stages.charsets import (  # noqa: F401  (re-exported for callers)
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    N_CHARSET_MODES,
    merge_selected,
    split_selected,
)

# Chunk patterns: start with a single character, or with a pair.
N_AMSCO_PATTERNS = 2
AMSCO_PATTERN_NAMES = ("1-2", "2-1")


def key_order(keyword: str) -> list[int]:
    """
    Column read order from a keyword.

    Digit keys ("198346572") rank by numeric value; otherwise columns rank
    alphabetically, ties broken left to right.
    """
    if keyword.isdigit():
        pairs = sorted((int(ch), i) for i, ch in enumerate(keyword))
    else:
        pairs = sorted((ch, i) for i, ch in enumerate(keyword))  # type: ignore[misc]
    order = [0] * len(keyword)
    for rank, (_, original) in enumerate(pairs):
        order[original] = rank
    return order


def _chunk_layout(n: int, n_cols: int, start_pair: bool) -> list[list[int]]:
    """
    Plan each cell's chunk length, filling row by row.

    Returns a grid of lengths; the alternation carries across rows, which is
    what distinguishes AMSCO from a plain columnar transposition.
    """
    grid: list[list[int]] = []
    used = 0
    pair = start_pair
    while used < n:
        row: list[int] = []
        for _ in range(n_cols):
            if used >= n:
                row.append(0)
                continue
            size = min(2 if pair else 1, n - used)
            row.append(size)
            used += size
            pair = not pair
        grid.append(row)
    return grid


def _amsco_decrypt_raw(cipher: str, keyword: str, start_pair: bool) -> str:
    n_cols = len(keyword)
    n = len(cipher)
    if n_cols < 2 or n == 0:
        return cipher

    grid = _chunk_layout(n, n_cols, start_pair)
    order = key_order(keyword)

    # Ciphertext is the columns concatenated in rank order, so refill them the
    # same way, then read the grid back row by row.
    cells: list[list[str]] = [["" for _ in range(n_cols)] for _ in grid]
    pos = 0
    for rank in range(n_cols):
        col = order.index(rank)
        for r, row in enumerate(grid):
            size = row[col]
            if size:
                cells[r][col] = cipher[pos : pos + size]
                pos += size

    return "".join("".join(row) for row in cells)


def amsco_decrypt(
    cipher: str,
    keyword: str,
    start_pair: bool = False,
    charset_mode: int = CHARSET_ALL,
) -> str:
    """
    Decrypt an AMSCO transposition.

    Args:
        cipher: The ciphertext to decrypt.
        keyword: Keyword or digit string defining column count and order.
        start_pair: False for a 1-2 chunk pattern, True for 2-1.
        charset_mode: 0=alpha, 1=alphanumeric, 2=all.

    Returns:
        The decrypted text; unchanged when the keyword is too short.
    """
    if not keyword or len(keyword) < 2 or not cipher:
        return cipher

    if charset_mode == CHARSET_ALL:
        return _amsco_decrypt_raw(cipher, keyword, start_pair)

    chars, positions = split_selected(cipher, charset_mode)
    if not chars:
        return cipher
    decrypted = _amsco_decrypt_raw("".join(chars), keyword, start_pair)
    return merge_selected(cipher, positions, decrypted)
