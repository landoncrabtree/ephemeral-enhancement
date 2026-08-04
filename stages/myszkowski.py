from __future__ import annotations

from stages.charsets import (  # noqa: F401  (re-exported for callers)
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    N_CHARSET_MODES,
    merge_selected,
    split_selected,
)

N_MYSZKOWSKI_CHARSET_MODES = N_CHARSET_MODES


def _myszkowski_key_order(keyword: str) -> list[int]:
    """
    Myszkowski ordering: duplicate letters share the same rank.
    E.g. ZOMBIE -> Z=4, O=3, M=2, B=0, I=1, E=4? No, all unique.
    E.g. TOMATO -> T=3, O=2, M=1, A=0, T=3, O=2
    """
    sorted_unique = sorted(set(keyword))
    char_rank = {ch: i for i, ch in enumerate(sorted_unique)}
    return [char_rank[ch] for ch in keyword]


def _myszkowski_decrypt_raw(cipher: str, keyword: str) -> str:
    """
    Decrypt Myszkowski transposition cipher.

    Like columnar transposition, but columns with the same rank are read
    left-to-right across rows together (not individually).
    """
    if not keyword or not cipher:
        return cipher

    k = len(keyword)
    n = len(cipher)
    ranks = _myszkowski_key_order(keyword)
    num_rows = -(-n // k)  # ceil division

    # Build grid of None
    grid = [[None] * k for _ in range(num_rows)]
    # Mark valid cells
    valid_count = 0
    for r in range(num_rows):
        for c in range(k):
            if valid_count < n:
                grid[r][c] = ""
                valid_count += 1

    # Read ciphertext into columns grouped by rank
    max_rank = max(ranks)
    idx = 0
    for rank in range(max_rank + 1):
        cols_with_rank = [c for c in range(k) if ranks[c] == rank]
        if len(cols_with_rank) == 1:
            # Single column: fill top-to-bottom
            col = cols_with_rank[0]
            for r in range(num_rows):
                if grid[r][col] is not None and idx < n:
                    grid[r][col] = cipher[idx]
                    idx += 1
        else:
            # Multiple columns with same rank: fill row by row, left to right
            for r in range(num_rows):
                for col in cols_with_rank:
                    if grid[r][col] is not None and idx < n:
                        grid[r][col] = cipher[idx]
                        idx += 1

    # Read plaintext row by row
    out = []
    for r in range(num_rows):
        for c in range(k):
            if grid[r][c] is not None:
                out.append(grid[r][c])
    return "".join(out)


def myszkowski_decrypt(
    cipher: str, keyword: str, charset_mode: int = CHARSET_ALL
) -> str:
    """
    Decrypt Myszkowski transposition, restricted to a character set.

    Args:
        cipher: The ciphertext to decrypt.
        keyword: The keyword defining column ranks.
        charset_mode: 0=alpha, 1=alphanumeric, 2=all. In the restricted modes
            only the selected characters are rearranged; everything else keeps
            its original position.
    """
    if charset_mode == CHARSET_ALL:
        return _myszkowski_decrypt_raw(cipher, keyword)

    chars, positions = split_selected(cipher, charset_mode)
    if not chars:
        return cipher
    decrypted = _myszkowski_decrypt_raw("".join(chars), keyword)
    return merge_selected(cipher, positions, decrypted)
