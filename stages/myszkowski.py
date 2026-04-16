from __future__ import annotations


def _myszkowski_key_order(keyword: str) -> list[int]:
    """
    Myszkowski ordering: duplicate letters share the same rank.
    E.g. ZOMBIE -> Z=4, O=3, M=2, B=0, I=1, E=4? No, all unique.
    E.g. TOMATO -> T=3, O=2, M=1, A=0, T=3, O=2
    """
    sorted_unique = sorted(set(keyword))
    char_rank = {ch: i for i, ch in enumerate(sorted_unique)}
    return [char_rank[ch] for ch in keyword]


def myszkowski_decrypt(cipher: str, keyword: str) -> str:
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
