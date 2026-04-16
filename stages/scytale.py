"""
Scytale transposition cipher.

The scytale wraps a strip of text around a cylinder. The number of columns
(band turns) determines the transposition pattern.

Encrypt: write text into a grid row-by-row, read column-by-column.
Decrypt: write ciphertext into columns, read row-by-row.
"""

from __future__ import annotations


def scytale_decrypt(text: str, n_cols: int) -> str:
    """
    Decrypt a scytale cipher.

    Args:
        text: The ciphertext to decrypt.
        n_cols: Number of columns (band turns / wraps around the cylinder).

    Returns:
        The decrypted plaintext.
    """
    n = len(text)
    if n_cols < 2 or n_cols >= n:
        return text

    rows = -(-n // n_cols)  # ceil(n / n_cols)
    n_full_cols = n % n_cols if n % n_cols != 0 else n_cols

    grid = [[""] * n_cols for _ in range(rows)]
    idx = 0
    for c in range(n_cols):
        col_len = rows if c < n_full_cols else (rows - 1)
        for r in range(col_len):
            grid[r][c] = text[idx]
            idx += 1

    return "".join(
        grid[r][c] for r in range(rows) for c in range(n_cols) if grid[r][c]
    )
