from __future__ import annotations

import math

# Charset modes for transposition (Rumkin/CryptTool naming):
# 0 = letters_only: only transpose ASCII letters; spaces, digits, punctuation
#     stay at their original positions ("Move only letters")
# 1 = all: transpose every character including spaces and punctuation
#     ("Move spaces, punctuation, and capitalization")
from stages.charsets import (  # noqa: F401  (re-exported for callers)
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    CHARSET_LETTERS_ONLY,
    N_CHARSET_MODES,
    is_selected,
)

N_COLUMNAR_CHARSET_MODES = N_CHARSET_MODES

_ASCII_ALPHA = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _is_transposable(ch: str, charset_mode: int) -> bool:
    """Return True if the character should be transposed in the given mode."""
    return is_selected(ch, charset_mode)


def _key_order(keyword: str) -> list[int]:
    pairs = sorted(
        [(ch, i) for i, ch in enumerate(keyword)], key=lambda x: (x[0], x[1])
    )
    order: list[int] = [0] * len(keyword)
    for rank, (_, original_i) in enumerate(pairs):
        order[original_i] = rank
    return order


def _columnar_decrypt_raw(cipher: str, keyword: str) -> str:
    """Core columnar decryption on a flat string (no charset filtering)."""
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


def columnar_decrypt(cipher: str, keyword: str, charset_mode: int = CHARSET_ALL) -> str:
    """Decrypt columnar transposition cipher.

    Args:
        cipher: The ciphertext to decrypt.
        keyword: The keyword defining column order.
        charset_mode: Which characters to transpose (0=alpha, 1=alphanumeric,
            2=all).
            In alpha/alnum modes, non-transposable characters stay at their
            original positions; only the transposable characters are rearranged.
    """
    if charset_mode == CHARSET_ALL:
        return _columnar_decrypt_raw(cipher, keyword)

    # Extract transposable chars and their positions
    trans_chars = []
    trans_positions = []
    for i, c in enumerate(cipher):
        if _is_transposable(c, charset_mode):
            trans_chars.append(c)
            trans_positions.append(i)

    if not trans_chars:
        return cipher

    # Decrypt only the transposable characters
    decrypted = _columnar_decrypt_raw("".join(trans_chars), keyword)

    # Rebuild: put decrypted chars back at transposable positions
    result = list(cipher)
    for i, pos in enumerate(trans_positions):
        if i < len(decrypted):
            result[pos] = decrypted[i]
    return "".join(result)


def double_columnar_decrypt(
    cipher: str, key1: str, key2: str, charset_mode: int = CHARSET_ALL
) -> str:
    """
    Decrypt double columnar transposition cipher.

    If encryption was: C = col(col(P, key1), key2)
    then decryption is: P = col_dec(col_dec(C, key2), key1)
    """
    return columnar_decrypt(
        columnar_decrypt(cipher, key2, charset_mode), key1, charset_mode
    )
