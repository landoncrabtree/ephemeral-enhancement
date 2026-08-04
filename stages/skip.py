"""
Skip (decimation) transposition.

Reads the text by repeatedly stepping `skip` positions around a circular
buffer, optionally after bypassing a number of leading characters. Used in the
Black Ops III ZNS-8 cipher ("Bypass first 5 letters and skip 25").

Encryption walks the plaintext in that stepped order to produce the
ciphertext; decryption therefore writes the ciphertext back into those same
positions.

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

# Skip values 2..MAX_SKIP and bypass offsets 0..MAX_BYPASS-1 are enumerated.
MAX_SKIP = 40
MIN_SKIP = 2
N_SKIP_VALUES = MAX_SKIP - MIN_SKIP + 1
MAX_BYPASS = 30


def _read_order(n: int, skip: int, bypass: int) -> list[int]:
    """
    The order in which positions are visited.

    Starting at `bypass`, repeatedly advance `skip` places around a ring of the
    still-unvisited positions. Returns a permutation of ``range(n)``.
    """
    remaining = list(range(n))
    order: list[int] = []
    if not remaining:
        return order

    idx = bypass % len(remaining)
    while remaining:
        order.append(remaining.pop(idx))
        if not remaining:
            break
        idx = (idx + skip - 1) % len(remaining)
    return order


def _skip_decrypt_raw(cipher: str, skip: int, bypass: int) -> str:
    """Invert the stepped read: ciphertext[i] belongs at order[i]."""
    n = len(cipher)
    order = _read_order(n, skip, bypass)
    out = [""] * n
    for i, pos in enumerate(order):
        out[pos] = cipher[i]
    return "".join(out)


def skip_decrypt(
    cipher: str,
    skip: int,
    bypass: int = 0,
    charset_mode: int = CHARSET_ALL,
) -> str:
    """
    Decrypt a skip (decimation) transposition.

    Args:
        cipher: The ciphertext to decrypt.
        skip: Step size between successive reads (>= 2).
        bypass: How many positions to skip before the first read.
        charset_mode: 0=alpha, 1=alphanumeric, 2=all.

    Returns:
        The decrypted text; unchanged when `skip` is out of range.
    """
    if skip < MIN_SKIP or not cipher:
        return cipher

    if charset_mode == CHARSET_ALL:
        return _skip_decrypt_raw(cipher, skip, bypass)

    chars, positions = split_selected(cipher, charset_mode)
    if not chars:
        return cipher
    decrypted = _skip_decrypt_raw("".join(chars), skip, bypass)
    return merge_selected(cipher, positions, decrypted)
