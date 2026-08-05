"""
Playfair digraph substitution, generalised to square grids of any size.

The classical cipher uses a 5x5 grid of 25 letters, which forces J onto I and
emits letters only. That variant cannot be an outer layer over a base64
payload. The same rules work on any NxN grid, so this module also supports an
8x8 grid over the 64-character base64 alphabet, where the cipher maps base64
onto base64 and the text stays decodable — the same generalisation
``stages/bifid.py`` already applies to Bifid.

Grid variants:

===== ==== ================================================
Index Size Alphabet
===== ==== ================================================
0     5x5  A-Z with J omitted (classical)
1     6x6  A-Z plus 0-9
2     8x8  base64: A-Za-z0-9+/
===== ==== ================================================
"""

from __future__ import annotations

from stages.bifid import build_keyed_square

PLAYFAIR_ALPHABETS = (
    "ABCDEFGHIKLMNOPQRSTUVWXYZ",                                          # 5x5
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",                               # 6x6
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",   # 8x8
)
PLAYFAIR_GRID_NAMES = ("5x5", "6x6", "8x8-b64")
N_PLAYFAIR_GRIDS = len(PLAYFAIR_ALPHABETS)


def playfair_decrypt(
    ciphertext: str, key: str, grid_mode: int = 2
) -> str | None:
    """
    Decrypt a Playfair digraph substitution.

    Args:
        ciphertext: Text to decrypt.
        key: Keyword seeding the grid.
        grid_mode: Index into PLAYFAIR_ALPHABETS (0=5x5, 1=6x6, 2=8x8 base64).

    Returns:
        Decrypted text, or None if the grid mode is unknown. Characters
        outside the alphabet pass through unchanged and do not consume a
        position in a digraph; a trailing unpaired character is emitted as is.
    """
    if not 0 <= grid_mode < N_PLAYFAIR_GRIDS:
        return None

    alphabet = PLAYFAIR_ALPHABETS[grid_mode]
    size = int(len(alphabet) ** 0.5)
    square = build_keyed_square(alphabet, key)
    pos = {ch: (i // size, i % size) for i, ch in enumerate(square)}

    # Split into the characters the grid can act on, keeping the rest in place.
    indices = [i for i, ch in enumerate(ciphertext) if ch in pos]
    out = list(ciphertext)

    for a, b in zip(indices[0::2], indices[1::2]):
        r1, c1 = pos[ciphertext[a]]
        r2, c2 = pos[ciphertext[b]]
        if r1 == r2:  # same row: shift left
            c1, c2 = (c1 - 1) % size, (c2 - 1) % size
        elif c1 == c2:  # same column: shift up
            r1, r2 = (r1 - 1) % size, (r2 - 1) % size
        else:  # rectangle: swap columns
            c1, c2 = c2, c1
        out[a] = square[r1 * size + c1]
        out[b] = square[r2 * size + c2]

    return "".join(out)


def playfair_encrypt(
    plaintext: str, key: str, grid_mode: int = 2
) -> str | None:
    """Encrypt with Playfair (inverse of `playfair_decrypt`, for tests)."""
    if not 0 <= grid_mode < N_PLAYFAIR_GRIDS:
        return None

    alphabet = PLAYFAIR_ALPHABETS[grid_mode]
    size = int(len(alphabet) ** 0.5)
    square = build_keyed_square(alphabet, key)
    pos = {ch: (i // size, i % size) for i, ch in enumerate(square)}

    indices = [i for i, ch in enumerate(plaintext) if ch in pos]
    out = list(plaintext)

    for a, b in zip(indices[0::2], indices[1::2]):
        r1, c1 = pos[plaintext[a]]
        r2, c2 = pos[plaintext[b]]
        if r1 == r2:
            c1, c2 = (c1 + 1) % size, (c2 + 1) % size
        elif c1 == c2:
            r1, r2 = (r1 + 1) % size, (r2 + 1) % size
        else:
            c1, c2 = c2, c1
        out[a] = square[r1 * size + c1]
        out[b] = square[r2 * size + c2]

    return "".join(out)
