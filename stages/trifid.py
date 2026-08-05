"""
Trifid fractionation, generalised to cubes of any side length.

Each character maps to three coordinates in an NxNxN cube. Within a block of
`period` characters the three coordinate rows are written out, concatenated,
and re-split into triples, which fractionates and diffuses the text.

The classical cipher uses a 3x3x3 cube of 27 symbols and emits letters only,
so it cannot wrap a base64 payload. A 4x4x4 cube holds exactly 64 symbols —
the base64 alphabet — so that variant maps base64 onto base64 and stays
decodable. This mirrors the 5x5/8x8 generalisation in ``stages/bifid.py``.

Cube variants:

===== ======= ===============================================
Index Cube    Alphabet
===== ======= ===============================================
0     3x3x3   A-Z plus '.' (classical, 27 symbols)
1     4x4x4   base64: A-Za-z0-9+/ (64 symbols)
===== ======= ===============================================
"""

from __future__ import annotations

from stages.bifid import build_keyed_square

TRIFID_ALPHABETS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ.",                                        # 3^3
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",   # 4^3
)
TRIFID_CUBE_NAMES = ("3x3x3", "4x4x4-b64")
N_TRIFID_CUBES = len(TRIFID_ALPHABETS)

MIN_PERIOD = 2
MAX_PERIOD = 30
N_TRIFID_PERIODS = MAX_PERIOD - MIN_PERIOD + 1


def _cube_side(alphabet: str) -> int:
    """Side length N such that N**3 == len(alphabet)."""
    side = round(len(alphabet) ** (1 / 3))
    return side if side**3 == len(alphabet) else 0


def trifid_decrypt(
    ciphertext: str, key: str, period: int, cube_mode: int = 1
) -> str | None:
    """
    Decrypt a Trifid fractionation cipher.

    Args:
        ciphertext: Text to decrypt.
        key: Keyword seeding the cube.
        period: Block length in characters.
        cube_mode: Index into TRIFID_ALPHABETS (0=3x3x3, 1=4x4x4 base64).

    Returns:
        Decrypted text, or None on an unknown cube or period < 2. Characters
        outside the alphabet pass through unchanged and do not consume a
        position in a block.
    """
    if not 0 <= cube_mode < N_TRIFID_CUBES or period < MIN_PERIOD:
        return None

    alphabet = TRIFID_ALPHABETS[cube_mode]
    side = _cube_side(alphabet)
    if not side:
        return None

    square = build_keyed_square(alphabet, key)
    index = {ch: i for i, ch in enumerate(square)}

    indices = [i for i, ch in enumerate(ciphertext) if ch in index]
    out = list(ciphertext)

    for start in range(0, len(indices), period):
        block = indices[start : start + period]
        n = len(block)

        # Flatten each character's three coordinates back into one digit run.
        digits: list[int] = []
        for i in block:
            v = index[ciphertext[i]]
            digits += [v // (side * side), (v // side) % side, v % side]

        # The run is three equal rows; column j rebuilds character j.
        rows = [digits[0:n], digits[n : 2 * n], digits[2 * n : 3 * n]]
        for j, i in enumerate(block):
            value = rows[0][j] * side * side + rows[1][j] * side + rows[2][j]
            out[i] = square[value]

    return "".join(out)


def trifid_encrypt(
    plaintext: str, key: str, period: int, cube_mode: int = 1
) -> str | None:
    """Encrypt with Trifid (inverse of `trifid_decrypt`, for tests)."""
    if not 0 <= cube_mode < N_TRIFID_CUBES or period < MIN_PERIOD:
        return None

    alphabet = TRIFID_ALPHABETS[cube_mode]
    side = _cube_side(alphabet)
    if not side:
        return None

    square = build_keyed_square(alphabet, key)
    index = {ch: i for i, ch in enumerate(square)}

    indices = [i for i, ch in enumerate(plaintext) if ch in index]
    out = list(plaintext)

    for start in range(0, len(indices), period):
        block = indices[start : start + period]

        rows: list[list[int]] = [[], [], []]
        for i in block:
            v = index[plaintext[i]]
            rows[0].append(v // (side * side))
            rows[1].append((v // side) % side)
            rows[2].append(v % side)

        digits = rows[0] + rows[1] + rows[2]
        for j, i in enumerate(block):
            a, b, c = digits[3 * j : 3 * j + 3]
            out[i] = square[a * side * side + b * side + c]

    return "".join(out)
