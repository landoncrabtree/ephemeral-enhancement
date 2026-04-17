from __future__ import annotations

# Charset modes (matching columnar convention)
N_RAILFENCE_CHARSET_MODES = 2
CHARSET_LETTERS_ONLY = 0
CHARSET_ALL = 1

_ASCII_ALPHA = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _build_zigzag(n: int, num_rails: int, offset: int = 0) -> list[int]:
    """Return the rail index for each position in the zigzag pattern."""
    if num_rails <= 1:
        return [0] * n
    cycle = 2 * (num_rails - 1)
    pattern = []
    for i in range(n):
        pos = (i + offset) % cycle
        if pos < num_rails:
            pattern.append(pos)
        else:
            pattern.append(cycle - pos)
    return pattern


def _railfence_decrypt_raw(cipher: str, num_rails: int, offset: int = 0) -> str:
    """Core railfence decryption on a flat string (no charset filtering)."""
    if num_rails <= 1 or not cipher:
        return cipher

    n = len(cipher)
    zigzag = _build_zigzag(n, num_rails, offset)

    # Count chars per rail
    rail_lengths = [0] * num_rails
    for r in zigzag:
        rail_lengths[r] += 1

    # Fill rails from ciphertext (read top-to-bottom)
    rails: list[str] = []
    idx = 0
    for rail in range(num_rails):
        length = rail_lengths[rail]
        rails.append(cipher[idx : idx + length])
        idx += length

    # Read off by zigzag pattern
    rail_pos = [0] * num_rails
    out = []
    for r in zigzag:
        out.append(rails[r][rail_pos[r]])
        rail_pos[r] += 1

    return "".join(out)


def railfence_decrypt(
    cipher: str, num_rails: int, offset: int = 0, charset_mode: int = CHARSET_ALL
) -> str:
    """
    Decrypt a railfence cipher with the given number of rails.

    Args:
        cipher: The ciphertext to decrypt.
        num_rails: Number of rails (depth).
        offset: Starting offset in the zigzag cycle (default 0).
        charset_mode: CHARSET_ALL (transpose everything) or
                      CHARSET_LETTERS_ONLY (only transpose letters).
    """
    if num_rails <= 1 or not cipher:
        return cipher

    if charset_mode == CHARSET_LETTERS_ONLY:
        trans_chars = []
        trans_positions = []
        for i, c in enumerate(cipher):
            if c in _ASCII_ALPHA:
                trans_chars.append(c)
                trans_positions.append(i)
        if not trans_chars:
            return cipher
        decrypted = _railfence_decrypt_raw("".join(trans_chars), num_rails, offset)
        result = list(cipher)
        for i, pos in enumerate(trans_positions):
            result[pos] = decrypted[i]
        return "".join(result)

    return _railfence_decrypt_raw(cipher, num_rails, offset)


def _redefense_decrypt_raw(
    cipher: str, num_rails: int, rail_order: list[int], offset: int = 0
) -> str:
    """Core redefense decryption on a flat string."""
    if num_rails <= 1 or not cipher:
        return cipher

    n = len(cipher)
    zigzag = _build_zigzag(n, num_rails, offset)

    # Count chars per rail
    rail_lengths = [0] * num_rails
    for r in zigzag:
        rail_lengths[r] += 1

    # Fill rails from ciphertext in keyword/order-determined sequence
    rails = [""] * num_rails
    idx = 0
    for rail_idx in rail_order:
        length = rail_lengths[rail_idx]
        rails[rail_idx] = cipher[idx : idx + length]
        idx += length

    # Read off by zigzag pattern
    rail_pos = [0] * num_rails
    out = []
    for r in zigzag:
        out.append(rails[r][rail_pos[r]])
        rail_pos[r] += 1

    return "".join(out)


def _derive_rail_order(key: str | list[int]) -> list[int]:
    """Derive the rail read order from a keyword or numeric order list.

    For a string keyword: alphabetical sorting gives reading sequence.
    For a list of ints (1-indexed): the list IS the reading sequence directly.
    """
    if isinstance(key, list):
        return [v - 1 for v in key]
    return [i for i, _ in sorted(enumerate(key), key=lambda x: (x[1], x[0]))]


def redefense_decrypt(
    cipher: str, key: str | list[int], offset: int = 0, charset_mode: int = CHARSET_ALL
) -> str:
    """
    Decrypt a Redefence (keyed rail fence) cipher.

    Args:
        cipher: The ciphertext to decrypt.
        key: Either a string keyword or a list of 1-indexed rank integers
             (e.g. [3, 2, 1]). Length determines number of rails.
        offset: Starting offset in the zigzag cycle (default 0).
        charset_mode: CHARSET_ALL or CHARSET_LETTERS_ONLY.
    """
    if not key or not cipher:
        return cipher

    num_rails = len(key)
    if num_rails <= 1:
        return cipher

    rail_order = _derive_rail_order(key)

    if charset_mode == CHARSET_LETTERS_ONLY:
        trans_chars = []
        trans_positions = []
        for i, c in enumerate(cipher):
            if c in _ASCII_ALPHA:
                trans_chars.append(c)
                trans_positions.append(i)
        if not trans_chars:
            return cipher
        decrypted = _redefense_decrypt_raw(
            "".join(trans_chars), num_rails, rail_order, offset
        )
        result = list(cipher)
        for i, pos in enumerate(trans_positions):
            result[pos] = decrypted[i]
        return "".join(result)

    return _redefense_decrypt_raw(cipher, num_rails, rail_order, offset)
