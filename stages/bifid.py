from __future__ import annotations

# Standard Bifid uses 5x5 square with 25 letters (I/J combined)
STANDARD_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 chars, J omitted (use I for J)

# Alternative: Base64 alphabet for 8x8 square (legacy, for compatibility)
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def build_keyed_square(alphabet: str, key: str) -> str:
    """
    Build a keyed Polybius square from an alphabet and key.

    The key characters (that exist in the alphabet) are placed first,
    followed by the remaining alphabet characters in order.

    Args:
        alphabet: The base alphabet to use (e.g., 25 or 64 characters)
        key: The keyword to use for keying the square

    Returns:
        The keyed square as a string

    Example:
        >>> build_keyed_square("ABCDEFGHIKLMNOPQRSTUVWXYZ", "ZOMBIE")
        'ZOMBIEACDFGHKLNPQRSTUVWXY'
    """
    out = []
    seen = set()
    # Add key characters first (uppercase, in alphabet, no duplicates)
    for ch in key.upper():
        if ch in alphabet and ch not in seen:
            out.append(ch)
            seen.add(ch)
    # Add remaining alphabet characters
    for ch in alphabet:
        if ch not in seen:
            out.append(ch)
            seen.add(ch)
    return "".join(out)


def bifid_decrypt(
    text: str, key: str, period: int, alphabet: str = STANDARD_ALPHABET
) -> str:
    """
    Decrypt text using the Bifid cipher.

    Args:
        text: The ciphertext to decrypt
        key: The keyword for the keyed Polybius square
        period: The period for fractionation
        alphabet: The alphabet used (determines square size)

    Returns:
        The decrypted plaintext

    Note:
        Characters not in the alphabet (e.g., spaces, punctuation) are
        preserved in their original positions and not decrypted.
    """
    if period <= 0:
        raise ValueError("period must be > 0")

    # Calculate square size from alphabet length
    size = int(len(alphabet) ** 0.5)
    if size * size != len(alphabet):
        raise ValueError(
            f"alphabet length must be a perfect square, got {len(alphabet)}"
        )

    # Build the keyed square from the key
    square = build_keyed_square(alphabet, key)
    pos = {ch: i for i, ch in enumerate(square)}

    # Separate cipher characters from non-alphabet characters
    cipher_chars = []
    non_alpha_positions = []
    for i, ch in enumerate(text):
        if ch in pos:
            cipher_chars.append(ch)
        else:
            non_alpha_positions.append((i, ch))

    def dec_block(block: str) -> str:
        coords: list[int] = []
        for ch in block:
            idx = pos[ch]
            coords.append(idx // size)
            coords.append(idx % size)
        m = len(block)
        rows = coords[:m]
        cols = coords[m:]
        out = []
        for r, c in zip(rows, cols):
            out.append(square[r * size + c])
        return "".join(out)

    # Decrypt only the cipher characters
    decrypted_chars = []
    for i in range(0, len(cipher_chars), period):
        decrypted_chars.extend(dec_block(cipher_chars[i : i + period]))

    # Reinsert non-alphabet characters at their original positions
    result = list(decrypted_chars)
    for pos_idx, ch in non_alpha_positions:
        result.insert(pos_idx, ch)

    return "".join(result)


def bifid_encrypt(
    text: str, key: str, period: int, alphabet: str = STANDARD_ALPHABET
) -> str:
    """
    Encrypt text using the Bifid cipher.

    Args:
        text: The plaintext to encrypt
        key: The keyword for the keyed Polybius square
        period: The period for fractionation
        alphabet: The alphabet used (determines square size)

    Returns:
        The encrypted ciphertext

    Note:
        Characters not in the alphabet (e.g., spaces, punctuation) are
        preserved in their original positions and not encrypted.
    """
    if period <= 0:
        raise ValueError("period must be > 0")

    # Calculate square size from alphabet length
    size = int(len(alphabet) ** 0.5)
    if size * size != len(alphabet):
        raise ValueError(
            f"alphabet length must be a perfect square, got {len(alphabet)}"
        )

    # Build the keyed square from the key
    square = build_keyed_square(alphabet, key)
    pos = {ch: i for i, ch in enumerate(square)}

    # Separate plaintext characters from non-alphabet characters
    plain_chars = []
    non_alpha_positions = []
    for i, ch in enumerate(text):
        if ch in pos:
            plain_chars.append(ch)
        else:
            non_alpha_positions.append((i, ch))

    def enc_block(block: str) -> str:
        rows: list[int] = []
        cols: list[int] = []
        for ch in block:
            idx = pos[ch]
            rows.append(idx // size)
            cols.append(idx % size)
        coords = rows + cols
        out = []
        for i in range(0, len(coords), 2):
            r = coords[i]
            c = coords[i + 1]
            out.append(square[r * size + c])
        return "".join(out)

    # Encrypt only the plaintext characters
    encrypted_chars = []
    for i in range(0, len(plain_chars), period):
        encrypted_chars.extend(enc_block(plain_chars[i : i + period]))

    # Reinsert non-alphabet characters at their original positions
    result = list(encrypted_chars)
    for pos_idx, ch in non_alpha_positions:
        result.insert(pos_idx, ch)

    return "".join(result)
