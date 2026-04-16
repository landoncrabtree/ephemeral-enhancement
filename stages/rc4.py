"""
RC4 (ARC4) stream cipher stage.

Decrypts bytes with a key (any length). Used after b64 or similar;
input must be bytes.
"""

from __future__ import annotations

def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using RC4 with the given key.

    Args:
        data: Ciphertext bytes.
        key: Key bytes (any length).

    Returns:
        Decrypted plaintext bytes.
    """
    from Crypto.Cipher import ARC4  # type: ignore[import-untyped]

    if not key:
        return data
    cipher = ARC4.new(key)
    return cipher.decrypt(data)
