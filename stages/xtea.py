"""
XTEA block cipher stage (ECB mode).

Uses the xtea package (https://pypi.org/project/xtea/).
Key must be 16 bytes. Block size 8 bytes. Input must be bytes (e.g. from b64 stage).
"""

from __future__ import annotations

def xtea_decrypt(data: bytes, key: bytes) -> bytes | None:
    """
    Decrypt data using XTEA-ECB.

    Args:
        data: Ciphertext bytes (length multiple of 8).
        key: 16-byte key.

    Returns:
        Decrypted bytes, or None if key length wrong or block alignment wrong.
    """
    from xtea import MODE_ECB, new  # type: ignore[import-untyped]

    if len(key) != 16:
        return None
    if len(data) % 8 != 0:
        return None
    try:
        cipher = new(key, mode=MODE_ECB)
        return cipher.decrypt(data)
    except Exception:
        return None
