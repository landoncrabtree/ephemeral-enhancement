"""
3DES (Triple DES) block cipher stage.

Key must be 16 or 24 bytes (use key derivation with size=16 or size=24).
Input must be bytes (e.g. from b64 stage). Block size 8 bytes.
"""

from __future__ import annotations

def des3_decrypt(data: bytes, key: bytes) -> bytes | None:
    """
    Decrypt data using 3DES-ECB.

    Args:
        data: Ciphertext bytes (length multiple of 8).
        key: 16-byte (2-key 3DES) or 24-byte (3-key 3DES) key.

    Returns:
        Decrypted bytes, or None if key length wrong or block alignment wrong.
    """
    from Crypto.Cipher import DES3  # type: ignore[import-untyped]

    if len(key) not in (16, 24):
        return None
    if len(data) % 8 != 0:
        return None
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)
        return cipher.decrypt(data)
    except Exception:
        return None
