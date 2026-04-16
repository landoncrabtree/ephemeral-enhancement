"""
AES-ECB decryption stage.

Supports PKCS7 padding or no padding. Key must be 16 bytes (use key derivation).
Input must be bytes (e.g. from b64 stage).
"""

from __future__ import annotations

from typing import Literal

PaddingMode = Literal["pkcs7", "nopadding"]


def aes_ecb_decrypt(
    data: bytes,
    key: bytes,
    padding: PaddingMode = "pkcs7",
) -> bytes | None:
    """
    Decrypt data using AES-ECB.

    Args:
        data: Ciphertext bytes (length multiple of 16 for nopadding).
        key: 16-byte key.
        padding: "pkcs7" (strip padding after decrypt) or "nopadding".

    Returns:
        Decrypted bytes, or None if key length wrong, block alignment wrong, or invalid padding.
    """
    from Crypto.Cipher import AES  # type: ignore[import-untyped]
    from Crypto.Util.Padding import unpad  # type: ignore[import-untyped]

    if len(key) != 16:
        return None
    if len(data) % 16 != 0:
        return None
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        out = cipher.decrypt(data)
    except Exception:
        return None
    if padding == "nopadding":
        return out
    try:
        return unpad(out, 16)
    except (ValueError, Exception):
        return None
