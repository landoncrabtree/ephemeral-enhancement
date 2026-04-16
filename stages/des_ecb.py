"""
DES-ECB decryption stage.

Supports PKCS7 padding or no padding. Key must be 8 bytes (use key derivation with size=8).
Input must be bytes (e.g. from b64 stage). Block size 8 bytes.
"""

from __future__ import annotations

from typing import Literal

PaddingMode = Literal["pkcs7", "nopadding"]


def des_ecb_decrypt(
    data: bytes,
    key: bytes,
    padding: PaddingMode = "pkcs7",
) -> bytes | None:
    """
    Decrypt data using DES-ECB.

    Args:
        data: Ciphertext bytes (length multiple of 8 for nopadding).
        key: 8-byte key.
        padding: "pkcs7" (strip padding after decrypt) or "nopadding".

    Returns:
        Decrypted bytes, or None if key length wrong, block alignment wrong, or invalid padding.
    """
    from Crypto.Cipher import DES  # type: ignore[import-untyped]
    from Crypto.Util.Padding import unpad  # type: ignore[import-untyped]

    if len(key) != 8:
        return None
    if len(data) % 8 != 0:
        return None
    try:
        cipher = DES.new(key, DES.MODE_ECB)
        out = cipher.decrypt(data)
    except Exception:
        return None
    if padding == "nopadding":
        return out
    try:
        return unpad(out, 8)
    except (ValueError, Exception):
        return None
