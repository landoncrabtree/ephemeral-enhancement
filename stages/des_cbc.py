"""
DES-CBC decryption stage.

Supports multiple IV derivation modes and PKCS7 / no padding.
Key and IV are 8 bytes. Input must be bytes (e.g. from b64 stage). Block size 8 bytes.
"""

from __future__ import annotations

import hashlib
from typing import Literal

PaddingMode = Literal["pkcs7", "nopadding"]

# IV modes: 0=key (padded/truncated to 8), 1=zero, 2=key+zero_pad, 3=md5(key)[:8], 4=sha256(key)[:8], 5=sha1(key)[:8]
N_IV_MODES = 6


def _iv_from_key(key: bytes, mode: int) -> bytes:
    if mode == 0:
        if len(key) >= 8:
            return key[:8]
        return key + (b"\x00" * (8 - len(key)))
    if mode == 1:
        return b"\x00" * 8
    if mode == 2:
        if len(key) >= 8:
            return key[:8]
        return key + (b"\x00" * (8 - len(key)))
    if mode == 3:
        return hashlib.md5(key).digest()[:8]
    if mode == 4:
        return hashlib.sha256(key).digest()[:8]
    if mode == 5:
        return hashlib.sha1(key).digest()[:8]
    return b"\x00" * 8


def des_cbc_decrypt(
    data: bytes,
    key: bytes,
    iv_mode: int,
    padding: Literal["pkcs7", "nopadding"] = "pkcs7",
) -> bytes | None:
    """
    Decrypt data using DES-CBC.

    Args:
        data: Ciphertext bytes (length multiple of 8).
        key: 8-byte key.
        iv_mode: 0=iv=key, 1=iv=zero, 2=iv=key+0pad, 3=md5(key)[:8], 4=sha256(key)[:8], 5=sha1(key)[:8].
        padding: "pkcs7" or "nopadding".

    Returns:
        Decrypted bytes, or None on error.
    """
    from Crypto.Cipher import DES  # type: ignore[import-untyped]
    from Crypto.Util.Padding import unpad  # type: ignore[import-untyped]

    if len(key) != 8:
        return None
    if len(data) % 8 != 0:
        return None
    iv = _iv_from_key(key, iv_mode)
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        out = cipher.decrypt(data)
    except Exception:
        return None
    if padding == "nopadding":
        return out
    try:
        return unpad(out, 8)
    except (ValueError, Exception):
        return None
