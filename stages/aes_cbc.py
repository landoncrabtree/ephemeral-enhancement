"""
AES-CBC decryption stage.

Supports multiple IV derivation modes and PKCS7 / no padding.
Key and IV are 16 bytes. Input must be bytes (e.g. from b64 stage).
"""

from __future__ import annotations

import hashlib
from typing import Literal

PaddingMode = Literal["pkcs7", "nopadding"]

# IV modes: 0=key (padded/truncated to 16), 1=zero, 2=key+zero_pad, 3=md5(key), 4=sha256(key)[:16], 5=sha1(key)[:16]
N_IV_MODES = 6


def _iv_from_key(key: bytes, mode: int) -> bytes:
    if mode == 0:
        # iv = key (truncate or pad to 16)
        if len(key) >= 16:
            return key[:16]
        return key + (b"\x00" * (16 - len(key)))
    if mode == 1:
        return b"\x00" * 16
    if mode == 2:
        # key + zero pad to 16
        if len(key) >= 16:
            return key[:16]
        return key + (b"\x00" * (16 - len(key)))
    if mode == 3:
        return hashlib.md5(key).digest()
    if mode == 4:
        return hashlib.sha256(key).digest()[:16]
    if mode == 5:
        return hashlib.sha1(key).digest()[:16]
    return b"\x00" * 16


def aes_cbc_decrypt(
    data: bytes,
    key: bytes,
    iv_mode: int,
    padding: Literal["pkcs7", "nopadding"] = "pkcs7",
) -> bytes | None:
    """
    Decrypt data using AES-CBC.

    Args:
        data: Ciphertext bytes (length multiple of 16).
        key: 16-byte key.
        iv_mode: 0=iv=key, 1=iv=zero, 2=iv=key+0pad, 3=md5(key), 4=sha256(key)[:16], 5=sha1(key)[:16].
        padding: "pkcs7" or "nopadding".

    Returns:
        Decrypted bytes, or None on error.
    """
    from Crypto.Cipher import AES  # type: ignore[import-untyped]
    from Crypto.Util.Padding import unpad  # type: ignore[import-untyped]

    if len(key) != 16:
        return None
    if len(data) % 16 != 0:
        return None
    iv = _iv_from_key(key, iv_mode)
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        out = cipher.decrypt(data)
    except Exception:
        return None
    if padding == "nopadding":
        return out
    try:
        return unpad(out, 16)
    except (ValueError, Exception):
        return None
