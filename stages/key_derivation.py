"""
Key derivation from wordlist candidates.

Turns a string candidate into a byte key for symmetric ciphers (AES, DES, RC4, XTEA).
Used by binary stages that bruteforce keys from a dictionary.
"""

from __future__ import annotations

import hashlib

# Modes: raw, pad_zero_16, truncate_16, repeat_16, md5, sha1, sha256, all_zeros
N_KEY_DERIVATION_MODES = 8

MODE_RAW = 0
MODE_PAD_ZERO_16 = 1
MODE_TRUNCATE_16 = 2
MODE_REPEAT_16 = 3
MODE_MD5 = 4
MODE_SHA1 = 5
MODE_SHA256 = 6
MODE_ALL_ZEROS = 7


def derive_key(word: str, mode: int, size: int | None = None) -> bytes:
    """
    Derive a byte key from a wordlist candidate.

    Args:
        word: The candidate string (e.g. dictionary word).
        mode: Derivation mode 0..6 (raw, pad_zero_16, truncate_16, repeat_16, md5, sha1, sha256).
        size: If set, truncate or zero-pad result to this length (for DES=8, AES=16, etc.).

    Returns:
        The derived key bytes.
    """
    raw = word.encode("utf-8", errors="ignore")

    if mode == MODE_RAW:
        key = raw
    elif mode == MODE_PAD_ZERO_16:
        if len(raw) >= 16:
            key = raw[:16]
        else:
            key = raw + (b"\x00" * (16 - len(raw)))
    elif mode == MODE_TRUNCATE_16:
        key = raw[:16] if len(raw) >= 16 else raw
    elif mode == MODE_REPEAT_16:
        if not raw:
            key = b"\x00" * 16
        else:
            key = (raw * (16 // len(raw) + 1))[:16]
    elif mode == MODE_MD5:
        key = hashlib.md5(raw).digest()
    elif mode == MODE_SHA1:
        key = hashlib.sha1(raw).digest()[:16]
    elif mode == MODE_SHA256:
        key = hashlib.sha256(raw).digest()[:16]
    elif mode == MODE_ALL_ZEROS:
        key = b"\x00" * 16
    else:
        key = raw

    if size is not None:
        if len(key) >= size:
            key = key[:size]
        else:
            key = key + (b"\x00" * (size - len(key)))
    return key
