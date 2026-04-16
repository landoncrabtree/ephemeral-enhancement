"""
Key derivation from wordlist candidates.

Turns a string candidate into a byte key for symmetric ciphers.
Used by binary stages that bruteforce keys from a dictionary.
"""

from __future__ import annotations

import hashlib

# Modes: raw, md5, sha1, sha256
N_KEY_DERIVATION_MODES = 4

MODE_RAW = 0
MODE_MD5 = 1
MODE_SHA1 = 2
MODE_SHA256 = 3

DERIVATION_NAMES = {
    MODE_RAW: "raw",
    MODE_MD5: "md5",
    MODE_SHA1: "sha1",
    MODE_SHA256: "sha256",
}


def derive_key(word: str, mode: int) -> bytes:
    """
    Derive a byte key from a wordlist candidate.

    Args:
        word: The candidate string (e.g. dictionary word).
        mode: Derivation mode (0=raw, 1=md5, 2=sha1, 3=sha256).

    Returns:
        The derived key bytes.
    """
    raw = word.encode("utf-8", errors="ignore")

    if mode == MODE_RAW:
        return raw
    elif mode == MODE_MD5:
        return hashlib.md5(raw).digest()
    elif mode == MODE_SHA1:
        return hashlib.sha1(raw).digest()
    elif mode == MODE_SHA256:
        return hashlib.sha256(raw).digest()
    else:
        return raw
