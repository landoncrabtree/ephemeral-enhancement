"""
Unified mcrypt decryption stage.

Provides a single decrypt function used by the executor for all
mcrypt-based cipher stages. Wraps mcrypt_wrapper with error handling.
"""

from __future__ import annotations

from stages.mcrypt_wrapper import McryptHandleCache, mcrypt_decrypt


def mcrypt_decrypt_stage(
    data: bytes,
    algo: str,
    mode: str,
    key: bytes,
    iv: bytes | None,
    *,
    handle_cache: McryptHandleCache | None = None,
) -> bytes | None:
    """
    Decrypt data using mcrypt with PHP-compatible semantics.

    Args:
        data: Ciphertext bytes
        algo: Mcrypt algorithm name (e.g. "rijndael-128", "des")
        mode: Mcrypt mode name (e.g. "ecb", "cbc", "stream")
        key: Raw key bytes (will be padded/truncated by wrapper)
        iv: IV bytes or None
        handle_cache: Optional handle cache for brute-force performance

    Returns:
        Decrypted bytes or None on any error
    """
    if not data:
        return None
    try:
        return mcrypt_decrypt(
            algo, mode, key, iv, data, handle_cache=handle_cache,
        )
    except Exception:
        return None
