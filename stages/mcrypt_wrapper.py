"""
Python ctypes wrapper for libmcrypt.

Provides a high-level decrypt function that matches PHP mcrypt_decrypt() semantics:
- Zero-pads ciphertext to block size for block algorithms
- Zero-pads key to algorithm's key size
- Output contains null padding (no PKCS7)

Also provides McryptHandleCache for efficient handle reuse in brute-force loops.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Optional

# Locate libmcrypt shared library relative to project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LIB_SEARCH_PATHS = [
    _PROJECT_ROOT / "lib" / "mcrypt" / "lib" / "libmcrypt.dylib",
    _PROJECT_ROOT / "lib" / "mcrypt" / "lib" / "libmcrypt.so",
    _PROJECT_ROOT / "lib" / "mcrypt" / "lib" / "libmcrypt.so.4",
]

_lib: Optional[ctypes.CDLL] = None


def _load_lib() -> ctypes.CDLL:
    """Load libmcrypt, searching known paths."""
    global _lib
    if _lib is not None:
        return _lib

    for path in _LIB_SEARCH_PATHS:
        if path.exists():
            _lib = ctypes.CDLL(str(path))
            _setup_prototypes(_lib)
            return _lib

    raise RuntimeError(
        "libmcrypt not found. Run: ./scripts/build_mcrypt.sh\n"
        f"Searched: {[str(p) for p in _LIB_SEARCH_PATHS]}"
    )


def _setup_prototypes(lib: ctypes.CDLL) -> None:
    """Set ctypes argument/return types for libmcrypt functions."""
    # MCRYPT is a pointer to opaque struct
    MCRYPT = ctypes.c_void_p

    lib.mcrypt_module_open.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.mcrypt_module_open.restype = MCRYPT

    lib.mcrypt_module_close.argtypes = [MCRYPT]
    lib.mcrypt_module_close.restype = ctypes.c_int

    lib.mcrypt_generic_init.argtypes = [
        MCRYPT, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
    ]
    lib.mcrypt_generic_init.restype = ctypes.c_int

    lib.mcrypt_generic_deinit.argtypes = [MCRYPT]
    lib.mcrypt_generic_deinit.restype = ctypes.c_int

    lib.mdecrypt_generic.argtypes = [MCRYPT, ctypes.c_void_p, ctypes.c_int]
    lib.mdecrypt_generic.restype = ctypes.c_int

    lib.mcrypt_enc_get_block_size.argtypes = [MCRYPT]
    lib.mcrypt_enc_get_block_size.restype = ctypes.c_int

    lib.mcrypt_enc_get_key_size.argtypes = [MCRYPT]
    lib.mcrypt_enc_get_key_size.restype = ctypes.c_int

    lib.mcrypt_enc_get_iv_size.argtypes = [MCRYPT]
    lib.mcrypt_enc_get_iv_size.restype = ctypes.c_int

    lib.mcrypt_enc_is_block_algorithm.argtypes = [MCRYPT]
    lib.mcrypt_enc_is_block_algorithm.restype = ctypes.c_int

    lib.mcrypt_enc_is_block_mode.argtypes = [MCRYPT]
    lib.mcrypt_enc_is_block_mode.restype = ctypes.c_int

    lib.mcrypt_enc_mode_has_iv.argtypes = [MCRYPT]
    lib.mcrypt_enc_mode_has_iv.restype = ctypes.c_int

    lib.mcrypt_enc_get_supported_key_sizes.argtypes = [
        MCRYPT, ctypes.POINTER(ctypes.c_int),
    ]
    lib.mcrypt_enc_get_supported_key_sizes.restype = ctypes.POINTER(ctypes.c_int)

    lib.mcrypt_list_algorithms.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    lib.mcrypt_list_algorithms.restype = ctypes.POINTER(ctypes.c_char_p)

    lib.mcrypt_list_modes.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    lib.mcrypt_list_modes.restype = ctypes.POINTER(ctypes.c_char_p)

    lib.mcrypt_free_p.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
    lib.mcrypt_free_p.restype = None

    lib.mcrypt_free.argtypes = [ctypes.c_void_p]
    lib.mcrypt_free.restype = None


def list_algorithms() -> list[str]:
    """Return all algorithms available in the compiled libmcrypt."""
    lib = _load_lib()
    n = ctypes.c_int(0)
    arr = lib.mcrypt_list_algorithms(None, ctypes.byref(n))
    result = [arr[i].decode() for i in range(n.value)]
    lib.mcrypt_free_p(arr, n)
    return sorted(result)


def list_modes() -> list[str]:
    """Return all modes available in the compiled libmcrypt."""
    lib = _load_lib()
    n = ctypes.c_int(0)
    arr = lib.mcrypt_list_modes(None, ctypes.byref(n))
    result = [arr[i].decode() for i in range(n.value)]
    lib.mcrypt_free_p(arr, n)
    return sorted(result)


def get_algo_info(algo: str, mode: str = "ecb") -> dict:
    """Query key size, block size, and supported key sizes for an algorithm.

    Opens a temporary handle to query properties. Uses the given mode
    (default: ecb; use "stream" for stream ciphers).
    """
    lib = _load_lib()
    td = lib.mcrypt_module_open(
        algo.encode(), None, mode.encode(), None,
    )
    if td is None or td == 0:
        raise ValueError(f"Cannot open mcrypt module for algorithm: {algo}")

    try:
        block_size = lib.mcrypt_enc_get_block_size(td)
        max_key_size = lib.mcrypt_enc_get_key_size(td)
        is_block = bool(lib.mcrypt_enc_is_block_algorithm(td))

        n = ctypes.c_int(0)
        sizes_ptr = lib.mcrypt_enc_get_supported_key_sizes(td, ctypes.byref(n))
        if n.value > 0:
            key_sizes = [sizes_ptr[i] for i in range(n.value)]
            lib.mcrypt_free(sizes_ptr)
        else:
            # Variable key size: 1..max_key_size
            key_sizes = None

        return {
            "block_size": block_size,
            "max_key_size": max_key_size,
            "key_sizes": key_sizes,
            "is_block": is_block,
        }
    finally:
        lib.mcrypt_module_close(td)


class McryptHandle:
    """Wrapper around an open mcrypt module handle."""

    def __init__(self, algo: str, mode: str):
        self._lib = _load_lib()
        self._td = self._lib.mcrypt_module_open(
            algo.encode(), None, mode.encode(), None,
        )
        if self._td is None or self._td == 0:
            raise ValueError(f"Cannot open mcrypt module: {algo}/{mode}")

        self.algo = algo
        self.mode = mode
        self.block_size = self._lib.mcrypt_enc_get_block_size(self._td)
        self.max_key_size = self._lib.mcrypt_enc_get_key_size(self._td)
        self.iv_size = self._lib.mcrypt_enc_get_iv_size(self._td)
        self.needs_iv = bool(self._lib.mcrypt_enc_mode_has_iv(self._td))
        self.is_block = bool(self._lib.mcrypt_enc_is_block_algorithm(self._td))
        self._initialized = False

    def decrypt(self, key: bytes, iv: bytes | None, data: bytes) -> bytes | None:
        """
        Decrypt data using PHP mcrypt_decrypt() semantics.

        - Key is zero-padded or truncated to max_key_size
        - Data is zero-padded to block_size multiple (block ciphers only)
        - IV is zero-padded or truncated to iv_size (if needed)
        - Returns decrypted bytes (may contain null padding)
        - Returns None on error
        """
        # PHP mcrypt_decrypt key handling: use key as-is if it's an accepted
        # length. Truncate if longer than max_key_size. PHP does NOT zero-pad
        # short keys — it passes them directly to libmcrypt.
        if len(key) > self.max_key_size:
            key = key[: self.max_key_size]

        # PHP zero-pads data to block size for block algorithms
        if self.is_block and self.block_size > 0:
            remainder = len(data) % self.block_size
            if remainder != 0:
                data = data + b"\x00" * (self.block_size - remainder)

        # Handle IV (executor provides correctly-sized IVs;
        # this is a safety net for direct wrapper usage)
        iv_ptr = None
        if self.needs_iv:
            if iv is None:
                iv = b"\x00" * self.iv_size
            if len(iv) > self.iv_size:
                iv = iv[: self.iv_size]
            elif len(iv) < self.iv_size:
                iv = iv + b"\x00" * (self.iv_size - len(iv))
            iv_buf = ctypes.create_string_buffer(iv)
            iv_ptr = ctypes.cast(iv_buf, ctypes.c_void_p)

        key_buf = ctypes.create_string_buffer(key)

        ret = self._lib.mcrypt_generic_init(
            self._td,
            ctypes.cast(key_buf, ctypes.c_void_p),
            len(key),
            iv_ptr,
        )
        if ret < 0:
            return None
        self._initialized = True

        try:
            data_len = len(data)
            out_buf = (ctypes.c_ubyte * data_len).from_buffer_copy(data)
            ret = self._lib.mdecrypt_generic(
                self._td,
                ctypes.cast(out_buf, ctypes.c_void_p),
                data_len,
            )
            if ret != 0:
                return None
            return bytes(out_buf)
        finally:
            self._lib.mcrypt_generic_deinit(self._td)
            self._initialized = False

    def close(self) -> None:
        """Close the mcrypt module handle."""
        if self._td is not None and self._td != 0:
            if self._initialized:
                self._lib.mcrypt_generic_deinit(self._td)
                self._initialized = False
            self._lib.mcrypt_module_close(self._td)
            self._td = None

    def __del__(self):
        self.close()


class McryptHandleCache:
    """
    Cache of McryptHandle objects keyed by (algo, mode).

    Each worker process should have its own cache instance.
    Handles are opened once and reused across brute-force attempts —
    only init/deinit is called per key.
    """

    def __init__(self):
        self._cache: dict[tuple[str, str], McryptHandle] = {}

    def get(self, algo: str, mode: str) -> McryptHandle:
        """Get or create a handle for the given algo+mode."""
        key = (algo, mode)
        if key not in self._cache:
            self._cache[key] = McryptHandle(algo, mode)
        return self._cache[key]

    def close_all(self) -> None:
        """Close all cached handles."""
        for handle in self._cache.values():
            handle.close()
        self._cache.clear()

    def __del__(self):
        self.close_all()


def mcrypt_decrypt(
    algo: str,
    mode: str,
    key: bytes,
    iv: bytes | None,
    data: bytes,
    *,
    handle_cache: McryptHandleCache | None = None,
) -> bytes | None:
    """
    High-level decrypt matching PHP mcrypt_decrypt() behavior.

    Args:
        algo: Algorithm name (e.g. "rijndael-128", "des", "arcfour")
        mode: Mode name (e.g. "ecb", "cbc", "stream")
        key: Raw key bytes
        iv: IV bytes (or None for ECB/stream)
        data: Ciphertext bytes
        handle_cache: Optional cache for handle reuse in brute-force loops

    Returns:
        Decrypted bytes or None on error
    """
    if handle_cache is not None:
        handle = handle_cache.get(algo, mode)
    else:
        handle = McryptHandle(algo, mode)

    try:
        return handle.decrypt(key, iv, data)
    except Exception:
        return None
    finally:
        if handle_cache is None:
            handle.close()
