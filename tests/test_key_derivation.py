from __future__ import annotations

import hashlib

from stages.key_derivation import (
    MODE_MD5,
    MODE_RAW,
    MODE_SHA1,
    MODE_SHA256,
    N_KEY_DERIVATION_MODES,
    derive_key,
)


class TestKeyDerivation:
    """Tests for key derivation from wordlist candidates."""

    def test_raw_mode(self):
        """Raw mode returns UTF-8 bytes."""
        assert derive_key("hello", MODE_RAW) == b"hello"

    def test_md5_mode(self):
        """MD5 mode returns 16-byte hash."""
        key = derive_key("test", MODE_MD5)
        assert len(key) == 16
        assert key == hashlib.md5(b"test").digest()

    def test_sha1_mode(self):
        """SHA1 mode returns 20-byte hash."""
        key = derive_key("test", MODE_SHA1)
        assert len(key) == 20
        assert key == hashlib.sha1(b"test").digest()

    def test_sha256_mode(self):
        """SHA256 mode returns 32-byte hash."""
        key = derive_key("test", MODE_SHA256)
        assert len(key) == 32
        assert key == hashlib.sha256(b"test").digest()

    def test_n_modes_constant(self):
        """N_KEY_DERIVATION_MODES is 4."""
        assert N_KEY_DERIVATION_MODES == 4

    def test_all_modes_produce_bytes(self):
        """Every derivation mode returns bytes."""
        for mode in range(N_KEY_DERIVATION_MODES):
            result = derive_key("Zombies", mode)
            assert isinstance(result, bytes)
            assert len(result) > 0
