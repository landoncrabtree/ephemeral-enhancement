from __future__ import annotations

import hashlib

from stages.key_derivation import (
    MODE_ALL_ZEROS,
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
        assert derive_key("ab", MODE_RAW, size=4) == b"ab\x00\x00"

    def test_md5_mode(self):
        """MD5 mode returns 16-byte hash."""
        key = derive_key("test", MODE_MD5)
        assert len(key) == 16
        assert key == hashlib.md5(b"test").digest()

    def test_sha1_mode_truncated_to_16(self):
        """SHA1 mode returns first 16 bytes of hash."""
        key = derive_key("test", MODE_SHA1)
        assert len(key) == 16

    def test_sha256_mode_truncated_to_16(self):
        """SHA256 mode returns first 16 bytes of hash."""
        key = derive_key("test", MODE_SHA256)
        assert len(key) == 16

    def test_all_zeros_mode(self):
        """All-zeros mode returns 16 zero bytes regardless of input."""
        key1 = derive_key("ZOMBIE", MODE_ALL_ZEROS)
        key2 = derive_key("ANYTHING", MODE_ALL_ZEROS)
        assert key1 == b"\x00" * 16
        assert key2 == b"\x00" * 16

    def test_all_zeros_with_size(self):
        """All-zeros mode respects size parameter."""
        key = derive_key("test", MODE_ALL_ZEROS, size=8)
        assert key == b"\x00" * 8

    def test_size_truncates(self):
        """size parameter truncates long keys."""
        key = derive_key("a" * 20, MODE_RAW, size=8)
        assert len(key) == 8
        assert key == b"aaaaaaaa"

    def test_size_pads(self):
        """size parameter zero-pads short keys."""
        key = derive_key("ab", MODE_RAW, size=8)
        assert len(key) == 8
        assert key == b"ab\x00\x00\x00\x00\x00\x00"

    def test_n_modes_constant(self):
        """N_KEY_DERIVATION_MODES is 8."""
        assert N_KEY_DERIVATION_MODES == 8
