from __future__ import annotations

from stages.common import printable_ratio
from stages.xor import repeating_xor


class TestXORCipher:
    """Tests for XOR cipher operations."""

    def test_encrypt_decrypt_round_trip(self):
        """Encrypt and decrypt round trip."""
        plaintext = b"Hello, World!"
        key = b"KEY"
        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)
        assert decrypted == plaintext

    def test_single_byte_key(self):
        """Single byte key works correctly."""
        plaintext = b"ABCDEFGH"
        key = b"X"
        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)
        assert decrypted == plaintext

    def test_key_longer_than_plaintext(self):
        """Key longer than plaintext."""
        plaintext = b"HI"
        key = b"VERYLONGKEY"
        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)
        assert decrypted == plaintext

    def test_wrong_key_produces_garbage(self):
        """Wrong key produces incorrect output."""
        plaintext = b"SECRET"
        key1 = b"KEY1"
        key2 = b"KEY2"
        encrypted = repeating_xor(plaintext, key1)
        wrong_decrypt = repeating_xor(encrypted, key2)
        assert wrong_decrypt != plaintext

    def test_empty_key(self):
        """Empty key returns empty result."""
        result = repeating_xor(b"test", b"")
        assert result == b""

    def test_empty_plaintext(self):
        """Empty plaintext returns empty result."""
        result = repeating_xor(b"", b"KEY")
        assert result == b""

    def test_produces_printable_output(self):
        """Can produce printable ASCII output."""
        plaintext = b"Hello!!"
        key = b"\x00\x00\x00\x00\x00\x00\x00"
        result = repeating_xor(plaintext, key)
        assert printable_ratio(result) == 1.0

    def test_produces_non_printable_output(self):
        """Can produce non-printable output."""
        plaintext = b"AAAA"
        key = b"A"
        result = repeating_xor(plaintext, key)
        assert printable_ratio(result) == 0.0
