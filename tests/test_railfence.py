from __future__ import annotations

from stages.railfence import railfence_decrypt


class TestRailfenceCipher:
    """Tests for Railfence cipher operations."""

    def test_decrypt_valid_3_rails(self):
        """Decrypt valid ciphertext with 3 rails."""
        ciphertext = "Wtk neatc tdw aaa"
        plaintext = railfence_decrypt(ciphertext, 3)
        assert plaintext == "We attack at dawn"

    def test_decrypt_valid_2_rails(self):
        """Decrypt valid ciphertext with 2 rails."""
        ciphertext = "TIDHSSIDNIHE"
        plaintext = railfence_decrypt(ciphertext, 3)
        assert plaintext == "THISISHIDDEN"

    def test_single_rail_no_change(self):
        """Single rail produces no change."""
        ciphertext = "ZOMBIES"
        result = railfence_decrypt(ciphertext, 1)
        assert result == ciphertext

    def test_empty_string(self):
        """Empty string returns empty."""
        result = railfence_decrypt("", 3)
        assert result == ""

    def test_rails_equal_length(self):
        """Rails equal to text length."""
        ciphertext = "ABC"
        result = railfence_decrypt(ciphertext, 3)
        assert isinstance(result, str)
