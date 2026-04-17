from __future__ import annotations

from stages.railfence import railfence_decrypt, redefense_decrypt


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


class TestRedefenseDecrypt:
    def test_roundtrip_secretkey(self):
        """Decrypt known ciphertext encrypted with SECRETKEY."""
        assert redefense_decrypt("IEGHSAINHDADSMETSSEI", "SECRETKEY") == "THISISAHIDDENMESSAGE"

    def test_roundtrip_simple(self):
        assert redefense_decrypt("ELWRDHOLLO", "KEY") == "HELLOWORLD"

    def test_single_char_key(self):
        assert redefense_decrypt("HELLO", "A") == "HELLO"

    def test_empty(self):
        assert redefense_decrypt("", "KEY") == ""

    def test_two_rail_key(self):
        """Two-char key = standard rail fence with 2 rails."""
        assert redefense_decrypt("HLOOLELWRD", "AB") == "HELLOWORLD"
