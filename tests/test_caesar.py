from __future__ import annotations

from stages.caesar import caesar_shift_text


class TestCaesarCipher:
    """Tests for Caesar cipher shift operations."""

    def test_decrypt_valid_uppercase(self):
        """Decrypt valid uppercase ciphertext."""
        ciphertext = "DL HAAHJR HA KHDU"
        plaintext = caesar_shift_text(ciphertext, -7)
        assert plaintext == "WE ATTACK AT DAWN"

    def test_decrypt_valid_mixed_case(self):
        """Decrypt valid mixed case ciphertext."""
        ciphertext = "Aopz pz h tlzzhnl"
        plaintext = caesar_shift_text(ciphertext, -7)
        assert plaintext == "This is a message"

    def test_decrypt_with_punctuation(self):
        """Decrypt preserving punctuation and spaces."""
        ciphertext = "Dvd, h zljyla tlzzhnl!"
        plaintext = caesar_shift_text(ciphertext, -7)
        assert plaintext == "Wow, a secret message!"

    def test_shift_zero_no_change(self):
        """Shift of 0 produces no change."""
        text = "HELLO WORLD"
        result = caesar_shift_text(text, 0)
        assert result == text

    def test_wrap_around_alphabet(self):
        """Shift wraps around alphabet boundaries."""
        plaintext = "XYZ"
        ciphertext = caesar_shift_text(plaintext, 3)
        assert ciphertext == "ABC"

    def test_negative_shift(self):
        """Negative shift works correctly."""
        ciphertext = "BCD"
        plaintext = caesar_shift_text(ciphertext, -1)
        assert plaintext == "ABC"

    def test_large_shift_modulo(self):
        """Large shift values use modulo 26."""
        text = "ABC"
        result = caesar_shift_text(text, 26)
        assert result == "ABC"

    def test_digit_shift(self):
        """Digits shift within 0-9."""
        assert caesar_shift_text("789", 3) == "012"
        assert caesar_shift_text("012", -3) == "789"

    def test_mixed_alphanumeric(self):
        """Digits and letters shift independently, symbols preserved."""
        result = caesar_shift_text("abc123/+=", 1)
        assert result == "bcd234/+="
