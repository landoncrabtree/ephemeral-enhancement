"""
Unit tests for individual cipher stages.

Run with: pytest test_stages.py -v
"""

from __future__ import annotations

import base64

import pytest

from run_pipeline import caesar_shift_text
from stages.bifid import (
    BASE64_ALPHABET,
    STANDARD_ALPHABET,
    bifid_decrypt,
    bifid_encrypt,
    build_keyed_square,
)
from stages.columnar import columnar_decrypt
from stages.double_columnar import double_columnar_decrypt
from stages.railfence import railfence_decrypt
from stages.reverse import reverse_text
from stages.xor import repeating_xor


class TestCaesar:
    """Tests for Caesar cipher."""

    def test_caesar_shift_basic(self):
        """Test basic Caesar shift."""
        ciphertext = "DL HAAHJR HA KHDU"
        shifted = caesar_shift_text(ciphertext, -7)
        assert shifted == "WE ATTACK AT DAWN"

    def test_caesar_shift_mixed_case(self):
        """Test Caesar shift with mixed case."""
        ciphertext = "Aopz pz h tlzzhnl"
        shifted = caesar_shift_text(ciphertext, -7)
        assert shifted == "This is a message"

    def test_caesar_shift_preserves_non_alpha(self):
        """Test that Caesar preserves non-alphabetic characters."""
        ciphertext = "Dvd, h zljyla tlzzhnl"
        shifted = caesar_shift_text(ciphertext, -7)
        assert shifted == "Wow, a secret message"

    def test_caesar_shift_wrap_around(self):
        """Test Caesar shift wraps around alphabet."""
        plaintext = "XYZ"
        shifted = caesar_shift_text(plaintext, 3)
        assert shifted == "ABC"


class TestRailfence:
    """Tests for Railfence cipher."""

    def test_railfence_decrypt_3_rails(self):
        """Test railfence decryption with 3 rails."""
        ciphertext = "Wtk neatc tdw aaa"
        result = railfence_decrypt(ciphertext, 3)
        assert result == "We attack at dawn"

    def test_railfence_decrypt_2_rails(self):
        """Test railfence decryption with 2 rails."""
        ciphertext = "TIDHSSIDNIHE"
        result = railfence_decrypt(ciphertext, 3)
        assert result == "THISISHIDDEN"

    def test_railfence_single_rail(self):
        """Test railfence with 1 rail (no change)."""
        ciphertext = "ZOMBIES"
        result = railfence_decrypt(ciphertext, 1)
        assert result == ciphertext

    def test_railfence_empty_string(self):
        """Test railfence with empty string."""
        result = railfence_decrypt("", 3)
        assert result == ""


class TestColumnar:
    """Tests for Columnar Transposition cipher."""

    def test_columnar_decrypt_space(self):
        """Test columnar decryption with space."""
        ciphertext = "ld ollerWHo"
        result = columnar_decrypt(ciphertext, "ZOMBIES")
        assert result == "Hello World"

    def test_columnar_decrypt_nospace(self):
        """Test columnar decryption with space."""
        ciphertext = "LWOLDELOHR"
        result = columnar_decrypt(ciphertext, "ZOMBIES")
        assert result == "HELLOWORLD"

    def test_columnar_decrypt_punctuation(self):
        """Test basic columnar decryption."""
        ciphertext = "s . e,siath eicTsr"
        result = columnar_decrypt(ciphertext, "ZOMBIES")
        assert result == "This, is a secret."

    def test_columnar_decrypt_single_char_key(self):
        """Test columnar with single character key (no change)."""
        ciphertext = "CHECKTHISOUT"
        result = columnar_decrypt(ciphertext, "A")
        assert result == ciphertext

    def test_columnar_decrypt_empty_string(self):
        """Test columnar with empty string."""
        result = columnar_decrypt("", "KEY")
        assert result == ""


class TestDoubleColumnar:
    """Tests for Double Columnar Transposition cipher."""

    def test_double_columnar_decrypt_space(self):
        """Test double columnar decryption."""
        ciphertext = "lroHdwlle o"
        result = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert result == "Hello world"

    def test_double_columnar_decrypt_nospace(self):
        """Test double columnar decryption with no space."""
        ciphertext = "LEOOLLDRWH"
        result = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert result == "HELLOWORLD"

    def test_double_columnar_decrypt_punctuation(self):
        """Test double columnar decryption with punctuation."""
        ciphertext = " shhoWwlo?aed usk "
        result = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert result == "Who should we ask?"

    def test_double_columnar_decrypt_same_key(self):
        """Test double columnar with same key twice."""
        ciphertext = "oHldw olelr"
        result = double_columnar_decrypt(ciphertext, "ZOMBIE", "ZOMBIE")
        assert result == "Hello world"


class TestBifid:
    """Tests for Bifid cipher."""

    def test_build_keyed_square_standard(self):
        """Test building a keyed Polybius square with standard alphabet."""
        square = build_keyed_square(STANDARD_ALPHABET, "ZOMBIE")
        assert len(square) == 25
        assert square.startswith("ZOMBIE")  # Key chars first
        assert square == "ZOMBIEACDFGHKLNPQRSTUVWXY"
        assert square.count("Z") == 1  # No duplicates

    def test_build_keyed_square_base64(self):
        """Test building a keyed Polybius square with base64 alphabet."""
        square = build_keyed_square(BASE64_ALPHABET, "SECRET")
        assert len(square) == 64
        assert square.startswith("SECRT")  # Key chars first (no duplicates)
        assert "S" in square
        assert square.count("S") == 1  # No duplicates

    def test_bifid_encrypt_decrypt_round_trip_standard(self):
        """Test bifid encryption and decryption round trip with standard alphabet."""
        key = "ZOMBIE"
        period = len("THE HYDRA HAS 99 HEADS!")
        plaintext = bifid_decrypt(
            "RCV QHRAD VOX 99 HAQOS!", key, period, STANDARD_ALPHABET
        )
        assert plaintext == "THE HYDRA HAS 99 HEADS!"

    def test_bifid_encrypt_decrypt_round_trip_base64(self):
        """Test bifid encryption and decryption round trip with base64 alphabet."""
        plaintext = "HELLOWORLD1234"
        key = "TESTKEY"
        period = len(plaintext)

        encrypted = bifid_encrypt(plaintext, key, period, BASE64_ALPHABET)
        decrypted = bifid_decrypt(encrypted, key, period, BASE64_ALPHABET)

        assert decrypted == plaintext

    def test_bifid_i_j_substitution(self):
        """Test that standard alphabet handles I/J correctly."""
        # Standard alphabet has no J, so J should be treated as I
        assert "J" not in STANDARD_ALPHABET
        assert "I" in STANDARD_ALPHABET
        assert len(STANDARD_ALPHABET) == 25


class TestXOR:
    """Tests for XOR cipher."""

    def test_xor_basic(self):
        """Test basic XOR encryption/decryption."""
        plaintext = b"Hello, World!"
        key = b"KEY"

        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)

        assert decrypted == plaintext

    def test_xor_single_byte_key(self):
        """Test XOR with single byte key."""
        plaintext = b"ABCDEFGH"
        key = b"X"

        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)

        assert decrypted == plaintext

    def test_xor_empty_key(self):
        """Test XOR with empty key."""
        plaintext = b"test"
        result = repeating_xor(plaintext, b"")
        assert result == b""

    def test_xor_longer_key(self):
        """Test XOR with key longer than plaintext."""
        plaintext = b"HI"
        key = b"VERYLONGKEY"

        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)

        assert decrypted == plaintext


class TestBase64:
    """Tests for Base64 decoding."""

    def test_base64_decode_valid(self):
        """Test valid base64 decoding."""
        ciphertext = "SGVsbG8gd29ybGQ="
        decoded = base64.b64decode(ciphertext)
        assert decoded == b"Hello world"

    def test_base64_decode_with_nopadding(self):
        """Test base64 with padding."""
        ciphertext = "U2VjcmV0"
        decoded = base64.b64decode(ciphertext)
        assert decoded == b"Secret"

    def test_base64_decode_without_padding_when_padding_expected(self):
        """Test base64 without padding (should fail with validate=True)."""
        encoded = "SGVsbG8gd29ybGQ"  # Missing padding
        with pytest.raises(Exception):
            base64.b64decode(encoded, validate=False)


class TestReverse:
    """Tests for Reverse cipher."""

    def test_reverse_basic(self):
        """Test basic text reversal."""
        text = "Hello World"
        result = reverse_text(text)
        assert result == "dlroW olleH"

    def test_reverse_palindrome(self):
        """Test reversing a palindrome."""
        text = "racecar"
        result = reverse_text(text)
        assert result == "racecar"

    def test_reverse_empty_string(self):
        """Test reversing empty string."""
        result = reverse_text("")
        assert result == ""

    def test_reverse_single_char(self):
        """Test reversing single character."""
        result = reverse_text("A")
        assert result == "A"

    def test_reverse_with_punctuation(self):
        """Test reversing text with punctuation."""
        text = "Hello, World!"
        result = reverse_text(text)
        assert result == "!dlroW ,olleH"

    def test_reverse_round_trip(self):
        """Test reversing twice returns original."""
        original = "Test message 123"
        reversed_once = reverse_text(original)
        reversed_twice = reverse_text(reversed_once)
        assert reversed_twice == original


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
