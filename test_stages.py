"""
Unit tests for individual cipher stages.

Structure:
- Each cipher stage has True/False/Edge test cases
- Utility functions (scoring, type detection) have dedicated test classes
- Tests are organized by functionality and follow a consistent pattern

Run with: pytest test_stages.py -v
"""

from __future__ import annotations

import base64

import pytest

from stages.bifid import (
    BASE64_ALPHABET,
    STANDARD_ALPHABET,
    bifid_decrypt,
    bifid_encrypt,
    build_keyed_square,
)
from stages.caesar import caesar_shift_text
from stages.columnar import columnar_decrypt
from stages.common import combined_score, printable_ratio
from stages.double_columnar import double_columnar_decrypt
from stages.railfence import railfence_decrypt
from stages.reverse import reverse_text
from stages.xor import repeating_xor

# ============================================================================
# CIPHER STAGE TESTS
# ============================================================================


class TestCaesarCipher:
    """Tests for Caesar cipher shift operations."""

    # True Cases (Valid decryption)
    def test_decrypt_valid_uppercase(self):
        """Caesar: Decrypt valid uppercase ciphertext."""
        ciphertext = "DL HAAHJR HA KHDU"
        plaintext = caesar_shift_text(ciphertext, -7)
        assert plaintext == "WE ATTACK AT DAWN"

    def test_decrypt_valid_mixed_case(self):
        """Caesar: Decrypt valid mixed case ciphertext."""
        ciphertext = "Aopz pz h tlzzhnl"
        plaintext = caesar_shift_text(ciphertext, -7)
        assert plaintext == "This is a message"

    def test_decrypt_with_punctuation(self):
        """Caesar: Decrypt preserving punctuation and spaces."""
        ciphertext = "Dvd, h zljyla tlzzhnl!"
        plaintext = caesar_shift_text(ciphertext, -7)
        assert plaintext == "Wow, a secret message!"

    # False Cases (Invalid/no-op)
    def test_shift_zero_no_change(self):
        """Caesar: Shift of 0 produces no change."""
        text = "HELLO WORLD"
        result = caesar_shift_text(text, 0)
        assert result == text

    # Edge Cases
    def test_wrap_around_alphabet(self):
        """Caesar: Shift wraps around alphabet boundaries."""
        plaintext = "XYZ"
        ciphertext = caesar_shift_text(plaintext, 3)
        assert ciphertext == "ABC"

    def test_negative_shift(self):
        """Caesar: Negative shift works correctly."""
        ciphertext = "BCD"
        plaintext = caesar_shift_text(ciphertext, -1)
        assert plaintext == "ABC"

    def test_large_shift_modulo(self):
        """Caesar: Large shift values use modulo 26."""
        text = "ABC"
        result = caesar_shift_text(text, 26)  # Same as shift 0
        assert result == "ABC"


class TestRailfenceCipher:
    """Tests for Railfence cipher operations."""

    # True Cases
    def test_decrypt_valid_3_rails(self):
        """Railfence: Decrypt valid ciphertext with 3 rails."""
        ciphertext = "Wtk neatc tdw aaa"
        plaintext = railfence_decrypt(ciphertext, 3)
        assert plaintext == "We attack at dawn"

    def test_decrypt_valid_2_rails(self):
        """Railfence: Decrypt valid ciphertext with 2 rails."""
        ciphertext = "TIDHSSIDNIHE"
        plaintext = railfence_decrypt(ciphertext, 3)
        assert plaintext == "THISISHIDDEN"

    # False Cases
    def test_single_rail_no_change(self):
        """Railfence: Single rail produces no change."""
        ciphertext = "ZOMBIES"
        result = railfence_decrypt(ciphertext, 1)
        assert result == ciphertext

    # Edge Cases
    def test_empty_string(self):
        """Railfence: Empty string returns empty."""
        result = railfence_decrypt("", 3)
        assert result == ""

    def test_rails_equal_length(self):
        """Railfence: Rails equal to text length."""
        ciphertext = "ABC"
        result = railfence_decrypt(ciphertext, 3)
        assert isinstance(result, str)


class TestColumnarTransposition:
    """Tests for Columnar Transposition cipher."""

    # True Cases
    def test_decrypt_valid_with_spaces(self):
        """Columnar: Decrypt valid ciphertext preserving spaces."""
        ciphertext = "ld ollerWHo"
        plaintext = columnar_decrypt(ciphertext, "ZOMBIES")
        assert plaintext == "Hello World"

    def test_decrypt_valid_no_spaces(self):
        """Columnar: Decrypt valid ciphertext without spaces."""
        ciphertext = "LWOLDELOHR"
        plaintext = columnar_decrypt(ciphertext, "ZOMBIES")
        assert plaintext == "HELLOWORLD"

    def test_decrypt_with_punctuation(self):
        """Columnar: Decrypt preserving punctuation."""
        ciphertext = "s . e,siath eicTsr"
        plaintext = columnar_decrypt(ciphertext, "ZOMBIES")
        assert plaintext == "This, is a secret."

    # False Cases
    def test_single_char_key_no_change(self):
        """Columnar: Single character key produces no change."""
        ciphertext = "CHECKTHISOUT"
        result = columnar_decrypt(ciphertext, "A")
        assert result == ciphertext

    # Edge Cases
    def test_empty_string(self):
        """Columnar: Empty string returns empty."""
        result = columnar_decrypt("", "KEY")
        assert result == ""

    def test_key_longer_than_text(self):
        """Columnar: Key longer than ciphertext."""
        ciphertext = "ABC"
        result = columnar_decrypt(ciphertext, "VERYLONGKEY")
        assert isinstance(result, str)


class TestDoubleColumnarTransposition:
    """Tests for Double Columnar Transposition cipher."""

    # True Cases
    def test_decrypt_valid_with_spaces(self):
        """Double Columnar: Decrypt valid ciphertext with spaces."""
        ciphertext = "lroHdwlle o"
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert plaintext == "Hello world"

    def test_decrypt_valid_no_spaces(self):
        """Double Columnar: Decrypt valid ciphertext without spaces."""
        ciphertext = "LEOOLLDRWH"
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert plaintext == "HELLOWORLD"

    def test_decrypt_with_punctuation(self):
        """Double Columnar: Decrypt preserving punctuation."""
        ciphertext = " shhoWwlo?aed usk "
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert plaintext == "Who should we ask?"

    # False Cases
    def test_same_key_twice(self):
        """Double Columnar: Using same key twice."""
        ciphertext = "oHldw olelr"
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ZOMBIE")
        assert plaintext == "Hello world"

    # Edge Cases
    def test_empty_string(self):
        """Double Columnar: Empty string returns empty."""
        result = double_columnar_decrypt("", "KEY1", "KEY2")
        assert result == ""


class TestBifidCipher:
    """Tests for Bifid cipher operations."""

    # True Cases
    def test_decrypt_valid_standard_alphabet(self):
        """Bifid: Decrypt valid ciphertext with standard alphabet."""
        key = "ZOMBIE"
        period = len("THE HYDRA HAS 99 HEADS!")
        ciphertext = "RCV QHRAD VOX 99 HAQOS!"
        plaintext = bifid_decrypt(ciphertext, key, period, STANDARD_ALPHABET)
        assert plaintext == "THE HYDRA HAS 99 HEADS!"

    def test_encrypt_decrypt_round_trip_standard(self):
        """Bifid: Encrypt and decrypt round trip (standard alphabet)."""
        plaintext = "ATTACK AT DAWN"
        key = "ZOMBIE"
        period = len(plaintext)

        encrypted = bifid_encrypt(plaintext, key, period, STANDARD_ALPHABET)
        decrypted = bifid_decrypt(encrypted, key, period, STANDARD_ALPHABET)
        assert decrypted == plaintext

    def test_encrypt_decrypt_round_trip_base64(self):
        """Bifid: Encrypt and decrypt round trip (base64 alphabet)."""
        plaintext = "HELLOWORLD1234"
        key = "TESTKEY"
        period = len(plaintext)

        encrypted = bifid_encrypt(plaintext, key, period, BASE64_ALPHABET)
        decrypted = bifid_decrypt(encrypted, key, period, BASE64_ALPHABET)
        assert decrypted == plaintext

    # False Cases
    def test_wrong_key_produces_gibberish(self):
        """Bifid: Wrong key produces incorrect output."""
        ciphertext = "RCV QHRAD VOX 99 HAQOS!"
        wrong_key = "WRONG"
        period = len(ciphertext)
        result = bifid_decrypt(ciphertext, wrong_key, period, STANDARD_ALPHABET)
        assert result != "THE HYDRA HAS 99 HEADS!"

    # Edge Cases
    def test_build_keyed_square_standard(self):
        """Bifid: Build keyed square with standard alphabet."""
        square = build_keyed_square(STANDARD_ALPHABET, "ZOMBIE")
        assert len(square) == 25
        assert square.startswith("ZOMBIE")
        assert square == "ZOMBIEACDFGHKLNPQRSTUVWXY"
        assert square.count("Z") == 1  # No duplicates

    def test_build_keyed_square_base64(self):
        """Bifid: Build keyed square with base64 alphabet."""
        square = build_keyed_square(BASE64_ALPHABET, "SECRET")
        assert len(square) == 64
        assert square.startswith("SECRT")  # No duplicate E
        assert square.count("S") == 1

    def test_i_j_substitution(self):
        """Bifid: Standard alphabet handles I/J correctly."""
        assert "J" not in STANDARD_ALPHABET
        assert "I" in STANDARD_ALPHABET
        assert len(STANDARD_ALPHABET) == 25


class TestXORCipher:
    """Tests for XOR cipher operations."""

    # True Cases
    def test_encrypt_decrypt_round_trip(self):
        """XOR: Encrypt and decrypt round trip."""
        plaintext = b"Hello, World!"
        key = b"KEY"

        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)
        assert decrypted == plaintext

    def test_single_byte_key(self):
        """XOR: Single byte key works correctly."""
        plaintext = b"ABCDEFGH"
        key = b"X"

        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)
        assert decrypted == plaintext

    def test_key_longer_than_plaintext(self):
        """XOR: Key longer than plaintext."""
        plaintext = b"HI"
        key = b"VERYLONGKEY"

        encrypted = repeating_xor(plaintext, key)
        decrypted = repeating_xor(encrypted, key)
        assert decrypted == plaintext

    # False Cases
    def test_wrong_key_produces_garbage(self):
        """XOR: Wrong key produces incorrect output."""
        plaintext = b"SECRET"
        key1 = b"KEY1"
        key2 = b"KEY2"

        encrypted = repeating_xor(plaintext, key1)
        wrong_decrypt = repeating_xor(encrypted, key2)
        assert wrong_decrypt != plaintext

    # Edge Cases
    def test_empty_key(self):
        """XOR: Empty key returns empty result."""
        plaintext = b"test"
        result = repeating_xor(plaintext, b"")
        assert result == b""

    def test_empty_plaintext(self):
        """XOR: Empty plaintext returns empty result."""
        result = repeating_xor(b"", b"KEY")
        assert result == b""

    def test_produces_printable_output(self):
        """XOR: Can produce printable ASCII output."""
        plaintext = b"Hello!!"
        key = b"\x00\x00\x00\x00\x00\x00\x00"  # Identity
        result = repeating_xor(plaintext, key)
        assert printable_ratio(result) == 1.0

    def test_produces_non_printable_output(self):
        """XOR: Can produce non-printable output."""
        plaintext = b"AAAA"
        key = b"A"  # 0x41 XOR 0x41 = 0x00
        result = repeating_xor(plaintext, key)
        assert printable_ratio(result) == 0.0


class TestBase64Encoding:
    """Tests for Base64 encoding/decoding."""

    # True Cases
    def test_decode_valid_with_padding(self):
        """Base64: Decode valid base64 with padding."""
        ciphertext = "SGVsbG8gd29ybGQ="
        decoded = base64.b64decode(ciphertext)
        assert decoded == b"Hello world"

    def test_decode_valid_without_padding(self):
        """Base64: Decode valid base64 without padding."""
        ciphertext = "U2VjcmV0"
        decoded = base64.b64decode(ciphertext)
        assert decoded == b"Secret"

    def test_encode_decode_round_trip(self):
        """Base64: Encode and decode round trip."""
        plaintext = b"Test message 123!"
        encoded = base64.b64encode(plaintext).decode()
        decoded = base64.b64decode(encoded)
        assert decoded == plaintext

    # False Cases
    def test_invalid_base64_raises_error(self):
        """Base64: Invalid base64 raises error with validate=True."""
        invalid = "SGVsbG8gd29ybGQ"  # Missing padding
        with pytest.raises(Exception):
            base64.b64decode(invalid, validate=False)

    # Edge Cases
    def test_empty_string(self):
        """Base64: Empty string decodes to empty bytes."""
        result = base64.b64decode("")
        assert result == b""

    def test_decode_to_printable(self):
        """Base64: Decode to fully printable ASCII."""
        plaintext = b"Hello World! 123"
        encoded = base64.b64encode(plaintext).decode()
        decoded = base64.b64decode(encoded)
        assert printable_ratio(decoded) == 1.0

    def test_decode_to_binary(self):
        """Base64: Decode to non-printable binary."""
        binary = bytes([0x00, 0x01, 0xFF, 0xFE])
        encoded = base64.b64encode(binary).decode()
        decoded = base64.b64decode(encoded)
        assert printable_ratio(decoded) < 1.0


class TestReverseCipher:
    """Tests for Reverse cipher operations."""

    # True Cases
    def test_reverse_basic(self):
        """Reverse: Reverse basic text."""
        text = "Hello World"
        result = reverse_text(text)
        assert result == "dlroW olleH"

    def test_reverse_with_punctuation(self):
        """Reverse: Reverse text with punctuation."""
        text = "Hello, World!"
        result = reverse_text(text)
        assert result == "!dlroW ,olleH"

    def test_reverse_round_trip(self):
        """Reverse: Reversing twice returns original."""
        original = "Test message 123"
        reversed_once = reverse_text(original)
        reversed_twice = reverse_text(reversed_once)
        assert reversed_twice == original

    # False Cases
    def test_palindrome_unchanged(self):
        """Reverse: Palindrome reverses to itself."""
        text = "racecar"
        result = reverse_text(text)
        assert result == text

    # Edge Cases
    def test_empty_string(self):
        """Reverse: Empty string returns empty."""
        result = reverse_text("")
        assert result == ""

    def test_single_character(self):
        """Reverse: Single character returns itself."""
        result = reverse_text("A")
        assert result == "A"


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================


class TestPrintableRatio:
    """Tests for printable_ratio utility function."""

    # True Cases
    def test_fully_printable_text(self):
        """Printable ratio: Fully printable text returns 1.0."""
        assert printable_ratio(b"Hello World!") == 1.0

    def test_printable_with_whitespace(self):
        """Printable ratio: Tabs and newlines count as printable."""
        assert printable_ratio(b"Hello\tWorld\n") == 1.0

    # False Cases
    def test_fully_non_printable(self):
        """Printable ratio: Fully non-printable returns 0.0."""
        assert printable_ratio(b"\x00\x01\x02") == 0.0

    # Edge Cases
    def test_empty_bytes(self):
        """Printable ratio: Empty bytes returns 0.0."""
        assert printable_ratio(b"") == 0.0

    def test_mixed_printable(self):
        """Printable ratio: Mixed content returns correct ratio."""
        mixed = b"AB\x00\x01"  # 2 printable, 2 non-printable
        assert printable_ratio(mixed) == 0.5


class TestCombinedScore:
    """Tests for combined_score (printable + English detection)."""

    @pytest.fixture
    def common_words(self):
        """Load common words for testing."""
        try:
            with open("common.txt") as f:
                return set(word.strip().upper() for word in f)
        except FileNotFoundError:
            return None

    # True Cases (Good English)
    def test_perfect_english_scores_high(self, common_words):
        """Combined score: Perfect English scores close to 2.0."""
        if common_words is None:
            pytest.skip("common.txt not found")

        perfect_text = b"THE MAN WAS HERE"
        score = combined_score(perfect_text, common_words)
        assert score > 1.8

    def test_good_english_scores_above_threshold(self, common_words):
        """Combined score: Good English scores > 1.7."""
        english_text = b"THE QUICK BROWN FOX"
        score = combined_score(english_text, common_words)
        assert score > 1.7

    def test_proper_spacing_improves_score(self, common_words):
        """Combined score: Proper spacing improves score."""
        with_spaces = b"HELLO WORLD"
        no_spaces = b"HELLOWORLD"

        score_spaces = combined_score(with_spaces, common_words)
        score_no_spaces = combined_score(no_spaces, common_words)

        assert score_spaces > score_no_spaces

    # False Cases (Non-English)
    def test_gibberish_scores_low(self, common_words):
        """Combined score: Gibberish scores lower than English."""
        english = b"THE QUICK BROWN FOX"
        gibberish = b"XQZ JKWPM BRVWN FGX"

        english_score = combined_score(english, common_words)
        gibberish_score = combined_score(gibberish, common_words)

        assert english_score > gibberish_score
        assert english_score - gibberish_score > 0.2

    def test_printable_no_english_scores_medium(self):
        """Combined score: Printable non-English scores 1.0-1.7."""
        gibberish = b"XQZJKW"
        score = combined_score(gibberish)
        assert 1.0 <= score < 1.7

    # Edge Cases
    def test_non_printable_scores_below_one(self):
        """Combined score: Non-printable bytes score < 1.0."""
        assert combined_score(b"\x00\x01\x02") == 0.0

        mixed = b"AB\x00\x01"
        assert combined_score(mixed) == 0.5

    def test_empty_bytes(self):
        """Combined score: Empty bytes returns 0.0."""
        assert combined_score(b"") == 0.0


class TestTypeDetection:
    """Tests for text vs bytes type detection in pipeline."""

    def test_base64_to_printable_text(self):
        """Type detection: Base64 decodes to printable text."""
        plaintext = b"Hello World"
        encoded = base64.b64encode(plaintext).decode()
        decoded = base64.b64decode(encoded)

        assert printable_ratio(decoded) == 1.0
        assert decoded.decode("ascii") == "Hello World"

    def test_base64_to_binary(self):
        """Type detection: Base64 decodes to binary."""
        binary = bytes([0x00, 0xFF, 0xFE])
        encoded = base64.b64encode(binary).decode()
        decoded = base64.b64decode(encoded)

        assert printable_ratio(decoded) < 1.0

    def test_xor_accepts_text_and_bytes(self):
        """Type detection: XOR accepts both text and bytes."""
        text_bytes = "Hello".encode("utf-8")
        byte_data = b"Hello"
        key = b"KEY"

        result1 = repeating_xor(text_bytes, key)
        result2 = repeating_xor(byte_data, key)

        assert isinstance(result1, bytes)
        assert isinstance(result2, bytes)

    def test_xor_output_printability(self):
        """Type detection: XOR output can be printable or not."""
        # Printable output
        plaintext1 = b"Hello World"
        key1 = b"\x00"
        result1 = repeating_xor(plaintext1, key1)
        assert printable_ratio(result1) == 1.0

        # Non-printable output
        plaintext2 = b"AAAA"
        key2 = b"A"
        result2 = repeating_xor(plaintext2, key2)
        assert printable_ratio(result2) == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
