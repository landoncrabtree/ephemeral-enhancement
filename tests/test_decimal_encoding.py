"""Tests for the decimal character-code decoding stage."""

from __future__ import annotations

from stages.decimal_encoding import decimal_decode


class TestDecimalDecode:
    """Tests for decimal_decode()."""

    def test_zero_padded_triplets(self):
        assert decimal_decode("072 101 108 108 111") == b"Hello"

    def test_unpadded_codes(self):
        assert decimal_decode("72 101 108 108 111") == b"Hello"

    def test_fixed_width_no_delimiters(self):
        assert decimal_decode("072101108108111") == b"Hello"

    def test_comma_and_semicolon_delimiters(self):
        assert decimal_decode("072,101;108,108;111") == b"Hello"

    def test_surrounding_whitespace_ignored(self):
        assert decimal_decode("  072 101\r\n") == b"He"

    def test_newline_delimited(self):
        assert decimal_decode("072\n101\n108") == b"Hel"

    def test_full_byte_range(self):
        assert decimal_decode("000 255") == b"\x00\xff"

    def test_single_code(self):
        assert decimal_decode("065") == b"A"

    def test_value_above_byte_range_rejected(self):
        assert decimal_decode("072 256") is None

    def test_non_numeric_rejected(self):
        assert decimal_decode("072 abc") is None

    def test_negative_rejected(self):
        assert decimal_decode("072 -5") is None

    def test_empty_string_rejected(self):
        assert decimal_decode("") is None

    def test_whitespace_only_rejected(self):
        assert decimal_decode("   ") is None

    def test_fixed_width_bad_length_rejected(self):
        # 8 digits is not divisible by 3
        assert decimal_decode("07210110") is None

    def test_bytes_input_rejected(self):
        assert decimal_decode(b"072 101") is None

    def test_roundtrip(self):
        original = b"The many worlds are now one."
        encoded = " ".join(f"{b:03d}" for b in original)
        assert decimal_decode(encoded) == original
