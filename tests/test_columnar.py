from __future__ import annotations

from stages.columnar import (
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    columnar_decrypt,
)
from stages.double_columnar import double_columnar_decrypt


class TestColumnarTransposition:
    """Tests for Columnar Transposition cipher."""

    def test_decrypt_all_with_spaces(self):
        """CryptTool vector: all-mode, spaces preserved."""
        ct = "S POIRS TONIASIH NTTSAI"
        assert columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "THIS IS A TRANSPOSITION"

    def test_decrypt_all_no_spaces(self):
        """CryptTool vector: all-mode, no spaces."""
        ct = "SAISSIINTIRSHTONTAPO"
        assert columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "THISISATRANSPOSITION"

    def test_decrypt_all_with_digits(self):
        """CryptTool vector: all-mode with digits (spaces stripped by CryptTool)."""
        ct = "rsbootpmy9ea9ld"
        assert columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "99problemstoday"

    def test_decrypt_alpha_preserves_digits(self):
        """Alpha mode: digits stay in place, only letters are transposed."""
        ct = "rsbootpmy9ea9ld"
        result = columnar_decrypt(ct, "ZOMBIE", CHARSET_ALPHA)
        # Digits at positions 9 and 12 must remain '9'
        assert result[9] == "9"
        assert result[12] == "9"
        # All original digits preserved
        assert [c for c in result if c.isdigit()] == ["9", "9"]

    def test_decrypt_alpha_preserves_punctuation(self):
        """Alpha mode: punctuation stays in place."""
        ct = "s . e,siath eicTsr"
        result = columnar_decrypt(ct, "ZOMBIE", CHARSET_ALPHA)
        # Spaces at 1,3,11 and . at 2, comma at 5 must stay
        assert result[2] == "."
        assert result[5] == ","

    def test_decrypt_alphanumeric_preserves_punct(self):
        """Alphanumeric mode: digits move, punctuation stays."""
        ct = "s . e,siath eicTsr"
        result = columnar_decrypt(ct, "ZOMBIE", CHARSET_ALPHANUMERIC)
        # Spaces and . and , stay in place
        assert result[2] == "."
        assert result[5] == ","

    def test_no_matching_chars_unchanged(self):
        """If no characters match the charset, text is unchanged."""
        ct = "123 456!"
        assert columnar_decrypt(ct, "KEY", CHARSET_ALPHA) == ct

    def test_single_char_key_no_change(self):
        """Single character key produces no change."""
        ct = "CHECKTHISOUT"
        assert columnar_decrypt(ct, "A") == ct

    def test_empty_string(self):
        """Empty string returns empty."""
        assert columnar_decrypt("", "KEY") == ""

    def test_key_longer_than_text(self):
        """Key longer than ciphertext."""
        result = columnar_decrypt("ABC", "VERYLONGKEY")
        assert isinstance(result, str)

    def test_default_charset_is_all(self):
        """Default charset_mode is CHARSET_ALL (backward compatible)."""
        ct = "SAISSIINTIRSHTONTAPO"
        assert columnar_decrypt(ct, "ZOMBIE") == "THISISATRANSPOSITION"


class TestDoubleColumnarTransposition:
    """Tests for Double Columnar Transposition cipher."""

    def test_decrypt_alpha_with_spaces(self):
        """CryptTool vector: alpha-mode, spaces preserved (case-insensitive)."""
        ct = "Siea ea e etssmc rsgsiht"
        result = double_columnar_decrypt(ct, "ZOMBIE", "ZOMBIE", CHARSET_ALPHA)
        assert result.lower() == "this is a secret message"

    def test_decrypt_alpha_with_digits(self):
        """CryptTool vector: alpha-mode, digits + punct preserved (case-insensitive)."""
        ct = "Eh sotw 99 eovosrlb le mavep!"
        result = double_columnar_decrypt(ct, "ZOMBIE", "ZOMBIE", CHARSET_ALPHA)
        assert result.lower() == "we have 99 problems to solve!"

    def test_decrypt_all_no_spaces(self):
        """All-mode double columnar, no spaces."""
        ct = "LEOOLLDRWH"
        result = double_columnar_decrypt(ct, "ZOMBIE", "ATTACK", CHARSET_ALL)
        assert result == "HELLOWORLD"

    def test_same_key_twice(self):
        """Using same key twice in all-mode."""
        ct = "oHldw olelr"
        result = double_columnar_decrypt(ct, "ZOMBIE", "ZOMBIE", CHARSET_ALL)
        assert result == "Hello world"

    def test_empty_string(self):
        """Empty string returns empty."""
        assert double_columnar_decrypt("", "KEY1", "KEY2") == ""

    def test_default_charset_is_all(self):
        """Default charset_mode is CHARSET_ALL (backward compatible)."""
        ct = "LEOOLLDRWH"
        assert double_columnar_decrypt(ct, "ZOMBIE", "ATTACK") == "HELLOWORLD"
