from __future__ import annotations

from stages.columnar import (
    CHARSET_ALL,
    CHARSET_LETTERS_ONLY,
    columnar_decrypt,
)
from stages.double_columnar import double_columnar_decrypt


class TestColumnarTransposition:
    """Tests for Columnar Transposition cipher."""

    # --- Rumkin/CryptTool verified vectors ---

    def test_rumkin_all_mode(self):
        """Rumkin: 'Move spaces, punctuation, and capitalization'."""
        ct = "s naiime h giaesh dsTsde."
        assert (
            columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "This is a hidden message."
        )

    def test_rumkin_letters_only(self):
        """Rumkin: 'Move only letters' (case-insensitive)."""
        ct = "sdss ea i dsiieh hmeTang."
        result = columnar_decrypt(ct, "ZOMBIE", CHARSET_LETTERS_ONLY)
        assert result.lower() == "this is a hidden message."

    def test_crypttool_all_with_spaces(self):
        """CryptTool vector: all-mode, spaces preserved."""
        ct = "S POIRS TONIASIH NTTSAI"
        assert columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "THIS IS A TRANSPOSITION"

    def test_crypttool_all_no_spaces(self):
        """CryptTool vector: all-mode, no spaces."""
        ct = "SAISSIINTIRSHTONTAPO"
        assert columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "THISISATRANSPOSITION"

    def test_crypttool_all_with_digits(self):
        """CryptTool vector: all-mode with digits (spaces stripped by CryptTool)."""
        ct = "rsbootpmy9ea9ld"
        assert columnar_decrypt(ct, "ZOMBIE", CHARSET_ALL) == "99problemstoday"

    # --- Charset mode behavior ---

    def test_letters_only_preserves_digits(self):
        """Letters-only mode: digits stay in place."""
        ct = "rsbootpmy9ea9ld"
        result = columnar_decrypt(ct, "ZOMBIE", CHARSET_LETTERS_ONLY)
        assert result[9] == "9"
        assert result[12] == "9"
        assert [c for c in result if c.isdigit()] == ["9", "9"]

    def test_letters_only_preserves_punctuation(self):
        """Letters-only mode: punctuation stays in place."""
        ct = "s . e,siath eicTsr"
        result = columnar_decrypt(ct, "ZOMBIE", CHARSET_LETTERS_ONLY)
        assert result[2] == "."
        assert result[5] == ","

    def test_no_letters_unchanged(self):
        """If no letters in text, letters-only mode returns unchanged."""
        ct = "123 456!"
        assert columnar_decrypt(ct, "KEY", CHARSET_LETTERS_ONLY) == ct

    # --- Edge cases ---

    def test_single_char_key_no_change(self):
        ct = "CHECKTHISOUT"
        assert columnar_decrypt(ct, "A") == ct

    def test_empty_string(self):
        assert columnar_decrypt("", "KEY") == ""

    def test_key_longer_than_text(self):
        result = columnar_decrypt("ABC", "VERYLONGKEY")
        assert isinstance(result, str)

    def test_default_charset_is_all(self):
        ct = "SAISSIINTIRSHTONTAPO"
        assert columnar_decrypt(ct, "ZOMBIE") == "THISISATRANSPOSITION"


class TestDoubleColumnarTransposition:
    """Tests for Double Columnar Transposition cipher."""

    def test_rumkin_letters_only(self):
        """Rumkin vector: letters-only mode (case-insensitive)."""
        ct = "Sdha sa i ediets shneimg!"
        result = double_columnar_decrypt(ct, "ZOMBIE", "GIANT", CHARSET_LETTERS_ONLY)
        assert result.lower() == "this is a hidden message!"

    def test_crypttool_letters_only_same_key(self):
        """CryptTool vector: letters-only, same key twice (case-insensitive)."""
        ct = "Siea ea e etssmc rsgsiht"
        result = double_columnar_decrypt(ct, "ZOMBIE", "ZOMBIE", CHARSET_LETTERS_ONLY)
        assert result.lower() == "this is a secret message"

    def test_crypttool_letters_only_digits(self):
        """CryptTool vector: letters-only, digits preserved (case-insensitive)."""
        ct = "Eh sotw 99 eovosrlb le mavep!"
        result = double_columnar_decrypt(ct, "ZOMBIE", "ZOMBIE", CHARSET_LETTERS_ONLY)
        assert result.lower() == "we have 99 problems to solve!"

    def test_all_no_spaces(self):
        ct = "LEOOLLDRWH"
        assert (
            double_columnar_decrypt(ct, "ZOMBIE", "ATTACK", CHARSET_ALL) == "HELLOWORLD"
        )

    def test_same_key_all_mode(self):
        ct = "oHldw olelr"
        assert (
            double_columnar_decrypt(ct, "ZOMBIE", "ZOMBIE", CHARSET_ALL)
            == "Hello world"
        )

    def test_empty_string(self):
        assert double_columnar_decrypt("", "KEY1", "KEY2") == ""

    def test_default_charset_is_all(self):
        ct = "LEOOLLDRWH"
        assert double_columnar_decrypt(ct, "ZOMBIE", "ATTACK") == "HELLOWORLD"
