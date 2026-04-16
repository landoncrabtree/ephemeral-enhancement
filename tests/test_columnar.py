from __future__ import annotations

from stages.columnar import columnar_decrypt
from stages.double_columnar import double_columnar_decrypt


class TestColumnarTransposition:
    """Tests for Columnar Transposition cipher."""

    def test_decrypt_valid_with_spaces(self):
        """Decrypt valid ciphertext preserving spaces."""
        ciphertext = "ld ollerWHo"
        plaintext = columnar_decrypt(ciphertext, "ZOMBIES")
        assert plaintext == "Hello World"

    def test_decrypt_valid_no_spaces(self):
        """Decrypt valid ciphertext without spaces."""
        ciphertext = "LWOLDELOHR"
        plaintext = columnar_decrypt(ciphertext, "ZOMBIES")
        assert plaintext == "HELLOWORLD"

    def test_decrypt_with_punctuation(self):
        """Decrypt preserving punctuation."""
        ciphertext = "s . e,siath eicTsr"
        plaintext = columnar_decrypt(ciphertext, "ZOMBIES")
        assert plaintext == "This, is a secret."

    def test_single_char_key_no_change(self):
        """Single character key produces no change."""
        ciphertext = "CHECKTHISOUT"
        result = columnar_decrypt(ciphertext, "A")
        assert result == ciphertext

    def test_empty_string(self):
        """Empty string returns empty."""
        result = columnar_decrypt("", "KEY")
        assert result == ""

    def test_key_longer_than_text(self):
        """Key longer than ciphertext."""
        ciphertext = "ABC"
        result = columnar_decrypt(ciphertext, "VERYLONGKEY")
        assert isinstance(result, str)


class TestDoubleColumnarTransposition:
    """Tests for Double Columnar Transposition cipher."""

    def test_decrypt_valid_with_spaces(self):
        """Decrypt valid ciphertext with spaces."""
        ciphertext = "lroHdwlle o"
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert plaintext == "Hello world"

    def test_decrypt_valid_no_spaces(self):
        """Decrypt valid ciphertext without spaces."""
        ciphertext = "LEOOLLDRWH"
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert plaintext == "HELLOWORLD"

    def test_decrypt_with_punctuation(self):
        """Decrypt preserving punctuation."""
        ciphertext = " shhoWwlo?aed usk "
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ATTACK")
        assert plaintext == "Who should we ask?"

    def test_same_key_twice(self):
        """Using same key twice."""
        ciphertext = "oHldw olelr"
        plaintext = double_columnar_decrypt(ciphertext, "ZOMBIE", "ZOMBIE")
        assert plaintext == "Hello world"

    def test_empty_string(self):
        """Empty string returns empty."""
        result = double_columnar_decrypt("", "KEY1", "KEY2")
        assert result == ""
