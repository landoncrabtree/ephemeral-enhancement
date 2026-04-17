from __future__ import annotations

from stages.myszkowski import myszkowski_decrypt


class TestMyszkowskiDecrypt:
    def test_basic_with_spaces(self):
        assert myszkowski_decrypt("LL ODLREOHW", "ZOMBIE") == "HELLO WORLD"

    def test_no_duplicates_in_key(self):
        """When key has no duplicate letters, behaves like standard columnar."""
        result = myszkowski_decrypt("LL ODLREOHW", "ZOMBIE")
        assert result == "HELLO WORLD"

    def test_with_duplicates(self):
        """Key TOMATO has duplicates T and O."""
        from stages.myszkowski import _myszkowski_key_order
        ranks = _myszkowski_key_order("TOMATO")
        assert ranks == [3, 2, 1, 0, 3, 2]

    def test_empty(self):
        assert myszkowski_decrypt("", "KEY") == ""

    def test_single_char_key(self):
        assert myszkowski_decrypt("HELLO", "A") == "HELLO"
