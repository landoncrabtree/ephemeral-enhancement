from __future__ import annotations

from stages.railfence import (
    CHARSET_ALL,
    CHARSET_LETTERS_ONLY,
    railfence_decrypt,
    redefense_decrypt,
)


class TestRailfenceCipher:
    """Tests for Railfence cipher operations."""

    # -- ALL mode (transpose everything including spaces/punct) --

    def test_decrypt_all_3_rails(self):
        """CryptTool: all mode, depth 3."""
        assert railfence_decrypt("Wtk neatc tdw aaa", 3) == "We attack at dawn"

    def test_decrypt_all_3_rails_hidden(self):
        assert railfence_decrypt("TIDHSSIDNIHE", 3) == "THISISHIDDEN"

    def test_decrypt_all_5_rails(self):
        """CryptTool: all mode, depth 5, offset 0."""
        ct = "Io m,nteo a   rfegwsaa hi!awtc"
        assert railfence_decrypt(ct, 5, charset_mode=CHARSET_ALL) == "I, was not aware of the magic!"

    # -- LETTERS_ONLY mode (preserve spaces/punct in place) --

    def test_decrypt_letters_only_3_rails(self):
        """CryptTool: letters-only, depth 3, offset 0."""
        ct = "Tiin sh s shdems aeiadeg"
        assert railfence_decrypt(ct, 3, charset_mode=CHARSET_LETTERS_ONLY) == "This is a hidden message"

    def test_decrypt_letters_only_3_rails_punct(self):
        """CryptTool: letters-only, depth 3, offset 0, with punctuation."""
        ct = "Vsen ceyert, idfo lr ckoo!"
        assert railfence_decrypt(ct, 3, charset_mode=CHARSET_LETTERS_ONLY) == "Very secret, kind of cool!"

    # -- Edge cases --

    def test_single_rail_no_change(self):
        assert railfence_decrypt("ZOMBIES", 1) == "ZOMBIES"

    def test_empty_string(self):
        assert railfence_decrypt("", 3) == ""

    def test_rails_equal_length(self):
        result = railfence_decrypt("ABC", 3)
        assert isinstance(result, str)

    def test_default_charset_is_all(self):
        """Default charset_mode should be CHARSET_ALL."""
        # "Wtk neatc tdw aaa" decrypts correctly without explicit mode
        assert railfence_decrypt("Wtk neatc tdw aaa", 3) == "We attack at dawn"


class TestRedefenseDecrypt:
    """Tests for Redefence (keyed rail fence) cipher."""

    # -- Keyword-based (existing behavior) --

    def test_keyword_secretkey(self):
        assert redefense_decrypt("IEGHSAINHDADSMETSSEI", "SECRETKEY") == "THISISAHIDDENMESSAGE"

    def test_keyword_simple(self):
        assert redefense_decrypt("ELWRDHOLLO", "KEY") == "HELLOWORLD"

    def test_keyword_single_char(self):
        assert redefense_decrypt("HELLO", "A") == "HELLO"

    def test_keyword_empty(self):
        assert redefense_decrypt("", "KEY") == ""

    def test_keyword_two_char(self):
        """Two-char key = standard rail fence with 2 rails."""
        assert redefense_decrypt("HLOOLELWRD", "AB") == "HELLOWORLD"

    # -- Numeric order (CryptTool style) --

    def test_numeric_order_321_letters_only(self):
        """CryptTool: depth 3, order [3,2,1], letters-only mode."""
        ct = "eco omvhz ghqik rwf xupoe teay oTu bnjs rld."
        pt = "The quick brown fox jumps over the lazy dog."
        assert redefense_decrypt(ct, [3, 2, 1], charset_mode=CHARSET_LETTERS_ONLY) == pt

    def test_numeric_order_identity(self):
        """Order [1,2,3] should behave like standard railfence with 3 rails."""
        ct = "TIDHSSIDNIHE"
        assert redefense_decrypt(ct, [1, 2, 3]) == railfence_decrypt(ct, 3)

    def test_numeric_order_single(self):
        assert redefense_decrypt("HELLO", [1]) == "HELLO"

    def test_numeric_order_empty_cipher(self):
        assert redefense_decrypt("", [3, 2, 1]) == ""

    def test_numeric_order_54312_all(self):
        """CryptTool: depth 5, order [5,4,3,1,2], all mode."""
        ct = "m ca eo o urfesIst!,nu ht"
        pt = "I, am unsure of the cost!"
        assert redefense_decrypt(ct, [5, 4, 3, 1, 2], charset_mode=CHARSET_ALL) == pt
