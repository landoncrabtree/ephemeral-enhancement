from __future__ import annotations

from stages.affine import (
    VALID_A_26,
    VALID_A_62,
    VALID_A_95,
    N_AFFINE_TOTAL,
    affine_decrypt,
)
from stages.myszkowski import myszkowski_decrypt
from stages.redefense import redefense_decrypt


class TestAffineDecrypt:
    def test_basic_alpha(self):
        assert affine_decrypt("YRLEZN", 3, 1, charset_mode=0) == "ZOMBIE"

    def test_identity_alpha(self):
        assert affine_decrypt("HELLO", 1, 0, charset_mode=0) == "HELLO"

    def test_preserves_case(self):
        assert affine_decrypt("Yrlezn", 3, 1, charset_mode=0) == "Zombie"

    def test_preserves_nonalpha(self):
        assert affine_decrypt("YRL EZN!", 3, 1, charset_mode=0) == "ZOM BIE!"

    def test_all_valid_a_alpha(self):
        for a in VALID_A_26:
            result = affine_decrypt("HELLO", a, 0, charset_mode=0)
            assert len(result) == 5

    def test_alphanumeric_mode(self):
        """Encrypt then decrypt with alphanumeric charset."""
        # a=3 is coprime with 62
        plain = "Hello123"
        # Encrypt: E(x) = (3*x + 5) mod 62
        from stages.affine import _ALPHANUM, _ALPHANUM_IDX, _mod_inverse
        ct_chars = []
        for ch in plain:
            if ch in _ALPHANUM_IDX:
                x = _ALPHANUM_IDX[ch]
                y = (3 * x + 5) % 62
                ct_chars.append(_ALPHANUM[y])
            else:
                ct_chars.append(ch)
        ct = "".join(ct_chars)
        assert affine_decrypt(ct, 3, 5, charset_mode=1) == plain

    def test_all_printable_mode(self):
        """Encrypt then decrypt with all-printable charset."""
        from stages.affine import _ALL_PRINTABLE, _ALL_PRINTABLE_IDX, _mod_inverse
        plain = "Hello World!"
        # a=3 is coprime with 95
        ct_chars = []
        for ch in plain:
            if ch in _ALL_PRINTABLE_IDX:
                x = _ALL_PRINTABLE_IDX[ch]
                y = (3 * x + 7) % 95
                ct_chars.append(_ALL_PRINTABLE[y])
            else:
                ct_chars.append(ch)
        ct = "".join(ct_chars)
        assert affine_decrypt(ct, 3, 7, charset_mode=2) == plain

    def test_total_combos(self):
        """N_AFFINE_TOTAL should be sum of all mode combos."""
        assert N_AFFINE_TOTAL == (
            len(VALID_A_26) * 26 + len(VALID_A_62) * 62 + len(VALID_A_95) * 95
        )


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
        assert ranks == [3, 2, 1, 0, 3, 2]  # T,O,M,A,T,O share ranks

    def test_empty(self):
        assert myszkowski_decrypt("", "KEY") == ""

    def test_single_char_key(self):
        assert myszkowski_decrypt("HELLO", "A") == "HELLO"


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
        # Rail fence 2 rails on HELLOWORLD: HLOOL, ELWRD -> HLOOLELWRD
        assert redefense_decrypt("HLOOLELWRD", "AB") == "HELLOWORLD"
