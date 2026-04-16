from __future__ import annotations

from stages.affine import VALID_A, affine_decrypt
from stages.myszkowski import myszkowski_decrypt
from stages.redefense import redefense_decrypt


class TestAffineDecrypt:
    def test_basic(self):
        assert affine_decrypt("YRLEZN", 3, 1) == "ZOMBIE"

    def test_identity(self):
        """a=1, b=0 is the identity."""
        assert affine_decrypt("HELLO", 1, 0) == "HELLO"

    def test_preserves_case(self):
        assert affine_decrypt("Yrlezn", 3, 1) == "Zombie"

    def test_preserves_nonalpha(self):
        assert affine_decrypt("YRL EZN!", 3, 1) == "ZOM BIE!"

    def test_all_valid_a_roundtrip(self):
        """Every valid 'a' should produce a valid decryption."""
        for a in VALID_A:
            result = affine_decrypt("HELLO", a, 0)
            assert len(result) == 5
            assert result.isalpha()


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
