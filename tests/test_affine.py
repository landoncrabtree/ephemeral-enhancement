from __future__ import annotations

from stages.affine import (
    VALID_A_26,
    VALID_A_62,
    VALID_A_95,
    N_AFFINE_TOTAL,
    affine_decrypt,
)

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
        plain = "Hello123"
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
