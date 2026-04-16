"""Tests for polyalphabetic cipher stages: Vigenere, Beaufort, Autokey, Porta, Trithemius."""

from __future__ import annotations

import pytest

from stages.polyalpha import (
    autokey_decrypt,
    beaufort_decrypt,
    porta_decrypt,
    trithemius_decrypt,
    vigenere_decrypt,
)


PLAIN = "The quick brown fox jumps over the lazy dog."
KEY = "Zombie"


# ---------------------------------------------------------------------------
# 26-char known test vectors (Cryptool-online standard behaviour)
# ---------------------------------------------------------------------------

class TestVigenere26:
    CT = "Svq rcmby nswam tay rylde pdiq htf teym ppo."

    def test_known_vector(self):
        assert vigenere_decrypt(self.CT, KEY) == PLAIN

    def test_identity_key_a(self):
        assert vigenere_decrypt("Hello", "A") == "Hello"

    def test_roundtrip(self):
        """Encrypt then decrypt returns original (26-char)."""
        # Encrypt: C = (P + K) mod 26
        kv = [ord(ch.upper()) - 65 for ch in KEY if ch.isalpha()]
        encrypted = []
        j = 0
        for ch in PLAIN:
            if ch.isalpha():
                base = 65 if ch.isupper() else 97
                cv = (ord(ch.upper()) - 65 + kv[j % len(kv)]) % 26
                encrypted.append(chr(base + cv))
                j += 1
            else:
                encrypted.append(ch)
        ct = "".join(encrypted)
        assert vigenere_decrypt(ct, KEY) == PLAIN


class TestBeaufort26:
    CT = "Ghi lowxe lkuim jye zknzu nnai vfx xeaq jnc."

    def test_known_vector(self):
        assert beaufort_decrypt(self.CT, KEY) == PLAIN

    def test_self_reciprocal(self):
        encrypted = beaufort_decrypt(PLAIN, KEY)
        assert encrypted is not None
        assert beaufort_decrypt(encrypted, KEY) == PLAIN


class TestAutokey26:
    CT = "Svq rcmvr fhiep ppo xqzug leyd izs geqr ksr."

    def test_known_vector(self):
        assert autokey_decrypt(self.CT, KEY) == PLAIN

    def test_short_msg_matches_vigenere(self):
        ct = "ABC"
        key = "XYZWV"
        assert autokey_decrypt(ct, key) == vigenere_decrypt(ct, key)


class TestPorta26:
    CT = "Fny dltqq veflm yhk sjnjl bmpd aor uylf xbp."

    def test_known_vector(self):
        assert porta_decrypt(self.CT, KEY) == PLAIN

    def test_self_reciprocal(self):
        encrypted = porta_decrypt(PLAIN, KEY)
        assert encrypted is not None
        assert porta_decrypt(encrypted, KEY) == PLAIN


class TestTrithemius26:
    CT = "Tig tynir jayhz scm zleim jrbp shf nddd jvo."

    def test_known_vector(self):
        assert trithemius_decrypt(self.CT) == PLAIN

    def test_no_shift_first_char(self):
        """First character has shift 0 — unchanged."""
        result = trithemius_decrypt("H")
        assert result == "H"


# ---------------------------------------------------------------------------
# 52-char known test vectors
# ---------------------------------------------------------------------------

class TestBeaufort52:
    CT = "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"
    EX = "LeIXjxfrjSpfgR1RnFDIZr0t2JDCRjgueCZqdIiZwvNXC0/yTS76kfRMb/sTi7p3"

    def test_known_vector(self):
        assert beaufort_decrypt(self.CT, "ZOMBIES", alpha52=True) == self.EX

    def test_self_reciprocal_52(self):
        encrypted = beaufort_decrypt("TestString", "KEY", alpha52=True)
        assert encrypted is not None
        assert beaufort_decrypt(encrypted, "KEY", alpha52=True) == "TestString"

    def test_z_wraps_to_a(self):
        """Z (index 25) wraps to a (index 26) in 52-char."""
        # Beaufort P = (K - C) mod 52; K='B'(1), C='a'(26): (1-26)%52 = 27 = 'b'
        assert beaufort_decrypt("a", "B", alpha52=True) == "b"


class TestVigenere52:
    def test_z_wraps_to_a(self):
        """52-char: Z + 1 = a."""
        # C='a'(26), K='B'(1): P = (26-1)%52 = 25 = 'Z'
        assert vigenere_decrypt("a", "B", alpha52=True) == "Z"

    def test_a_wraps_to_z(self):
        # C='A'(0), K='B'(1): P = (0-1)%52 = 51 = 'z'
        assert vigenere_decrypt("A", "B", alpha52=True) == "z"

    def test_case_changes(self):
        """52-char mode can change case (unlike 26-char)."""
        r26 = vigenere_decrypt("Z", "B")  # 26-char preserves case
        r52 = vigenere_decrypt("Z", "B", alpha52=True)  # 52-char may change
        assert r26 is not None and r26.isupper()  # Preserved upper
        assert r52 is not None  # May be different case


class TestPorta52:
    def test_self_reciprocal_52(self):
        encrypted = porta_decrypt("TestInput", "KEY", alpha52=True)
        assert encrypted is not None
        assert porta_decrypt(encrypted, "KEY", alpha52=True) == "TestInput"


# ---------------------------------------------------------------------------
# Non-alpha passthrough
# ---------------------------------------------------------------------------

class TestPassthrough:
    def test_digits_unchanged(self):
        result = vigenere_decrypt("A1B2C3", "KEY")
        assert "1" in result and "2" in result and "3" in result

    def test_b64_symbols_unchanged(self):
        result = beaufort_decrypt("AB+CD/EF==", "KEY")
        assert "+" in result and "/" in result and "==" in result[-2:]

    def test_key_does_not_advance_on_nonalpha(self):
        """Non-alpha chars should not consume a key position."""
        r1 = vigenere_decrypt("A+B", "XY")
        r2 = vigenere_decrypt("AB", "XY")
        # A uses key X, B uses key Y in both cases
        assert r1[0] == r2[0] and r1[2] == r2[1]

    def test_b64_structure_preserved(self):
        """Only alpha chars change; digits, +, /, = stay at same positions."""
        b64 = "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"
        for fn in (vigenere_decrypt, beaufort_decrypt, autokey_decrypt, porta_decrypt):
            result = fn(b64, "KEY")
            assert result is not None
            for i, ch in enumerate(b64):
                if not ch.isalpha():
                    assert result[i] == ch

    def test_length_preserved(self):
        ct = "SomeBase64String+/=="
        for fn in (vigenere_decrypt, beaufort_decrypt, autokey_decrypt, porta_decrypt):
            result = fn(ct, "KEY")
            assert result is not None
            assert len(result) == len(ct)
        assert len(trithemius_decrypt(ct)) == len(ct)


# ---------------------------------------------------------------------------
# Empty / invalid key
# ---------------------------------------------------------------------------

class TestEmptyKey:
    def test_vigenere_empty(self):
        assert vigenere_decrypt("Hello", "") is None

    def test_beaufort_empty(self):
        assert beaufort_decrypt("Hello", "") is None

    def test_autokey_empty(self):
        assert autokey_decrypt("Hello", "") is None

    def test_porta_empty(self):
        assert porta_decrypt("Hello", "") is None

    def test_numeric_only_key(self):
        assert vigenere_decrypt("Hello", "12345") is None

    def test_empty_ciphertext(self):
        assert vigenere_decrypt("", "KEY") == ""
        assert beaufort_decrypt("", "KEY") == ""
        assert autokey_decrypt("", "KEY") == ""
        assert porta_decrypt("", "KEY") == ""
        assert trithemius_decrypt("") == ""
