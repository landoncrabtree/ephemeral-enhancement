"""Tests for polyalphabetic cipher stages: Vigenere, Beaufort, Autokey."""

from __future__ import annotations

import pytest

from stages.polyalpha import (
    _ALPHA,
    _MOD,
    _ORD,
    autokey_decrypt,
    beaufort_decrypt,
    vigenere_decrypt,
)


# ---------------------------------------------------------------------------
# Alphabet basics
# ---------------------------------------------------------------------------

class TestAlphabet:
    def test_alphabet_length(self):
        assert _MOD == 52

    def test_alphabet_order(self):
        assert _ALPHA[:26] == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        assert _ALPHA[26:] == "abcdefghijklmnopqrstuvwxyz"

    def test_z_wraps_to_a(self):
        """Z (index 25) + 1 = a (index 26) in Vigenere."""
        # Encrypt: C = (P + K) mod 52
        # If P=Z(25), K=B(1): C = (25+1) % 52 = 26 = 'a'
        # Decrypt: P = (C - K) mod 52
        # C='a'(26), K='B'(1): P = (26-1) % 52 = 25 = 'Z'
        assert vigenere_decrypt("a", "B") == "Z"

    def test_a_wraps_to_z(self):
        """a (index 26) - 1 wraps to Z (index 25)."""
        # C='A'(0), K='B'(1): P = (0-1) % 52 = 51 = 'z'
        assert vigenere_decrypt("A", "B") == "z"


# ---------------------------------------------------------------------------
# Non-alpha passthrough
# ---------------------------------------------------------------------------

class TestPassthrough:
    def test_digits_unchanged(self):
        result = vigenere_decrypt("A1B2C3", "KEY")
        assert "1" in result and "2" in result and "3" in result

    def test_b64_symbols_unchanged(self):
        result = vigenere_decrypt("AB+CD/EF==", "KEY")
        assert "+" in result and "/" in result and "==" in result[-2:]

    def test_key_does_not_advance_on_nonalpha(self):
        """Non-alpha chars should not consume a key position."""
        # "A+B" with key "XY": A uses X, B uses Y (not: A uses X, + skipped, B uses X)
        r1 = vigenere_decrypt("A+B", "XY")
        # Manually: A(0) - X(23) = -23 % 52 = 29 = 'd'; B(1) - Y(24) = -23 % 52 = 29 = 'd'
        assert r1 == "d+d"

    def test_passthrough_beaufort(self):
        result = beaufort_decrypt("A1B2", "K")
        assert "1" in result and "2" in result

    def test_passthrough_autokey(self):
        result = autokey_decrypt("A1B2", "K")
        assert "1" in result and "2" in result


# ---------------------------------------------------------------------------
# Empty / invalid key
# ---------------------------------------------------------------------------

class TestEmptyKey:
    def test_vigenere_empty_key_returns_none(self):
        assert vigenere_decrypt("Hello", "") is None

    def test_beaufort_empty_key_returns_none(self):
        assert beaufort_decrypt("Hello", "") is None

    def test_autokey_empty_key_returns_none(self):
        assert autokey_decrypt("Hello", "") is None

    def test_numeric_only_key_returns_none(self):
        """Key with no alpha chars should return None."""
        assert vigenere_decrypt("Hello", "12345") is None

    def test_empty_ciphertext(self):
        assert vigenere_decrypt("", "KEY") == ""
        assert beaufort_decrypt("", "KEY") == ""
        assert autokey_decrypt("", "KEY") == ""


# ---------------------------------------------------------------------------
# Vigenere known vectors
# ---------------------------------------------------------------------------

class TestVigenere:
    def test_identity_key_a(self):
        """Key 'A' (index 0) = identity (no shift)."""
        assert vigenere_decrypt("Hello", "A") == "Hello"

    def test_single_shift(self):
        """Key 'B' shifts by 1."""
        # H(7)-B(1)=6=G, e(30)-B(1)=29=d, l(37)-B(1)=36=k, l(37)-B(1)=36=k, o(40)-B(1)=39=n
        assert vigenere_decrypt("Hello", "B") == "Gdkkn"

    def test_roundtrip(self):
        """Encrypt then decrypt returns original."""
        plain = "TheQuickBrownFox"
        key = "ZOMBIES"
        # Encrypt: C = (P + K) mod 52
        ki = [_ORD[ch] for ch in key]
        encrypted = []
        j = 0
        for ch in plain:
            if ch in _ORD:
                pi = _ORD[ch]
                ci = (pi + ki[j % len(ki)]) % _MOD
                encrypted.append(_ALPHA[ci])
                j += 1
            else:
                encrypted.append(ch)
        ct = "".join(encrypted)
        assert vigenere_decrypt(ct, key) == plain

    def test_key_repeats(self):
        """Key cycles when shorter than ciphertext."""
        # 7-char key over 10-char text: key repeats
        result = vigenere_decrypt("AAAAAAAAAA", "BCD")
        # A(0)-B(1)=-1%52=51='z', A(0)-C(2)=-2%52=50='y', A(0)-D(3)=-3%52=49='x'
        # Then repeats: z, y, x, z, y, x, z, y, x, z
        assert result == "zyxzyxzyxz"


# ---------------------------------------------------------------------------
# Beaufort known vectors
# ---------------------------------------------------------------------------

class TestBeaufort:
    def test_self_reciprocal(self):
        """Beaufort encrypt == decrypt (self-reciprocal)."""
        text = "HelloWorld"
        key = "ZOMBIES"
        encrypted = beaufort_decrypt(text, key)
        assert encrypted is not None
        decrypted = beaufort_decrypt(encrypted, key)
        assert decrypted == text

    def test_beaufort_vs_vigenere(self):
        """Beaufort P=(K-C) is different from Vigenere P=(C-K)."""
        ct = "Hello"
        key = "KEY"
        v = vigenere_decrypt(ct, key)
        b = beaufort_decrypt(ct, key)
        assert v != b  # They should differ

    def test_identity_impossible(self):
        """Unlike Vigenere, key 'A' is NOT identity for Beaufort."""
        # Beaufort: P = (K - C) = (0 - C) = -C mod 52
        # Only identity if C=0 for all chars
        result = beaufort_decrypt("Hello", "A")
        assert result != "Hello"


# ---------------------------------------------------------------------------
# Autokey known vectors
# ---------------------------------------------------------------------------

class TestAutokey:
    def test_short_message_same_as_vigenere(self):
        """If message <= key length, autokey == vigenere."""
        ct = "ABC"
        key = "XYZWV"  # longer than ct
        assert autokey_decrypt(ct, key) == vigenere_decrypt(ct, key)

    def test_key_extends_with_plaintext(self):
        """After key exhausts, plaintext chars extend it."""
        # Manual: key="AB", ct="CCCC"
        # pos 0: C(2) - A(0) = 2 = 'C', ext_key=[A,B,C]
        # pos 1: C(2) - B(1) = 1 = 'B', ext_key=[A,B,C,B]
        # pos 2: C(2) - C(2) = 0 = 'A', ext_key=[A,B,C,B,A]
        # pos 3: C(2) - B(1) = 1 = 'B'
        assert autokey_decrypt("CCCC", "AB") == "CBAB"

    def test_autokey_nonalpha_skipped_in_extension(self):
        """Non-alpha passthrough chars don't extend the key."""
        # key="A", ct="B+C"
        # pos 0: B(1) - A(0) = 1 = 'B', ext=[A,B]
        # '+' passes through, key not advanced
        # pos 1: C(2) - B(1) = 1 = 'B'
        assert autokey_decrypt("B+C", "A") == "B+B"

    def test_roundtrip(self):
        """Encrypt with autokey then decrypt returns original."""
        plain = "AttackAtDawn"
        key = "ZOMBIES"
        # Encrypt autokey: C = (P + K_extended) mod 52
        ki = [_ORD[ch] for ch in key]
        ext = list(ki)
        encrypted = []
        j = 0
        for ch in plain:
            if ch in _ORD:
                pi = _ORD[ch]
                ci = (pi + ext[j]) % _MOD
                encrypted.append(_ALPHA[ci])
                ext.append(pi)
                j += 1
            else:
                encrypted.append(ch)
        ct = "".join(encrypted)
        assert autokey_decrypt(ct, key) == plain


# ---------------------------------------------------------------------------
# Integration: works as pre-b64 stage
# ---------------------------------------------------------------------------

class TestPreB64:
    def test_preserves_b64_structure(self):
        """Only alpha chars change; digits, +, /, = are preserved."""
        b64_ct = "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"
        result = vigenere_decrypt(b64_ct, "ZOMBIES")
        assert result is not None
        # All non-alpha chars from original should be in result at same positions
        for i, ch in enumerate(b64_ct):
            if not ch.isalpha():
                assert result[i] == ch

    def test_length_preserved(self):
        """Output length always equals input length."""
        ct = "SomeBase64String+/=="
        for fn in (vigenere_decrypt, beaufort_decrypt, autokey_decrypt):
            result = fn(ct, "KEY")
            assert result is not None
            assert len(result) == len(ct)
