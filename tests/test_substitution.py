"""Tests for the Atbash and keyword substitution stages."""

from __future__ import annotations

import base64

import pytest

from core.pipeline import axes_for_pipeline
from stages.substitution import (
    ALPHABET_26,
    ALPHABET_52,
    ALPHABET_ALNUM62,
    ALPHABET_B64,
    N_POLYALPHA_ALPHABETS,
    atbash_decrypt,
    build_keyed_alphabet,
    keyword_decrypt,
)

B64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
N_KEYS = 4


class TestAtbash:
    def test_known_vector_26(self):
        # A<->Z, B<->Y, ... so ZOMBIE maps to ALNYRV.
        assert atbash_decrypt("ZOMBIE") == "ALNYRV"

    def test_self_reciprocal_26(self):
        assert atbash_decrypt(atbash_decrypt("HelloWorld")) == "HelloWorld"

    def test_preserves_case_in_26_mode(self):
        assert atbash_decrypt("aZ") == "zA"

    def test_non_alpha_passes_through_in_26_mode(self):
        assert atbash_decrypt("AB-12+/") == "ZY-12+/"

    @pytest.mark.parametrize(
        "alphabet", [ALPHABET_26, ALPHABET_52, ALPHABET_B64, ALPHABET_ALNUM62]
    )
    def test_self_reciprocal_all_alphabets(self, alphabet):
        text = "kCmlgFi6GUJNgkNI1Q41+/"
        once = atbash_decrypt(text, alphabet=alphabet)
        assert atbash_decrypt(once, alphabet=alphabet) == text

    def test_b64_alphabet_maps_endpoints(self):
        # First symbol maps to last and vice versa.
        assert atbash_decrypt("A", alphabet=ALPHABET_B64) == "/"
        assert atbash_decrypt("/", alphabet=ALPHABET_B64) == "A"

    def test_empty(self):
        assert atbash_decrypt("") == ""


class TestKeywordAlphabet:
    def test_key_leads_then_remainder(self):
        # 'T' is not in the alphabet and is dropped; 'G' leads the remainder.
        assert build_keyed_alphabet("TG", "ABCDEFG") == "GABCDEF"

    def test_duplicates_dropped(self):
        assert build_keyed_alphabet("ZOMBIE", "ABCDEFGHIJKLMNOPQRSTUVWXYZ").startswith("ZOMBIE")

    def test_repeated_key_letters_used_once(self):
        keyed = build_keyed_alphabet("TheGiant", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert keyed == "TGABCDEFHIJKLMNOPQRSUVWXYZ"
        assert len(keyed) == 26
        assert len(set(keyed)) == 26

    def test_is_permutation_of_alphabet(self):
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        keyed = build_keyed_alphabet("TheGiant", alpha)
        assert sorted(keyed) == sorted(alpha)


class TestKeywordCipher:
    def test_roundtrip_26(self):
        plain = "ATTACKATDAWN"
        keyed = build_keyed_alphabet("ZOMBIE", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        table = {p: k for p, k in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", keyed)}
        cipher = "".join(table[c] for c in plain)
        assert keyword_decrypt(cipher, "ZOMBIE") == plain

    def test_roundtrip_b64(self):
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        plain = "kCmlgFi6GUJN+/"
        keyed = build_keyed_alphabet("TheGiant", alpha)
        table = {p: k for p, k in zip(alpha, keyed)}
        cipher = "".join(table[c] for c in plain)
        assert keyword_decrypt(cipher, "TheGiant", alphabet=ALPHABET_B64) == plain

    def test_key_with_no_usable_chars_returns_none(self):
        assert keyword_decrypt("ABC", "123", alphabet=ALPHABET_52) is None

    def test_non_alphabet_chars_pass_through(self):
        out = keyword_decrypt("AB+/", "ZOMBIE", alphabet=ALPHABET_52)
        assert out.endswith("+/")


class TestBase64Safety:
    """A substitution over a base64 subset must keep the text decodable."""

    @pytest.mark.parametrize(
        "alphabet", [ALPHABET_26, ALPHABET_52, ALPHABET_B64, ALPHABET_ALNUM62]
    )
    def test_output_stays_valid_base64(self, alphabet):
        ct = base64.b64encode(bytes(range(96))).decode().rstrip("=")
        for out in (
            atbash_decrypt(ct, alphabet=alphabet),
            keyword_decrypt(ct, "TheGiant", alphabet=alphabet),
        ):
            assert set(out) <= B64_CHARS


class TestAxisSizes:
    def test_atbash_bare_sweeps_alphabets(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["atbash"], N_KEYS)}
        assert sizes["atbash"] == N_POLYALPHA_ALPHABETS

    @pytest.mark.parametrize("stage", ["atbash26", "atbash52", "atbash64"])
    def test_atbash_pinned_is_keyless(self, stage):
        assert axes_for_pipeline([stage], N_KEYS) == []

    def test_keyword_bare_includes_alphabets(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["keyword"], N_KEYS)}
        assert sizes["keyword"] == N_KEYS * N_POLYALPHA_ALPHABETS

    def test_keyword_pinned_is_keys_only(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["keyword64"], N_KEYS)}
        assert sizes["keyword64"] == N_KEYS
