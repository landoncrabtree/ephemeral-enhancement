"""Tests for the shared alpha/alphanumeric/all charset modes."""

from __future__ import annotations

import pytest

from core.pipeline import axes_for_pipeline
from stages.charsets import (
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    CHARSET_LETTERS_ONLY,
    N_CHARSET_MODES,
    charset_name,
    is_selected,
    merge_selected,
    split_selected,
)
from stages.columnar import columnar_decrypt
from stages.myszkowski import myszkowski_decrypt
from stages.railfence import railfence_decrypt, redefense_decrypt
from stages.scytale import scytale_decrypt

# Mixed payload: letters, digits and base64 symbols.
SAMPLE = "AbC12+/dEfG34"
N_KEYS = 4


class TestCharsetPrimitives:
    def test_three_modes(self):
        assert N_CHARSET_MODES == 3

    def test_mode_ordering_is_stable(self):
        assert (CHARSET_ALPHA, CHARSET_ALPHANUMERIC, CHARSET_ALL) == (0, 1, 2)

    def test_letters_only_alias_points_at_alpha(self):
        assert CHARSET_LETTERS_ONLY == CHARSET_ALPHA

    def test_names(self):
        assert charset_name(CHARSET_ALPHA) == "alpha"
        assert charset_name(CHARSET_ALPHANUMERIC) == "alphanumeric"
        assert charset_name(CHARSET_ALL) == "all"

    @pytest.mark.parametrize(
        "ch,alpha,alnum",
        [("A", True, True), ("z", True, True), ("5", False, True),
         ("+", False, False), ("/", False, False), ("=", False, False)],
    )
    def test_is_selected(self, ch, alpha, alnum):
        assert is_selected(ch, CHARSET_ALPHA) is alpha
        assert is_selected(ch, CHARSET_ALPHANUMERIC) is alnum
        assert is_selected(ch, CHARSET_ALL) is True

    def test_split_merge_roundtrip(self):
        chars, positions = split_selected(SAMPLE, CHARSET_ALPHA)
        assert "".join(chars) == "AbCdEfG"
        assert merge_selected(SAMPLE, positions, "".join(chars)) == SAMPLE


TRANSPOSITIONS = [
    ("columnar", lambda t, m: columnar_decrypt(t, "ZOMBIE", m)),
    ("myszkowski", lambda t, m: myszkowski_decrypt(t, "ZOMBIE", m)),
    ("railfence", lambda t, m: railfence_decrypt(t, 3, 0, m)),
    ("redefense", lambda t, m: redefense_decrypt(t, "ZOM", 0, m)),
    ("scytale", lambda t, m: scytale_decrypt(t, 3, m)),
]


class TestTranspositionCharsets:
    """Every transposition stage must honour all three modes identically."""

    @pytest.mark.parametrize("name,fn", TRANSPOSITIONS)
    def test_alpha_mode_keeps_digits_and_symbols_in_place(self, name, fn):
        out = fn(SAMPLE, CHARSET_ALPHA)
        for i, ch in enumerate(SAMPLE):
            if not ch.isalpha():
                assert out[i] == ch, f"{name} moved {ch!r} in alpha mode"

    @pytest.mark.parametrize("name,fn", TRANSPOSITIONS)
    def test_alphanumeric_mode_keeps_symbols_in_place(self, name, fn):
        out = fn(SAMPLE, CHARSET_ALPHANUMERIC)
        for i, ch in enumerate(SAMPLE):
            if not ch.isalnum():
                assert out[i] == ch, f"{name} moved {ch!r} in alphanumeric mode"

    @pytest.mark.parametrize("name,fn", TRANSPOSITIONS)
    def test_all_modes_preserve_multiset(self, name, fn):
        for mode in range(N_CHARSET_MODES):
            assert sorted(fn(SAMPLE, mode)) == sorted(SAMPLE)

    @pytest.mark.parametrize("name,fn", TRANSPOSITIONS)
    def test_modes_are_distinguishable(self, name, fn):
        """alpha and all must not collapse to the same permutation."""
        assert fn(SAMPLE, CHARSET_ALPHA) != fn(SAMPLE, CHARSET_ALL)


class TestCharsetAxisSizes:
    """Charset modes must be reflected in the search space."""

    @pytest.mark.parametrize(
        "stage,expected",
        [
            ("columnar", N_KEYS * N_CHARSET_MODES),
            ("myszkowski", N_KEYS * N_CHARSET_MODES),
            ("redefense", N_KEYS * N_CHARSET_MODES),
            ("double_columnar", N_KEYS * N_KEYS * N_CHARSET_MODES),
            ("railfence", 29 * N_CHARSET_MODES),
            ("scytale", 99 * N_CHARSET_MODES),
        ],
    )
    def test_axis_includes_charset_modes(self, stage, expected):
        sizes = {a.name: a.size for a in axes_for_pipeline([stage], N_KEYS)}
        assert sizes[stage] == expected
