"""Tests for the generalised Playfair and Trifid grid ciphers."""

from __future__ import annotations

import base64

import pytest

from core.pipeline import axes_for_pipeline
from stages.playfair import (
    N_PLAYFAIR_GRIDS,
    PLAYFAIR_ALPHABETS,
    playfair_decrypt,
    playfair_encrypt,
)
from stages.trifid import (
    N_TRIFID_CUBES,
    N_TRIFID_PERIODS,
    TRIFID_ALPHABETS,
    _cube_side,
    trifid_decrypt,
    trifid_encrypt,
)

B64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
B64_TEXT = base64.b64encode(bytes(range(96))).decode().rstrip("=")
N_KEYS = 4


class TestGridShapes:
    def test_playfair_alphabets_are_perfect_squares(self):
        for alpha in PLAYFAIR_ALPHABETS:
            side = int(len(alpha) ** 0.5)
            assert side * side == len(alpha)

    def test_playfair_has_a_base64_grid(self):
        assert set(PLAYFAIR_ALPHABETS[2]) == B64_CHARS
        assert len(PLAYFAIR_ALPHABETS[2]) == 64

    def test_trifid_alphabets_are_perfect_cubes(self):
        for alpha in TRIFID_ALPHABETS:
            assert _cube_side(alpha) ** 3 == len(alpha)

    def test_trifid_has_a_base64_cube(self):
        assert set(TRIFID_ALPHABETS[1]) == B64_CHARS
        assert _cube_side(TRIFID_ALPHABETS[1]) == 4


class TestPlayfair:
    @pytest.mark.parametrize("grid", range(N_PLAYFAIR_GRIDS))
    def test_roundtrip(self, grid):
        plain = "ATTACKATDAWN" if grid == 0 else B64_TEXT[:60]
        cipher = playfair_encrypt(plain, "TheGiant", grid)
        assert playfair_decrypt(cipher, "TheGiant", grid) == plain

    def test_wrong_key_does_not_recover(self):
        cipher = playfair_encrypt(B64_TEXT[:40], "TheGiant", 2)
        assert playfair_decrypt(cipher, "Zombies", 2) != B64_TEXT[:40]

    def test_base64_grid_preserves_alphabet(self):
        out = playfair_decrypt(B64_TEXT, "TheGiant", 2)
        assert set(out) <= B64_CHARS
        assert len(out) == len(B64_TEXT)
        base64.b64decode(out + "=" * ((-len(out)) % 4))

    def test_five_by_five_emits_letters_only(self):
        """The classical grid cannot preserve base64 — hence the 8x8 variant."""
        out = playfair_decrypt("ABCDEFGH", "KEY", 0)
        assert set(out) <= set(PLAYFAIR_ALPHABETS[0])

    def test_unknown_grid_returns_none(self):
        assert playfair_decrypt("ABCD", "KEY", 99) is None

    def test_odd_length_keeps_trailing_char(self):
        out = playfair_decrypt("ABC", "KEY", 2)
        assert len(out) == 3

    def test_chars_outside_alphabet_pass_through(self):
        out = playfair_decrypt("AB!CD", "KEY", 0)
        assert out[2] == "!"


class TestTrifid:
    @pytest.mark.parametrize("cube", range(N_TRIFID_CUBES))
    @pytest.mark.parametrize("period", [2, 3, 5, 7, 12])
    def test_roundtrip(self, cube, period):
        plain = "ABCDEFGHIJKLMNOP" if cube == 0 else B64_TEXT[:60]
        cipher = trifid_encrypt(plain, "TheGiant", period, cube)
        assert trifid_decrypt(cipher, "TheGiant", period, cube) == plain

    def test_wrong_period_does_not_recover(self):
        cipher = trifid_encrypt(B64_TEXT[:60], "TheGiant", 5, 1)
        assert trifid_decrypt(cipher, "TheGiant", 6, 1) != B64_TEXT[:60]

    def test_base64_cube_preserves_alphabet(self):
        out = trifid_decrypt(B64_TEXT, "TheGiant", 5, 1)
        assert set(out) <= B64_CHARS
        assert len(out) == len(B64_TEXT)
        base64.b64decode(out + "=" * ((-len(out)) % 4))

    def test_invalid_period_returns_none(self):
        assert trifid_decrypt(B64_TEXT, "KEY", 1, 1) is None

    def test_unknown_cube_returns_none(self):
        assert trifid_decrypt(B64_TEXT, "KEY", 5, 99) is None

    def test_chars_outside_alphabet_pass_through(self):
        out = trifid_decrypt("ABC!DEF", "KEY", 3, 0)
        assert out[3] == "!"


class TestAxisSizes:
    def test_playfair_axis(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["playfair"], N_KEYS)}
        assert sizes["playfair"] == N_KEYS * N_PLAYFAIR_GRIDS

    def test_trifid_axis(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["trifid"], N_KEYS)}
        assert sizes["trifid"] == N_KEYS * N_TRIFID_PERIODS * N_TRIFID_CUBES
