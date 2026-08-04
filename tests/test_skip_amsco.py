"""Tests for the Skip (decimation) and AMSCO transposition stages."""

from __future__ import annotations

import base64

import pytest

from core.pipeline import axes_for_pipeline
from stages.amsco import (
    N_AMSCO_PATTERNS,
    _amsco_decrypt_raw,
    _chunk_layout,
    amsco_decrypt,
    key_order,
)
from stages.charsets import (
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    N_CHARSET_MODES,
)
from stages.skip import MAX_BYPASS, N_SKIP_VALUES, _read_order, skip_decrypt

SAMPLE = "AbC12+/dEfG34hIjK"
N_KEYS = 4


def _skip_encrypt(plain: str, skip: int, bypass: int) -> str:
    """Reference encryption: read the plaintext in stepped order."""
    order = _read_order(len(plain), skip, bypass)
    return "".join(plain[i] for i in order)


class TestSkipOrder:
    @pytest.mark.parametrize("n,skip,bypass", [(20, 3, 5), (17, 2, 0), (50, 25, 5)])
    def test_order_is_a_permutation(self, n, skip, bypass):
        assert sorted(_read_order(n, skip, bypass)) == list(range(n))

    def test_skip_of_one_is_sequential(self):
        assert _read_order(5, 1, 0) == [0, 1, 2, 3, 4]

    def test_bypass_sets_starting_point(self):
        assert _read_order(5, 1, 2)[0] == 2


class TestSkipCipher:
    @pytest.mark.parametrize("skip,bypass", [(2, 0), (3, 5), (25, 5), (7, 3)])
    def test_roundtrip(self, skip, bypass):
        plain = "TheMountainMustBeSearchedForTheFrozenOne"
        assert skip_decrypt(_skip_encrypt(plain, skip, bypass), skip, bypass) == plain

    def test_zns8_parameters_roundtrip(self):
        """ZNS-8 used 'bypass first 5, skip 25'."""
        plain = "RichtofenMustUnderstandThatUsingTheseTeleporters"
        assert skip_decrypt(_skip_encrypt(plain, 25, 5), 25, 5) == plain

    def test_preserves_multiset(self):
        assert sorted(skip_decrypt(SAMPLE, 3, 2)) == sorted(SAMPLE)

    def test_invalid_skip_is_identity(self):
        assert skip_decrypt(SAMPLE, 1) == SAMPLE
        assert skip_decrypt(SAMPLE, 0) == SAMPLE

    def test_empty(self):
        assert skip_decrypt("", 3) == ""

    def test_alpha_mode_keeps_others_in_place(self):
        out = skip_decrypt(SAMPLE, 3, 0, CHARSET_ALPHA)
        for i, ch in enumerate(SAMPLE):
            if not ch.isalpha():
                assert out[i] == ch


class TestAmscoLayout:
    def test_digit_key_ranks_numerically(self):
        assert key_order("198346572") == [0, 8, 7, 2, 3, 5, 4, 6, 1]

    def test_alpha_key_ranks_alphabetically(self):
        assert key_order("ZOMBIE") == [5, 4, 3, 0, 2, 1]

    def test_chunks_alternate_and_cover_text(self):
        grid = _chunk_layout(20, 4, False)
        assert sum(map(sum, grid)) == 20
        assert grid[0][:4] == [1, 2, 1, 2]

    def test_alternation_carries_across_rows(self):
        grid = _chunk_layout(12, 3, False)
        flat = [n for row in grid for n in row if n]
        assert flat[:6] == [1, 2, 1, 2, 1, 2]

    def test_start_pair_flips_pattern(self):
        assert _chunk_layout(20, 4, True)[0][:4] == [2, 1, 2, 1]


class TestAmscoCipher:
    def _encrypt(self, plain, keyword, start_pair):
        grid = _chunk_layout(len(plain), len(keyword), start_pair)
        order = key_order(keyword)
        cells, pos = [], 0
        for row in grid:
            out_row = []
            for size in row:
                out_row.append(plain[pos : pos + size])
                pos += size
            cells.append(out_row)
        parts = []
        for rank in range(len(keyword)):
            col = order.index(rank)
            for row in cells:
                parts.append(row[col])
        return "".join(parts)

    @pytest.mark.parametrize("keyword", ["198346572", "ZOMBIE", "TheGiant"])
    @pytest.mark.parametrize("start_pair", [False, True])
    def test_roundtrip(self, keyword, start_pair):
        plain = "IMeetTheReporterWhoWasToDeliverTheArtifactHeSaidHeWas"
        cipher = self._encrypt(plain, keyword, start_pair)
        assert _amsco_decrypt_raw(cipher, keyword, start_pair) == plain

    def test_preserves_multiset(self):
        assert sorted(amsco_decrypt(SAMPLE, "ZOMBIE")) == sorted(SAMPLE)

    def test_short_key_is_identity(self):
        assert amsco_decrypt(SAMPLE, "A") == SAMPLE
        assert amsco_decrypt(SAMPLE, "") == SAMPLE

    def test_alpha_mode_keeps_others_in_place(self):
        out = amsco_decrypt(SAMPLE, "ZOMBIE", False, CHARSET_ALPHA)
        for i, ch in enumerate(SAMPLE):
            if not ch.isalpha():
                assert out[i] == ch


class TestBase64Safety:
    """Transpositions permute characters, so base64 stays decodable."""

    @pytest.mark.parametrize("mode", [CHARSET_ALPHA, CHARSET_ALPHANUMERIC, CHARSET_ALL])
    def test_outputs_remain_valid_base64(self, mode):
        ct = base64.b64encode(bytes(range(96))).decode().rstrip("=")
        for out in (
            skip_decrypt(ct, 7, 3, mode),
            amsco_decrypt(ct, "TheGiant", False, mode),
        ):
            assert sorted(out) == sorted(ct)
            base64.b64decode(out + "=" * ((-len(out)) % 4))


class TestAxisSizes:
    def test_skip_axis(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["skip"], N_KEYS)}
        assert sizes["skip"] == N_SKIP_VALUES * MAX_BYPASS * N_CHARSET_MODES

    def test_amsco_axis(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["amsco"], N_KEYS)}
        assert sizes["amsco"] == N_KEYS * N_AMSCO_PATTERNS * N_CHARSET_MODES
