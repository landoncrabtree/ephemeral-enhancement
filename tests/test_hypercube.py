"""Tests for the hypercube (multi-axis reshape) transposition."""

from __future__ import annotations

import base64
from itertools import permutations

import pytest

from core.pipeline import axes_for_pipeline
from stages.charsets import (
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    N_CHARSET_MODES,
)
from stages.hypercube import (
    MAX_PERMS,
    MAX_SHAPES,
    _read_order,
    hypercube_decrypt,
    shapes_for_length,
)

B64_192 = base64.b64encode(bytes(range(144))).decode().rstrip("=")
N_KEYS = 4


class TestShapes:
    def test_192_factors_as_tesseract_counts(self):
        """8 cells x 6 faces x 4 corners — the shape motivating this stage."""
        assert (8, 6, 4) in shapes_for_length(192)

    def test_no_degenerate_axes(self):
        for shape in shapes_for_length(192):
            assert all(d >= 2 for d in shape)

    def test_shapes_multiply_to_length(self):
        for shape in shapes_for_length(192):
            product = 1
            for d in shape:
                product *= d
            assert product == 192

    def test_ordering_is_deterministic(self):
        assert shapes_for_length(192) == shapes_for_length(192)

    def test_prime_length_has_no_shapes(self):
        assert shapes_for_length(97) == []

    def test_axis_counts_present(self):
        lengths = {len(s) for s in shapes_for_length(192)}
        assert lengths == {2, 3, 4}


class TestReadOrder:
    @pytest.mark.parametrize("shape", [(8, 6, 4), (4, 4, 4, 3), (12, 16)])
    def test_order_is_a_permutation(self, shape):
        for perm in permutations(range(len(shape))):
            order = _read_order(shape, perm)
            assert sorted(order) == list(range(192))

    def test_identity_permutation_is_sequential(self):
        assert _read_order((8, 6, 4), (0, 1, 2)) == list(range(192))


class TestDecrypt:
    def test_identity_permutation_returns_input(self):
        idx = shapes_for_length(192).index((8, 6, 4))
        assert hypercube_decrypt(B64_192, idx, 0) == B64_192

    def test_every_shape_and_permutation_is_a_permutation(self):
        shapes = shapes_for_length(len(B64_192))
        for i, shape in enumerate(shapes):
            for p in range(len(list(permutations(range(len(shape)))))):
                out = hypercube_decrypt(B64_192, i, p)
                assert out is not None
                assert sorted(out) == sorted(B64_192)

    def test_non_identity_permutation_changes_text(self):
        idx = shapes_for_length(192).index((8, 6, 4))
        assert hypercube_decrypt(B64_192, idx, 3) != B64_192

    def test_out_of_range_shape_returns_none(self):
        assert hypercube_decrypt(B64_192, 9999, 0) is None

    def test_out_of_range_permutation_returns_none(self):
        idx = shapes_for_length(192).index((12, 16))  # 2 axes -> only 2 perms
        assert hypercube_decrypt(B64_192, idx, 5) is None

    def test_empty_returns_none(self):
        assert hypercube_decrypt("", 0, 0) is None

    def test_unfactorable_length_returns_none(self):
        assert hypercube_decrypt("A" * 97, 0, 0) is None


class TestBase64Safety:
    @pytest.mark.parametrize(
        "mode", [CHARSET_ALPHA, CHARSET_ALPHANUMERIC, CHARSET_ALL]
    )
    def test_output_decodes_as_base64(self, mode):
        out = hypercube_decrypt(B64_192, 0, 1, mode)
        if out is None:
            pytest.skip("shape not valid for this charset selection")
        assert sorted(out) == sorted(B64_192)
        base64.b64decode(out + "=" * ((-len(out)) % 4))

    def test_alpha_mode_keeps_others_in_place(self):
        text = "AbC12+/dEfG34hIjK"
        out = hypercube_decrypt(text, 0, 1, CHARSET_ALPHA)
        if out is None:
            pytest.skip("no valid shape for the selected subsequence")
        for i, ch in enumerate(text):
            if not ch.isalpha():
                assert out[i] == ch


class TestAxisSize:
    def test_axis_size(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["hypercube"], N_KEYS)}
        assert sizes["hypercube"] == MAX_SHAPES * MAX_PERMS * N_CHARSET_MODES

    def test_axis_is_keyless(self):
        with_keys = axes_for_pipeline(["hypercube"], 100)
        without = axes_for_pipeline(["hypercube"], 4)
        assert with_keys[0].size == without[0].size
