"""Tests for combined-alphabet polyalphabetic stage names."""

from __future__ import annotations

import pytest

from core.executor import _split_alphabet_suffix
from core.pipeline import axes_for_pipeline
from stages.polyalpha import N_POLYALPHA_ALPHABETS, N_POLYALPHA_MODES

N_KEYS = 4


def _axis_sizes(pipeline: list[str]) -> dict[str, int]:
    return {a.name: a.size for a in axes_for_pipeline(pipeline, N_KEYS)}


class TestAlphabetSuffixSplit:
    """Tests for _split_alphabet_suffix()."""

    @pytest.mark.parametrize("stage", ["vigenere", "beaufort", "porta", "trithemius"])
    def test_bare_name_is_unpinned(self, stage):
        assert _split_alphabet_suffix(stage) == (stage, None)

    @pytest.mark.parametrize("stage", ["vigenere", "beaufort", "porta", "trithemius"])
    def test_52_suffix_pins_alpha52(self, stage):
        assert _split_alphabet_suffix(f"{stage}52") == (stage, 1)

    @pytest.mark.parametrize("stage", ["vigenere", "beaufort", "porta", "trithemius"])
    def test_26_suffix_pins_alpha26(self, stage):
        assert _split_alphabet_suffix(f"{stage}26") == (stage, 0)


class TestCombinedAxisSizes:
    """Base stage names must sweep both alphabets."""

    @pytest.mark.parametrize("stage", ["vigenere", "beaufort", "porta"])
    def test_base_name_doubles_axis(self, stage):
        sizes = _axis_sizes([stage])
        assert sizes[stage] == N_KEYS * N_POLYALPHA_MODES * N_POLYALPHA_ALPHABETS

    @pytest.mark.parametrize("stage", ["vigenere", "beaufort", "porta"])
    def test_pinned_variants_keep_original_size(self, stage):
        expected = N_KEYS * N_POLYALPHA_MODES
        assert _axis_sizes([f"{stage}26"])[f"{stage}26"] == expected
        assert _axis_sizes([f"{stage}52"])[f"{stage}52"] == expected

    def test_pinned_is_half_of_combined(self):
        combined = _axis_sizes(["beaufort"])["beaufort"]
        pinned = _axis_sizes(["beaufort52"])["beaufort52"]
        assert combined == pinned * N_POLYALPHA_ALPHABETS

    def test_trithemius_base_sweeps_alphabets(self):
        assert _axis_sizes(["trithemius"])["trithemius"] == N_POLYALPHA_ALPHABETS

    @pytest.mark.parametrize("stage", ["trithemius26", "trithemius52"])
    def test_trithemius_pinned_is_keyless(self, stage):
        assert _axis_sizes([stage]) == {}


class TestCombinedStageExecution:
    """The combined name must reach both alphabets' results."""

    def _run(self, stage, ciphertext, key, size):
        """Collect every plaintext the stage produces across its axis."""
        from core.executor import StageExecutor

        out = []
        for idx in range(size):
            ex = StageExecutor("", [key], [stage], "standard", vary_case=False)
            res = ex._execute_polyalpha(stage, ciphertext, "text", [idx], 0, {})
            if res is not None:
                out.append(res[0])
        return out

    def test_combined_reaches_both_alphabet_results(self):
        from stages.polyalpha import beaufort_decrypt

        ct = "LeIXjxfrjSpfgR1R"
        key = "ZOMBIES"
        results = self._run("beaufort", ct, key, 1 * N_POLYALPHA_MODES * 2)
        assert beaufort_decrypt(ct, key, alpha52=True) in results
        assert beaufort_decrypt(ct, key, alpha52=False) in results

    def test_pinned_52_only_yields_alpha52(self):
        from stages.polyalpha import beaufort_decrypt

        ct = "LeIXjxfrjSpfgR1R"
        key = "ZOMBIES"
        results = self._run("beaufort52", ct, key, 1 * N_POLYALPHA_MODES)
        assert beaufort_decrypt(ct, key, alpha52=True) in results
        assert beaufort_decrypt(ct, key, alpha52=False) not in results

    def test_alphabet_recorded_in_meta(self):
        from core.executor import StageExecutor

        meta: dict = {}
        ex = StageExecutor("", ["ZOMBIES"], ["beaufort"], "standard", vary_case=False)
        ex._execute_polyalpha("beaufort", "AbCd", "text", [0], 0, meta)
        assert meta["beaufort_alphabet"] == "alpha26"

        meta = {}
        # alphabet is the high-order component: index 2 = alpha52, normal mode
        ex._execute_polyalpha("beaufort", "AbCd", "text", [2], 0, meta)
        assert meta["beaufort_alphabet"] == "alpha52"
        assert meta["beaufort_mode"] == "normal"
