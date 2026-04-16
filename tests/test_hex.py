"""Tests for hex decode pipeline stage."""

import pytest

from core.executor import StageExecutor
from core.pipeline import parse_pipeline, axes_for_pipeline, validate_pipeline


def _run_hex(ciphertext: str, pipeline: str = "hex", threshold: float = 0.0):
    """Helper to run a hex pipeline and return (score, meta) or None."""
    stages = parse_pipeline(pipeline)
    ex = StageExecutor(
        ciphertext=ciphertext,
        keys=["dummy"],
        stages=stages,
        bifid_alphabet="",
    )
    return ex.execute_pipeline(param_idxs=[0], threshold=threshold)


class TestHexDecode:
    def test_basic_ascii(self):
        """Hex-encoded ASCII text should decode correctly."""
        plaintext = "Hello World"
        hex_encoded = plaintext.encode().hex()
        score, meta = _run_hex(hex_encoded)
        assert score is not None
        assert score > 0

    def test_uppercase_hex(self):
        """Uppercase hex should also work."""
        plaintext = "Hello World"
        hex_encoded = plaintext.encode().hex().upper()
        score, meta = _run_hex(hex_encoded)
        assert score is not None

    def test_binary_output(self):
        """Non-printable hex should produce bytes output."""
        hex_str = "00ff80"
        score, meta = _run_hex(hex_str)
        assert score is not None
        assert score < 1.0  # not fully printable

    def test_invalid_hex(self):
        """Invalid hex string should return (None, None)."""
        score, meta = _run_hex("ZZZZ not hex")
        assert score is None

    def test_odd_length_hex(self):
        """Odd-length hex string gets padded with leading '0' and decoded."""
        score, meta = _run_hex("abc")
        assert score is not None

    def test_empty_string(self):
        """Empty hex string produces empty bytes → score 0."""
        score, meta = _run_hex("")
        assert score == 0.0

    def test_with_whitespace(self):
        """Leading/trailing whitespace should be stripped."""
        plaintext = "test"
        hex_encoded = "  " + plaintext.encode().hex() + "  "
        score, meta = _run_hex(hex_encoded)
        assert score is not None

    def test_hex_pipeline_axes(self):
        """hex adds no axis to the search space (like b64)."""
        stages = parse_pipeline("hex>rijndael-128-ecb")
        validate_pipeline(stages)
        axes = axes_for_pipeline(stages, 2)
        # hex adds no axis, rijndael-128-ecb adds one
        assert len(axes) == 1
        assert axes[0].name == "rijndael-128-ecb"

    def test_known_english(self):
        """Hex-encoded English text should score above 1.0."""
        plaintext = "The quick brown fox jumps over the lazy dog"
        hex_ct = plaintext.encode().hex()
        score, meta = _run_hex(hex_ct, threshold=1.0)
        assert score is not None
        assert score >= 1.0
