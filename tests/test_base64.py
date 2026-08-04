from __future__ import annotations

import base64

import pytest

from stages.common import printable_ratio


class TestBase64Encoding:
    """Tests for Base64 encoding/decoding."""

    def test_decode_valid_with_padding(self):
        """Decode valid base64 with padding."""
        ciphertext = "SGVsbG8gd29ybGQ="
        decoded = base64.b64decode(ciphertext)
        assert decoded == b"Hello world"

    def test_decode_valid_without_padding(self):
        """Decode valid base64 without padding."""
        ciphertext = "U2VjcmV0"
        decoded = base64.b64decode(ciphertext)
        assert decoded == b"Secret"

    def test_encode_decode_round_trip(self):
        """Encode and decode round trip."""
        plaintext = b"Test message 123!"
        encoded = base64.b64encode(plaintext).decode()
        decoded = base64.b64decode(encoded)
        assert decoded == plaintext

    def test_invalid_base64_raises_error(self):
        """Invalid base64 raises error with validate=True."""
        invalid = "SGVsbG8gd29ybGQ"
        with pytest.raises(Exception):
            base64.b64decode(invalid, validate=False)

    def test_empty_string(self):
        """Empty string decodes to empty bytes."""
        result = base64.b64decode("")
        assert result == b""

    def test_decode_to_printable(self):
        """Decode to fully printable ASCII."""
        plaintext = b"Hello World! 123"
        encoded = base64.b64encode(plaintext).decode()
        decoded = base64.b64decode(encoded)
        assert printable_ratio(decoded) == 1.0

    def test_decode_to_binary(self):
        """Decode to non-printable binary."""
        binary = bytes([0x00, 0x01, 0xFF, 0xFE])
        encoded = base64.b64encode(binary).decode()
        decoded = base64.b64decode(encoded)
        assert printable_ratio(decoded) < 1.0


class TestBase64StrictAlphabet:
    """
    The b64 stage force-pads unpadded input but rejects non-base64 characters.

    Silently discarding stray characters (the old validate=False behaviour)
    produced short misaligned blobs that scored as false positives — see
    ATTEMPTS.md #8, where an all-printable classical layer yielded 16,793
    bogus hits.
    """

    def _run(self, text, kind="text"):
        """Return the stage's output payload, or None if the branch is pruned.

        Note the stage promotes fully-printable output to str, so short
        ASCII payloads come back as text rather than bytes.
        """
        from core.executor import StageExecutor

        ex = StageExecutor("", ["k"], ["b64"], "standard")
        return ex._execute_b64(text, kind, 0)

    # --- unpadded input must still decode (the regression this guards) ---

    def test_unpadded_remainder_2(self):
        assert self._run("QQ")[0] == "A"

    def test_unpadded_remainder_3(self):
        assert self._run("QUE")[0] == "AA"

    def test_unpadded_long_blob_matches_padded(self):
        import base64

        raw = bytes(range(80))
        padded = base64.b64encode(raw).decode()
        assert self._run(padded.rstrip("="))[0] == raw
        assert self._run(padded)[0] == raw

    def test_partially_padded(self):
        assert self._run("QQ=")[0] == "A"

    # --- whitespace is not significant in base64 ---

    def test_internal_whitespace_ignored(self):
        assert self._run("QU\nE")[0] == "AA"

    def test_surrounding_whitespace_ignored(self):
        assert self._run("  QUE\r\n")[0] == "AA"

    # --- non-base64 characters prune the branch instead of being discarded ---

    def test_non_alphabet_char_rejected(self):
        assert self._run("QU!E") is None

    def test_all_printable_corruption_rejected(self):
        assert self._run('hEwZ";%^-3;x"u@KC7Q6#~(z') is None

    def test_impossible_length_rejected(self):
        assert self._run("QQQQQ") is None

    def test_empty_rejected(self):
        assert self._run("") is None
        assert self._run("===") is None

    def test_bytes_input_rejected(self):
        assert self._run(b"QUE", kind="bytes") is None
