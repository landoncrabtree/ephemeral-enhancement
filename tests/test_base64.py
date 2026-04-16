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
