from __future__ import annotations

from stages.reverse import reverse_text


class TestReverseCipher:
    """Tests for Reverse cipher operations."""

    def test_reverse_basic(self):
        """Reverse basic text."""
        result = reverse_text("Hello World")
        assert result == "dlroW olleH"

    def test_reverse_with_punctuation(self):
        """Reverse text with punctuation."""
        result = reverse_text("Hello, World!")
        assert result == "!dlroW ,olleH"

    def test_reverse_round_trip(self):
        """Reversing twice returns original."""
        original = "Test message 123"
        assert reverse_text(reverse_text(original)) == original

    def test_palindrome_unchanged(self):
        """Palindrome reverses to itself."""
        assert reverse_text("racecar") == "racecar"

    def test_empty_string(self):
        """Empty string returns empty."""
        assert reverse_text("") == ""

    def test_single_character(self):
        """Single character returns itself."""
        assert reverse_text("A") == "A"
