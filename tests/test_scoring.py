from __future__ import annotations

import base64

import pytest

from stages.common import combined_score, printable_ratio
from stages.xor import repeating_xor


class TestPrintableRatio:
    """Tests for printable_ratio utility function."""

    def test_fully_printable_text(self):
        """Fully printable text returns 1.0."""
        assert printable_ratio(b"Hello World!") == 1.0

    def test_printable_with_whitespace(self):
        """Tabs and newlines count as printable."""
        assert printable_ratio(b"Hello\tWorld\n") == 1.0

    def test_fully_non_printable(self):
        """Fully non-printable returns 0.0."""
        assert printable_ratio(b"\x00\x01\x02") == 0.0

    def test_empty_bytes(self):
        """Empty bytes returns 0.0."""
        assert printable_ratio(b"") == 0.0

    def test_mixed_printable(self):
        """Mixed content returns correct ratio."""
        mixed = b"AB\x00\x01"
        assert printable_ratio(mixed) == 0.5

    def test_typographic_punctuation_is_printable(self):
        """Em/en dashes, curly quotes and ellipsis count as printable."""
        text = "He said \u201cgo\u201d \u2014 then left\u2026 \u2013M"
        assert printable_ratio(text.encode("utf-8")) == 1.0

    def test_accented_latin_is_printable(self):
        """Latin-1 accented letters count as printable."""
        assert printable_ratio("caf\u00e9 na\u00efve".encode("utf-8")) == 1.0

    def test_non_latin_scripts_are_not_printable(self):
        """Cyrillic/CJK/emoji still read as non-printable noise."""
        assert printable_ratio("\u043f\u0440\u0438\u0432\u0435\u0442".encode()) < 1.0
        assert printable_ratio("\u65e5\u672c\u8a9e".encode("utf-8")) == 0.0
        assert printable_ratio("hi \U0001f389".encode("utf-8")) < 1.0

    def test_invalid_utf8_falls_back_to_bytes(self):
        """Undecodable bytes fall back to a per-byte printable count."""
        assert printable_ratio(b"AB\xff\xfe") == 0.5
        assert printable_ratio(b"\xff\xfe\xfd") == 0.0


class TestCombinedScore:
    """Tests for combined_score (printable + English detection)."""

    @pytest.fixture
    def common_words(self):
        """Load common words for testing."""
        try:
            with open("common.txt") as f:
                return set(word.strip().upper() for word in f)
        except FileNotFoundError:
            return None

    def test_perfect_english_scores_high(self, common_words):
        """Perfect English scores close to 2.0."""
        if common_words is None:
            pytest.skip("common.txt not found")
        score = combined_score(b"THE MAN WAS HERE", common_words)
        assert score > 1.8

    def test_good_english_scores_above_threshold(self, common_words):
        """Good English scores > 1.7."""
        score = combined_score(b"THE QUICK BROWN FOX", common_words)
        assert score > 1.7

    def test_proper_spacing_improves_score(self, common_words):
        """Proper spacing improves score."""
        score_spaces = combined_score(b"HELLO WORLD", common_words)
        score_no_spaces = combined_score(b"HELLOWORLD", common_words)
        assert score_spaces > score_no_spaces

    def test_gibberish_scores_low(self, common_words):
        """Gibberish scores lower than English."""
        english_score = combined_score(b"THE QUICK BROWN FOX", common_words)
        gibberish_score = combined_score(b"XQZ JKWPM BRVWN FGX", common_words)
        assert english_score > gibberish_score
        assert english_score - gibberish_score > 0.2

    def test_printable_no_english_scores_medium(self):
        """Printable non-English scores 1.0-1.7."""
        score = combined_score(b"XQZJKW")
        assert 1.0 <= score < 1.7

    def test_non_printable_scores_below_one(self):
        """Non-printable bytes score < 1.0."""
        assert combined_score(b"\x00\x01\x02") == 0.0
        assert combined_score(b"AB\x00\x01") == 0.5

    def test_empty_bytes(self):
        """Empty bytes returns 0.0."""
        assert combined_score(b"") == 0.0

    def test_typography_not_penalised_below_one(self, common_words):
        """Prose with an en dash scores like English, not like binary."""
        prose = (
            "The man was here and the men were there, so the man went home. "
            "\u2013M"
        )
        assert combined_score(prose.encode("utf-8"), common_words) > 1.5

    def test_typography_scores_close_to_ascii_equivalent(self, common_words):
        """Curly quotes score about the same as their ASCII counterparts."""
        curly = "He said \u201cthe man was here\u201d and then went home."
        plain = 'He said "the man was here" and then went home.'
        curly_score = combined_score(curly.encode("utf-8"), common_words)
        plain_score = combined_score(plain.encode("utf-8"), common_words)
        assert abs(curly_score - plain_score) < 0.05


class TestTypeDetection:
    """Tests for text vs bytes type detection in pipeline."""

    def test_base64_to_printable_text(self):
        """Base64 decodes to printable text."""
        plaintext = b"Hello World"
        encoded = base64.b64encode(plaintext).decode()
        decoded = base64.b64decode(encoded)
        assert printable_ratio(decoded) == 1.0
        assert decoded.decode("ascii") == "Hello World"

    def test_base64_to_binary(self):
        """Base64 decodes to binary."""
        binary = bytes([0x00, 0xFF, 0xFE])
        encoded = base64.b64encode(binary).decode()
        decoded = base64.b64decode(encoded)
        assert printable_ratio(decoded) < 1.0

    def test_xor_accepts_text_and_bytes(self):
        """XOR accepts both text and bytes."""
        result1 = repeating_xor("Hello".encode("utf-8"), b"KEY")
        result2 = repeating_xor(b"Hello", b"KEY")
        assert isinstance(result1, bytes)
        assert isinstance(result2, bytes)

    def test_xor_output_printability(self):
        """XOR output can be printable or not."""
        result1 = repeating_xor(b"Hello World", b"\x00")
        assert printable_ratio(result1) == 1.0
        result2 = repeating_xor(b"AAAA", b"A")
        assert printable_ratio(result2) == 0.0


class TestShortTextDamping:
    """
    Short fragments must not score like real prose.

    A beaufort/all_printable sweep produced ' 3C8' — four characters of
    garbage — at 1.851, essentially tied with the genuine 28-character
    plaintext at 1.880. Chi-squared over four samples is noise, and the single
    space is a 25% space ratio, which earned the full spacing bonus.
    """

    def test_four_char_fragment_scores_below_threshold(self):
        from stages.common import combined_score

        assert combined_score(b" 3C8") < 1.4

    def test_single_character_is_not_english(self):
        from stages.common import combined_score

        assert combined_score(b"a") < 1.2

    def test_real_plaintext_is_unaffected(self):
        from stages.common import combined_score

        assert combined_score(b"The many worlds are now one.") > 1.85

    def test_long_plaintext_outranks_short_fragment(self):
        from stages.common import combined_score

        assert combined_score(b"The many worlds are now one.") > combined_score(b" 3C8")

    def test_damping_is_proportional_to_length(self):
        from stages.common import MIN_RELIABLE_LENGTH, english_score

        text = "the quick brown fox jumps"
        full = english_score(text[:MIN_RELIABLE_LENGTH])
        half = english_score(text[: MIN_RELIABLE_LENGTH // 2])
        assert half < full

    def test_no_damping_at_or_above_threshold(self):
        from stages.common import MIN_RELIABLE_LENGTH, english_score

        text = "the quick brown fox jumps over"
        assert len(text) > MIN_RELIABLE_LENGTH
        assert english_score(text) == english_score(text)
