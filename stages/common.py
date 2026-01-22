from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, Literal

PayloadKind = Literal["text", "bytes"]


@dataclass(slots=True)
class Candidate:
    payload: str | bytes
    kind: PayloadKind
    meta: Dict[str, Any] = field(default_factory=dict)


def printable_ratio(b: bytes) -> float:
    """
    Returns the ratio of printable ASCII characters (0.0 to 1.0).
    """
    if not b:
        return 0.0
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return printable / len(b)


# English letter frequencies (from most to least common)
# Source: https://en.wikipedia.org/wiki/Letter_frequency
ENGLISH_FREQ = {
    "E": 0.1270,
    "T": 0.0906,
    "A": 0.0817,
    "O": 0.0751,
    "I": 0.0697,
    "N": 0.0675,
    "S": 0.0633,
    "H": 0.0609,
    "R": 0.0599,
    "D": 0.0425,
    "L": 0.0403,
    "C": 0.0278,
    "U": 0.0276,
    "M": 0.0241,
    "W": 0.0236,
    "F": 0.0223,
    "G": 0.0202,
    "Y": 0.0197,
    "P": 0.0193,
    "B": 0.0149,
    "V": 0.0098,
    "K": 0.0077,
    "J": 0.0015,
    "X": 0.0015,
    "Q": 0.0010,
    "Z": 0.0007,
}


def chi_squared_score(text: str) -> float:
    """
    Calculate chi-squared statistic comparing text to English letter frequencies.
    Lower values indicate better match to English.
    Returns a normalized score where 0 is worst, 1 is best.
    """
    if not text:
        return 0.0

    # Count letters (case-insensitive)
    letter_counts = {}
    total_letters = 0
    for char in text.upper():
        if "A" <= char <= "Z":
            letter_counts[char] = letter_counts.get(char, 0) + 1
            total_letters += 1

    if total_letters == 0:
        return 0.0

    # Calculate chi-squared statistic
    chi_squared = 0.0
    for letter, expected_freq in ENGLISH_FREQ.items():
        expected_count = expected_freq * total_letters
        observed_count = letter_counts.get(letter, 0)
        if expected_count > 0:
            chi_squared += ((observed_count - expected_count) ** 2) / expected_count

    # Normalize: typical chi-squared for random text is ~500-1000
    # Good English text is usually < 100
    # Convert to 0-1 scale where 1 is best
    normalized = max(0.0, 1.0 - (chi_squared / 500.0))
    return normalized


def word_score(text: str, common_words: set[str]) -> float:
    """
    Score text based on presence of common English words.
    Returns ratio of recognized words (0.0 to 1.0).
    """
    if not text:
        return 0.0

    # Split on whitespace and punctuation
    words = []
    current_word = []
    for char in text:
        if char.isalpha():
            current_word.append(char)
        elif current_word:
            words.append("".join(current_word).upper())
            current_word = []
    if current_word:
        words.append("".join(current_word).upper())

    if not words:
        return 0.0

    # Count how many words are in our dictionary
    recognized = sum(1 for word in words if word in common_words)
    return recognized / len(words)


def english_score(text: str, common_words: set[str] | None = None) -> float:
    """
    Score how "English-like" the text is using multiple heuristics.
    Returns a value from 0.0 (not English) to ~1.0 (very English-like).

    Combines:
    - Chi-squared frequency analysis (weight: 0.7)
    - Common word matching (weight: 0.3)
    - Space ratio bonus (up to 0.2 for proper word spacing)
    """
    if not text:
        return 0.0

    # Chi-squared frequency analysis
    chi_score = chi_squared_score(text)

    # Word matching (if dictionary provided)
    if common_words:
        word_match_score = word_score(text, common_words)
    else:
        word_match_score = 0.0

    # Space ratio bonus: English text typically has 15-20% spaces
    space_count = text.count(" ")
    if len(text) > 0:
        space_ratio = space_count / len(text)
        # Ideal space ratio is around 0.15-0.20 (15-20%)
        if 0.10 <= space_ratio <= 0.25:
            space_bonus = 0.2
        elif 0.05 <= space_ratio < 0.10 or 0.25 < space_ratio <= 0.35:
            space_bonus = 0.1
        else:
            space_bonus = 0.0
    else:
        space_bonus = 0.0

    # Weighted combination
    combined = (chi_score * 0.7) + (word_match_score * 0.3) + space_bonus
    return min(1.0, combined)  # Cap at 1.0


def combined_score(b: bytes, common_words: set[str] | None = None) -> float:
    """
    Combined scoring: printable_ratio (0-1) + english_score (0-1).

    Returns:
    - < 1.0: Contains non-printable bytes (ratio of printable bytes)
    - = 1.0: Fully printable but no English characteristics
    - > 1.0: Fully printable + English-like (up to 2.0 for perfect English)
    """
    pr = printable_ratio(b)

    # If not fully printable, return just the printable ratio
    if pr < 1.0:
        return pr

    # If fully printable, try to decode and score as English
    try:
        text = b.decode("utf-8", errors="ignore")
        eng_score = english_score(text, common_words)
        return 1.0 + eng_score
    except Exception:
        return pr


def normalize_base64_alphabet(s: str, alphabet: str) -> str:
    allowed = set(alphabet)
    return "".join(ch for ch in s if ch in allowed)


def take(it: Iterable[Candidate], limit: int) -> Iterator[Candidate]:
    if limit <= 0:
        yield from it
        return
    n = 0
    for x in it:
        yield x
        n += 1
        if n >= limit:
            return
