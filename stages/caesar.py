from __future__ import annotations


def _shift_char(ch: str, shift: int) -> str:
    """Shift a single character by the given amount."""
    o = ord(ch)
    if 65 <= o <= 90:  # A-Z
        return chr(65 + ((o - 65 + shift) % 26))
    if 97 <= o <= 122:  # a-z
        return chr(97 + ((o - 97 + shift) % 26))
    return ch


def caesar_shift_text(text: str, shift: int) -> str:
    """
    Apply Caesar cipher shift to text.

    Shifts only alphabetic characters, preserving case and non-alpha chars.

    Args:
        text: Input text
        shift: Number of positions to shift (positive or negative)

    Returns:
        Shifted text
    """
    shift %= 26
    return "".join(_shift_char(ch, shift) for ch in text)
