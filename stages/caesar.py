from __future__ import annotations


def _shift_char(ch: str, shift: int) -> str:
    """Shift a single alphanumeric character, leaving others untouched."""
    o = ord(ch)
    if 65 <= o <= 90:  # A-Z
        return chr(65 + ((o - 65 + shift) % 26))
    if 97 <= o <= 122:  # a-z
        return chr(97 + ((o - 97 + shift) % 26))
    if 48 <= o <= 57:  # 0-9
        return chr(48 + ((o - 48 + shift) % 10))
    return ch


def caesar_shift_text(text: str, shift: int) -> str:
    """
    Apply Caesar cipher shift to text.

    Shifts alphanumeric characters only: A-Z wraps within A-Z,
    a-z wraps within a-z, 0-9 wraps within 0-9. All other characters
    (/, =, +, etc.) are preserved as-is.

    Args:
        text: Input text
        shift: Number of positions to shift (positive or negative)

    Returns:
        Shifted text
    """
    return "".join(_shift_char(ch, shift) for ch in text)
