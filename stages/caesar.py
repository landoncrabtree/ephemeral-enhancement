from __future__ import annotations

# Charset modes: 0=alpha-only, 1=alphanumeric, 2=all printable ASCII
N_CAESAR_CHARSET_MODES = 3

# All printable ASCII chars used as a single rotating alphabet (mode 2)
_ALL_PRINTABLE = [chr(i) for i in range(32, 127)]  # space through ~
_ALL_PRINTABLE_SET = set(_ALL_PRINTABLE)
_ALL_PRINTABLE_IDX = {ch: i for i, ch in enumerate(_ALL_PRINTABLE)}
_ALL_PRINTABLE_MOD = len(_ALL_PRINTABLE)  # 95

# Shifts per charset mode:
#   alpha: 26 (letters mod 26)
#   alphanumeric: LCM(26,10)=130 (letters mod 26, digits mod 10)
#   all_printable: 95 (all printable mod 95)
CAESAR_SHIFTS_PER_MODE = [26, 130, 95]
N_CAESAR_TOTAL = sum(CAESAR_SHIFTS_PER_MODE)  # 251


def _shift_alpha(ch: str, shift: int) -> str:
    """Shift only A-Z/a-z, leave everything else."""
    o = ord(ch)
    if 65 <= o <= 90:
        return chr(65 + ((o - 65 + shift) % 26))
    if 97 <= o <= 122:
        return chr(97 + ((o - 97 + shift) % 26))
    return ch


def _shift_alphanumeric(ch: str, shift: int) -> str:
    """Shift A-Z/a-z/0-9, leave everything else."""
    o = ord(ch)
    if 65 <= o <= 90:
        return chr(65 + ((o - 65 + shift) % 26))
    if 97 <= o <= 122:
        return chr(97 + ((o - 97 + shift) % 26))
    if 48 <= o <= 57:
        return chr(48 + ((o - 48 + shift) % 10))
    return ch


def _shift_all(ch: str, shift: int) -> str:
    """Shift within all printable ASCII (32-126)."""
    if ch in _ALL_PRINTABLE_SET:
        idx = _ALL_PRINTABLE_IDX[ch]
        return _ALL_PRINTABLE[(idx + shift) % _ALL_PRINTABLE_MOD]
    return ch


def caesar_shift_text(text: str, shift: int, charset_mode: int = 1) -> str:
    """
    Apply Caesar cipher shift to text.

    Args:
        text: Input text
        shift: Number of positions to shift
        charset_mode: 0=alpha only, 1=alphanumeric, 2=all printable ASCII

    Returns:
        Shifted text
    """
    if charset_mode == 0:
        return "".join(_shift_alpha(ch, shift) for ch in text)
    elif charset_mode == 2:
        return "".join(_shift_all(ch, shift) for ch in text)
    else:
        return "".join(_shift_alphanumeric(ch, shift) for ch in text)
