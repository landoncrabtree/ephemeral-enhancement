from __future__ import annotations


def _mod_inverse(a: int, m: int) -> int | None:
    """Extended Euclidean algorithm to find modular inverse of a mod m."""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


# Charset modes: 0=alpha(mod 26), 1=alphanumeric(mod 36), 2=all printable(mod 95)
N_AFFINE_CHARSET_MODES = 3

_ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_ALPHANUM_IDX = {ch: i for i, ch in enumerate(_ALPHANUM)}
_ALPHANUM_MOD = len(_ALPHANUM)  # 62

_ALL_PRINTABLE = [chr(i) for i in range(32, 127)]
_ALL_PRINTABLE_IDX = {ch: i for i, ch in enumerate(_ALL_PRINTABLE)}
_ALL_PRINTABLE_MOD = len(_ALL_PRINTABLE)  # 95


def _valid_a_values(m: int) -> list[int]:
    return [a for a in range(1, m) if _mod_inverse(a, m) is not None]


# Pre-computed valid 'a' values for each modulus
VALID_A_26 = _valid_a_values(26)   # 12 values
VALID_A_62 = _valid_a_values(62)   # alpha+digits+case
VALID_A_95 = _valid_a_values(95)   # all printable

VALID_A_BY_MODE = [VALID_A_26, VALID_A_62, VALID_A_95]
MOD_BY_MODE = [26, _ALPHANUM_MOD, _ALL_PRINTABLE_MOD]

# Total combos per charset mode
N_AFFINE_COMBOS_BY_MODE = [len(va) * m for va, m in zip(VALID_A_BY_MODE, MOD_BY_MODE)]
N_AFFINE_TOTAL = sum(N_AFFINE_COMBOS_BY_MODE)


def affine_decrypt(cipher: str, a: int, b: int, charset_mode: int = 0) -> str:
    """
    Decrypt an affine cipher.

    Args:
        cipher: Ciphertext
        a: Multiplier (must be coprime with modulus)
        b: Shift
        charset_mode: 0=alpha(mod 26), 1=alphanumeric(mod 62), 2=all printable(mod 95)
    """
    if charset_mode == 0:
        return _affine_decrypt_alpha(cipher, a, b)
    elif charset_mode == 1:
        return _affine_decrypt_alphanum(cipher, a, b)
    else:
        return _affine_decrypt_all(cipher, a, b)


def _affine_decrypt_alpha(cipher: str, a: int, b: int) -> str:
    a_inv = _mod_inverse(a, 26)
    if a_inv is None:
        return cipher
    out = []
    for ch in cipher:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            y = ord(ch) - base
            x = (a_inv * (y - b)) % 26
            out.append(chr(base + x))
        else:
            out.append(ch)
    return "".join(out)


def _affine_decrypt_alphanum(cipher: str, a: int, b: int) -> str:
    a_inv = _mod_inverse(a, _ALPHANUM_MOD)
    if a_inv is None:
        return cipher
    out = []
    for ch in cipher:
        if ch in _ALPHANUM_IDX:
            y = _ALPHANUM_IDX[ch]
            x = (a_inv * (y - b)) % _ALPHANUM_MOD
            out.append(_ALPHANUM[x])
        else:
            out.append(ch)
    return "".join(out)


def _affine_decrypt_all(cipher: str, a: int, b: int) -> str:
    a_inv = _mod_inverse(a, _ALL_PRINTABLE_MOD)
    if a_inv is None:
        return cipher
    out = []
    for ch in cipher:
        if ch in _ALL_PRINTABLE_IDX:
            y = _ALL_PRINTABLE_IDX[ch]
            x = (a_inv * (y - b)) % _ALL_PRINTABLE_MOD
            out.append(_ALL_PRINTABLE[x])
        else:
            out.append(ch)
    return "".join(out)
