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


# Valid 'a' values: must be coprime with 26
VALID_A = [a for a in range(1, 26) if _mod_inverse(a, 26) is not None]


def affine_decrypt(cipher: str, a: int, b: int) -> str:
    """
    Decrypt an affine cipher. E(x) = (a*x + b) mod 26, so
    D(y) = a_inv * (y - b) mod 26. Only transforms alpha chars.
    """
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
