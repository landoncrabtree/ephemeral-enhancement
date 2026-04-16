"""
Polyalphabetic cipher stages: Vigenere, Beaufort, Autokey.

Uses a 52-character alphabet (A-Za-z) matching Cryptool-online's default,
where uppercase and lowercase are treated as separate characters in a single
continuous alphabet.  Non-alpha characters pass through unchanged, which
preserves base64 digits/symbols when used as a pre-b64 stage.

Alphabet:  A B C ... Z a b c ... z
Index:     0 1 2 ... 25 26 27 28 ... 51
"""

from __future__ import annotations

_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MOD = len(_ALPHA)  # 52
_ORD = {ch: i for i, ch in enumerate(_ALPHA)}


def _key_indices(key: str) -> list[int]:
    """Map key string to list of alphabet indices, skipping non-alpha chars."""
    return [_ORD[ch] for ch in key if ch in _ORD]


def vigenere_decrypt(ciphertext: str, key: str) -> str | None:
    """
    Vigenere decrypt: P_i = (C_i - K_i) mod 52.

    Non-alpha chars in ciphertext pass through and don't advance the key.
    Returns None if key has no alpha characters.
    """
    ki = _key_indices(key)
    if not ki:
        return None
    klen = len(ki)
    out: list[str] = []
    j = 0
    for ch in ciphertext:
        if ch in _ORD:
            ci = _ORD[ch]
            pi = (ci - ki[j % klen]) % _MOD
            out.append(_ALPHA[pi])
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def beaufort_decrypt(ciphertext: str, key: str) -> str | None:
    """
    Beaufort decrypt: P_i = (K_i - C_i) mod 52.

    Beaufort is self-reciprocal (encrypt == decrypt).
    Non-alpha chars pass through.
    Returns None if key has no alpha characters.
    """
    ki = _key_indices(key)
    if not ki:
        return None
    klen = len(ki)
    out: list[str] = []
    j = 0
    for ch in ciphertext:
        if ch in _ORD:
            ci = _ORD[ch]
            pi = (ki[j % klen] - ci) % _MOD
            out.append(_ALPHA[pi])
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey_decrypt(ciphertext: str, key: str) -> str | None:
    """
    Autokey (Vigenere variant) decrypt.

    The key is extended by appending plaintext characters as they are recovered.
    P_i = (C_i - K_i) mod 52, where K extends with recovered plaintext.
    Non-alpha chars pass through and don't advance the key.
    Returns None if key has no alpha characters.
    """
    ki = _key_indices(key)
    if not ki:
        return None
    # Extended key starts as the initial key indices
    ext_key = list(ki)
    out: list[str] = []
    j = 0
    for ch in ciphertext:
        if ch in _ORD:
            ci = _ORD[ch]
            pi = (ci - ext_key[j]) % _MOD
            out.append(_ALPHA[pi])
            ext_key.append(pi)  # extend key with recovered plaintext index
            j += 1
        else:
            out.append(ch)
    return "".join(out)
