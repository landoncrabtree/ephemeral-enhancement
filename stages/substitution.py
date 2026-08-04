"""
Monoalphabetic substitution stages: Atbash and keyword substitution.

Both map each character to another *within the same alphabet*, so when the
alphabet is a subset of base64 the output stays valid base64 and a downstream
``b64`` stage can still decode it.

Alphabet selection is shared with the polyalphabetic stages
(``stages/polyalpha.py``) so ``atbash64`` and ``beaufort64`` mean the same
thing — see ``POLYALPHA_ALPHABET_NAMES``.
"""

from __future__ import annotations

from stages.polyalpha import (  # noqa: F401  (re-exported for callers)
    ALPHABET_26,
    ALPHABET_52,
    ALPHABET_ALL95,
    ALPHABET_ALNUM62,
    ALPHABET_B64,
    N_POLYALPHA_ALPHABETS,
    POLYALPHA_ALPHABET_NAMES,
    resolve_alphabet,
)


def atbash_decrypt(
    ciphertext: str, *, alphabet: int | None = None
) -> str | None:
    """
    Atbash: map each symbol to its mirror in the alphabet (P = N - 1 - C).

    Self-reciprocal (encrypt == decrypt) and keyless. Characters outside the
    selected alphabet pass through unchanged, which preserves base64 structure
    for a downstream ``b64`` stage.

    Args:
        ciphertext: Text to transform
        alphabet: Alphabet index; defaults to the 26-char alphabet

    Returns:
        The transformed text.
    """
    table = resolve_alphabet(False, alphabet)
    if table is None:
        # 26-char mode mirrors A-Z and a-z while preserving case.
        out: list[str] = []
        for ch in ciphertext:
            if "A" <= ch <= "Z":
                out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
            elif "a" <= ch <= "z":
                out.append(chr(ord("z") - (ord(ch) - ord("a"))))
            else:
                out.append(ch)
        return "".join(out)

    alpha, order, mod = table
    return "".join(
        alpha[mod - 1 - order[ch]] if ch in order else ch for ch in ciphertext
    )


def build_keyed_alphabet(key: str, alpha: str) -> str:
    """
    Build a substitution alphabet from a keyword.

    The key's characters come first (duplicates dropped, and only characters
    that exist in `alpha` are used), then the remaining alphabet in order.
    ``"TheGiant"`` over A-Z gives ``THEGIANBCDFJKLMOPQRSUVWXYZ``.
    """
    seen: set[str] = set()
    result: list[str] = []
    for ch in key:
        if ch in alpha and ch not in seen:
            seen.add(ch)
            result.append(ch)
    for ch in alpha:
        if ch not in seen:
            result.append(ch)
    return "".join(result)


def keyword_decrypt(
    ciphertext: str, key: str, *, alphabet: int | None = None
) -> str | None:
    """
    Keyword (keyed monoalphabetic) substitution decrypt.

    Encryption maps the plain alphabet onto a keyword-derived alphabet, so
    decryption maps the keyed alphabet back onto the plain one.

    Args:
        ciphertext: Text to decrypt
        key: Keyword seeding the substitution alphabet
        alphabet: Alphabet index; defaults to the 26-char alphabet

    Returns:
        Decrypted text, or None when the key contributes no usable characters.
    """
    table = resolve_alphabet(False, alphabet)
    if table is None:
        plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        keyed = build_keyed_alphabet(key.upper(), plain)
        if keyed == plain and not any(c in plain for c in key.upper()):
            return None
        mapping = {k: p for k, p in zip(keyed, plain)}
        out: list[str] = []
        for ch in ciphertext:
            upper = ch.upper()
            if upper in mapping:
                sub = mapping[upper]
                out.append(sub if ch.isupper() else sub.lower())
            else:
                out.append(ch)
        return "".join(out)

    alpha, _order, _mod = table
    if not any(ch in alpha for ch in key):
        return None
    keyed = build_keyed_alphabet(key, alpha)
    mapping = {k: p for k, p in zip(keyed, alpha)}
    return "".join(mapping.get(ch, ch) for ch in ciphertext)
