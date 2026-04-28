"""
Polyalphabetic cipher stages: Vigenere, Beaufort, Porta, Trithemius.

Each cipher supports two key-stream modes:
  - normal: Key repeats cyclically.
  - autokey: Recovered plaintext extends the initial key (CrypTool "Autokey").

Two alphabet modes:
  - 26-char (default): Case-insensitive A-Z with case preservation.
    Matches standard Cryptool-online behaviour.
  - 52-char: Case-sensitive ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.
    Upper/lowercase are distinct; "Z" + 1 wraps to "a".
    Matches Cryptool-online's 52-char alphabet option (used in BO3 ciphers).

Non-alpha characters pass through unchanged and do not advance the key
position — this preserves base64 structure when used as a pre-b64 stage.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Mode constants
# ---------------------------------------------------------------------------
N_POLYALPHA_MODES = 2
POLYALPHA_MODE_NAMES = ("normal", "autokey")

# ---------------------------------------------------------------------------
# 52-char alphabet helpers
# ---------------------------------------------------------------------------
_ALPHA52 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MOD52 = 52
_ORD52 = {ch: i for i, ch in enumerate(_ALPHA52)}

# ---------------------------------------------------------------------------
# 26-char alphabet helpers
# ---------------------------------------------------------------------------
_MOD26 = 26


def _char_val26(ch: str) -> int:
    """Return 0-25 for A-Za-z, or -1 for non-alpha."""
    o = ord(ch)
    if 65 <= o <= 90:
        return o - 65
    if 97 <= o <= 122:
        return o - 97
    return -1


def _val_to_char26(val: int, preserve_case_from: str) -> str:
    """Convert 0-25 value back to a letter, preserving original case."""
    v = val % _MOD26
    if preserve_case_from.isupper():
        return chr(65 + v)
    return chr(97 + v)


def _key_vals26(key: str) -> list[int]:
    """Extract 0-25 key values, skipping non-alpha."""
    return [_char_val26(ch) for ch in key if _char_val26(ch) >= 0]


def _key_vals52(key: str) -> list[int]:
    """Extract 0-51 key values, skipping non-alpha."""
    return [_ORD52[ch] for ch in key if ch in _ORD52]


# ---------------------------------------------------------------------------
# Vigenere
# ---------------------------------------------------------------------------

def vigenere_decrypt(ciphertext: str, key: str, *, alpha52: bool = False) -> str | None:
    """
    Vigenere decrypt: P = (C - K) mod N.

    Args:
        alpha52: If True, use 52-char case-sensitive alphabet.
    Returns None if key has no alpha characters.
    """
    if alpha52:
        kv = _key_vals52(key)
        if not kv:
            return None
        klen = len(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _ORD52:
                pv = (_ORD52[ch] - kv[j % klen]) % _MOD52
                out.append(_ALPHA52[pv])
                j += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        kv = _key_vals26(key)
        if not kv:
            return None
        klen = len(kv)
        out = []
        j = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                pv = (cv - kv[j % klen]) % _MOD26
                out.append(_val_to_char26(pv, ch))
                j += 1
            else:
                out.append(ch)
        return "".join(out)


# ---------------------------------------------------------------------------
# Beaufort (self-reciprocal)
# ---------------------------------------------------------------------------

def beaufort_decrypt(ciphertext: str, key: str, *, alpha52: bool = False) -> str | None:
    """
    Beaufort decrypt: P = (K - C) mod N.

    Beaufort is self-reciprocal (encrypt == decrypt).
    Returns None if key has no alpha characters.
    """
    if alpha52:
        kv = _key_vals52(key)
        if not kv:
            return None
        klen = len(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _ORD52:
                pv = (kv[j % klen] - _ORD52[ch]) % _MOD52
                out.append(_ALPHA52[pv])
                j += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        kv = _key_vals26(key)
        if not kv:
            return None
        klen = len(kv)
        out = []
        j = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                pv = (kv[j % klen] - cv) % _MOD26
                out.append(_val_to_char26(pv, ch))
                j += 1
            else:
                out.append(ch)
        return "".join(out)


# ---------------------------------------------------------------------------
# Autokey variants (plaintext extends the key)
# ---------------------------------------------------------------------------

def autokey_decrypt(ciphertext: str, key: str, *, alpha52: bool = False) -> str | None:
    """
    Vigenere autokey decrypt: P = (C - K) mod N, plaintext extends key.

    Returns None if key has no alpha characters.
    """
    if alpha52:
        kv = _key_vals52(key)
        if not kv:
            return None
        ext = list(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _ORD52:
                cv = _ORD52[ch]
                pv = (cv - ext[j]) % _MOD52
                out.append(_ALPHA52[pv])
                ext.append(pv)
                j += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        kv = _key_vals26(key)
        if not kv:
            return None
        ext = list(kv)
        out = []
        j = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                pv = (cv - ext[j]) % _MOD26
                out.append(_val_to_char26(pv, ch))
                ext.append(pv)
                j += 1
            else:
                out.append(ch)
        return "".join(out)


def beaufort_autokey_decrypt(ciphertext: str, key: str, *, alpha52: bool = False) -> str | None:
    """
    Beaufort autokey decrypt: P = (K - C) mod N, plaintext extends key.

    Returns None if key has no alpha characters.
    """
    if alpha52:
        kv = _key_vals52(key)
        if not kv:
            return None
        ext = list(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _ORD52:
                cv = _ORD52[ch]
                pv = (ext[j] - cv) % _MOD52
                out.append(_ALPHA52[pv])
                ext.append(pv)
                j += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        kv = _key_vals26(key)
        if not kv:
            return None
        ext = list(kv)
        out = []
        j = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                pv = (ext[j] - cv) % _MOD26
                out.append(_val_to_char26(pv, ch))
                ext.append(pv)
                j += 1
            else:
                out.append(ch)
        return "".join(out)


def porta_autokey_decrypt(ciphertext: str, key: str, *, alpha52: bool = False) -> str | None:
    """
    Porta autokey decrypt: Porta substitution with plaintext extending key.

    Recovered plaintext values are appended to the key stream (raw values;
    they are reduced by // 2 when applied as Porta pair indices).

    Returns None if key has no alpha characters.
    """
    if alpha52:
        kv = _key_vals52(key)
        if not kv:
            return None
        ext = list(kv)
        half = _MOD52 // 2  # 26
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _ORD52:
                cv = _ORD52[ch]
                k = ext[j] // 2
                if cv < half:
                    pv = half + (cv - k + half) % half
                else:
                    pv = (cv - half + k) % half
                out.append(_ALPHA52[pv])
                ext.append(pv)
                j += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        kv = _key_vals26(key)
        if not kv:
            return None
        ext = list(kv)
        half = 13
        out = []
        j = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                k = ext[j] // 2
                if cv < half:
                    pv = half + (cv - k + half) % half
                else:
                    pv = (cv - half + k) % half
                out.append(_val_to_char26(pv, ch))
                ext.append(pv)
                j += 1
            else:
                out.append(ch)
        return "".join(out)


# ---------------------------------------------------------------------------
# Porta (self-reciprocal paired substitution)
# ---------------------------------------------------------------------------

def porta_decrypt(ciphertext: str, key: str, *, alpha52: bool = False) -> str | None:
    """
    Porta cipher (self-reciprocal), case-preserving (26-char) or case-sensitive (52-char).

    Splits alphabet into two halves.  Key value k = floor(key_char_value / 2)
    determines a rotation of the second half.  First-half chars map to the
    shifted second half and vice-versa.

    Returns None if key has no alpha characters.
    """
    if alpha52:
        kv = _key_vals52(key)
        if not kv:
            return None
        klen = len(kv)
        half = _MOD52 // 2  # 26
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _ORD52:
                cv = _ORD52[ch]
                k = kv[j % klen] // 2
                if cv < half:
                    pv = half + (cv - k + half) % half
                else:
                    pv = (cv - half + k) % half
                out.append(_ALPHA52[pv])
                j += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        kv = _key_vals26(key)
        if not kv:
            return None
        klen = len(kv)
        half = 13
        out = []
        j = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                k = kv[j % klen] // 2
                if cv < half:
                    pv = half + (cv - k + half) % half
                else:
                    pv = (cv - half + k) % half
                out.append(_val_to_char26(pv, ch))
                j += 1
            else:
                out.append(ch)
        return "".join(out)


# ---------------------------------------------------------------------------
# Trithemius (keyless — shift = character position)
# ---------------------------------------------------------------------------

def trithemius_decrypt(ciphertext: str, *, alpha52: bool = False) -> str:
    """
    Trithemius decrypt: P = (C - position) mod N.

    Position increments for each alpha character; non-alpha passes through.
    Keyless cipher — no dictionary key needed.
    """
    if alpha52:
        out: list[str] = []
        pos = 0
        for ch in ciphertext:
            if ch in _ORD52:
                pv = (_ORD52[ch] - pos) % _MOD52
                out.append(_ALPHA52[pv])
                pos += 1
            else:
                out.append(ch)
        return "".join(out)
    else:
        out = []
        pos = 0
        for ch in ciphertext:
            cv = _char_val26(ch)
            if cv >= 0:
                pv = (cv - pos) % _MOD26
                out.append(_val_to_char26(pv, ch))
                pos += 1
            else:
                out.append(ch)
        return "".join(out)
