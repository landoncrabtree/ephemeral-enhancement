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

# Alphabet modes. Index 0 is the 26-char alphabet so that alphabet 0 + mode 0
# (normal) still occupies the start of the search space.
ALPHABET_26 = 0
ALPHABET_52 = 1
ALPHABET_B64 = 2
ALPHABET_ALNUM62 = 3
ALPHABET_ALL95 = 4
N_POLYALPHA_ALPHABETS = 5
POLYALPHA_ALPHABET_NAMES = (
    "alpha26",
    "alpha52",
    "b64",
    "alnum62",
    "all_printable",
)

# ---------------------------------------------------------------------------
# 52-char alphabet helpers
# ---------------------------------------------------------------------------
_ALPHA52 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MOD52 = 52
_ORD52 = {ch: i for i, ch in enumerate(_ALPHA52)}

# ---------------------------------------------------------------------------
# Extended fixed alphabets
# ---------------------------------------------------------------------------
# Standard base64 alphabet (RFC 4648).  A polyalphabetic layer over this
# alphabet maps base64 onto base64, so the ciphertext stays decodable — the
# natural construction when a puzzle wraps a b64 blob in a classical cipher.
_ALPHA_B64 = _ALPHA52 + "0123456789+/"
# Alphanumeric only: shifts letters and digits but leaves '+' and '/' in place.
_ALPHA_ALNUM62 = _ALPHA52 + "0123456789"
# Every printable ASCII character (space through '~'), matching the
# all-printable charset used by the Caesar/Affine stages.
_ALPHA_ALL95 = "".join(chr(i) for i in range(32, 127))

# Fixed (non case-preserving) alphabets, keyed by alphabet index.  Index 0 is
# absent because the 26-char mode preserves the case of each source character
# instead of treating upper/lower as distinct symbols.
_FIXED_ALPHABETS: dict[int, tuple[str, dict[str, int], int]] = {
    ALPHABET_52: (_ALPHA52, _ORD52, _MOD52),
    ALPHABET_B64: (
        _ALPHA_B64,
        {ch: i for i, ch in enumerate(_ALPHA_B64)},
        len(_ALPHA_B64),
    ),
    ALPHABET_ALNUM62: (
        _ALPHA_ALNUM62,
        {ch: i for i, ch in enumerate(_ALPHA_ALNUM62)},
        len(_ALPHA_ALNUM62),
    ),
    ALPHABET_ALL95: (
        _ALPHA_ALL95,
        {ch: i for i, ch in enumerate(_ALPHA_ALL95)},
        len(_ALPHA_ALL95),
    ),
}


def _resolve_alphabet(
    alpha52: bool, alphabet: int | None
) -> tuple[str, dict[str, int], int] | None:
    """
    Resolve the alphabet selection to a fixed-alphabet table.

    ``alphabet`` takes precedence when given; ``alpha52`` is the older boolean
    form kept so existing callers keep working. Returns None for the 26-char
    case-preserving mode, which is handled separately.
    """
    if alphabet is None:
        alphabet = ALPHABET_52 if alpha52 else ALPHABET_26
    return _FIXED_ALPHABETS.get(alphabet)

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
    return [_O[ch] for ch in key if ch in _O]


# ---------------------------------------------------------------------------
# Vigenere
# ---------------------------------------------------------------------------

def vigenere_decrypt(ciphertext: str, key: str, *, alpha52: bool = False,
        alphabet: int | None = None) -> str | None:
    """
    Vigenere decrypt: P = (C - K) mod N.

    Args:
        alpha52: If True, use 52-char case-sensitive alphabet.
    Returns None if key has no alpha characters.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        kv = [_O[c] for c in key if c in _O]
        if not kv:
            return None
        klen = len(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _O:
                pv = (_O[ch] - kv[j % klen]) % _M
                out.append(_A[pv])
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

def beaufort_decrypt(ciphertext: str, key: str, *, alpha52: bool = False,
        alphabet: int | None = None) -> str | None:
    """
    Beaufort decrypt: P = (K - C) mod N.

    Beaufort is self-reciprocal (encrypt == decrypt).
    Returns None if key has no alpha characters.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        kv = [_O[c] for c in key if c in _O]
        if not kv:
            return None
        klen = len(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _O:
                pv = (kv[j % klen] - _O[ch]) % _M
                out.append(_A[pv])
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

def autokey_decrypt(ciphertext: str, key: str, *, alpha52: bool = False,
        alphabet: int | None = None) -> str | None:
    """
    Vigenere autokey decrypt: P = (C - K) mod N, plaintext extends key.

    Returns None if key has no alpha characters.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        kv = [_O[c] for c in key if c in _O]
        if not kv:
            return None
        ext = list(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _O:
                cv = _O[ch]
                pv = (cv - ext[j]) % _M
                out.append(_A[pv])
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


def beaufort_autokey_decrypt(ciphertext: str, key: str, *, alpha52: bool = False,
        alphabet: int | None = None) -> str | None:
    """
    Beaufort autokey decrypt: P = (K - C) mod N, plaintext extends key.

    Returns None if key has no alpha characters.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        kv = [_O[c] for c in key if c in _O]
        if not kv:
            return None
        ext = list(kv)
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _O:
                cv = _O[ch]
                pv = (ext[j] - cv) % _M
                out.append(_A[pv])
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


def porta_autokey_decrypt(ciphertext: str, key: str, *, alpha52: bool = False,
        alphabet: int | None = None) -> str | None:
    """
    Porta autokey decrypt: Porta substitution with plaintext extending key.

    Recovered plaintext values are appended to the key stream (raw values;
    they are reduced by // 2 when applied as Porta pair indices).

    Returns None if key has no alpha characters.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        kv = [_O[c] for c in key if c in _O]
        if not kv:
            return None
        ext = list(kv)
        half = _M // 2  # 26
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _O:
                cv = _O[ch]
                k = ext[j] // 2
                if cv < half:
                    pv = half + (cv - k + half) % half
                else:
                    pv = (cv - half + k) % half
                out.append(_A[pv])
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

def porta_decrypt(ciphertext: str, key: str, *, alpha52: bool = False,
        alphabet: int | None = None) -> str | None:
    """
    Porta cipher (self-reciprocal), case-preserving (26-char) or case-sensitive (52-char).

    Splits alphabet into two halves.  Key value k = floor(key_char_value / 2)
    determines a rotation of the second half.  First-half chars map to the
    shifted second half and vice-versa.

    Returns None if key has no alpha characters.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        kv = [_O[c] for c in key if c in _O]
        if not kv:
            return None
        klen = len(kv)
        half = _M // 2  # 26
        out: list[str] = []
        j = 0
        for ch in ciphertext:
            if ch in _O:
                cv = _O[ch]
                k = kv[j % klen] // 2
                if cv < half:
                    pv = half + (cv - k + half) % half
                else:
                    pv = (cv - half + k) % half
                out.append(_A[pv])
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

def trithemius_decrypt(ciphertext: str, *, alpha52: bool = False,
                       alphabet: int | None = None) -> str:
    """
    Trithemius decrypt: P = (C - position) mod N.

    Position increments for each alpha character; non-alpha passes through.
    Keyless cipher — no dictionary key needed.
    """
    _tbl = _resolve_alphabet(alpha52, alphabet)
    if _tbl is not None:
        _A, _O, _M = _tbl
        out: list[str] = []
        pos = 0
        for ch in ciphertext:
            if ch in _O:
                pv = (_O[ch] - pos) % _M
                out.append(_A[pv])
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
