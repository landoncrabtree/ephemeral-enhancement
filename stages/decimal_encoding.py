"""
Decimal character-code decoding stage.

Decodes text made of decimal character codes back into raw bytes, e.g.
``"072 105 033"`` -> ``b"Hi!"``.

BO3 Revelations chains this between cipher layers: a block cipher emits a
run of zero-padded 3-digit ASCII codes which must be folded back into bytes
before the next base64 layer can be decoded.

Two input shapes are accepted:

* **Delimited** — codes separated by whitespace, commas or semicolons
  (``"072 105"``, ``"072,105"``).
* **Fixed-width** — an unbroken digit run whose length divides evenly by 3
  (``"072105"``), decoded as consecutive 3-digit groups.
"""

from __future__ import annotations

import re

# Codes may be separated by whitespace, commas or semicolons (or a mix).
_DELIMITER_RE = re.compile(r"[\s,;]+")

_FIXED_WIDTH = 3


def decimal_decode(text: str) -> bytes | None:
    """
    Decode decimal character codes into bytes.

    Args:
        text: Decimal codes, either delimited or as fixed-width 3-digit groups

    Returns:
        The decoded bytes, or None if the text is not valid decimal codes
        or any code falls outside the byte range 0-255.
    """
    if not isinstance(text, str):
        return None

    stripped = text.strip()
    if not stripped:
        return None

    tokens = _tokenize(stripped)
    if not tokens:
        return None

    values = []
    for tok in tokens:
        if not tok.isdigit():
            return None
        value = int(tok)
        if value > 0xFF:
            return None
        values.append(value)

    return bytes(values)


def _tokenize(stripped: str) -> list[str] | None:
    """Split input into individual decimal codes, or None if malformed."""
    tokens = [t for t in _DELIMITER_RE.split(stripped) if t]

    # A single unbroken digit run is only meaningful as fixed-width groups.
    if len(tokens) == 1 and len(tokens[0]) > _FIXED_WIDTH:
        run = tokens[0]
        if not run.isdigit() or len(run) % _FIXED_WIDTH != 0:
            return None
        return [
            run[i : i + _FIXED_WIDTH] for i in range(0, len(run), _FIXED_WIDTH)
        ]

    return tokens
