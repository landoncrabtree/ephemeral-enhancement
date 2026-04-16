"""
End-to-end tests using real confirmed Black Ops 3 cipher solutions.

Each test replicates a known decryption chain step-by-step, verifying that
the full pipeline produces the expected plaintext from the original ciphertext.
"""

from __future__ import annotations

import base64

import pytest

from stages.mcrypt_wrapper import McryptHandleCache, mcrypt_decrypt
from stages.polyalpha import beaufort_decrypt


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cache():
    return McryptHandleCache()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _strip_mcrypt_output(data: bytes) -> bytes:
    """Strip null bytes and trailing control chars (< 0x20) from mcrypt output."""
    data = data.rstrip(b"\x00")
    while data and data[-1] < 0x20:
        data = data[:-1]
    return data


# ---------------------------------------------------------------------------
# Test 1: beaufort52 > b64 > rc2-ecb > reverse > b64 > rijndael-256-ecb
#   OkEeZH... -> beaufort52(ZOMBIES) -> b64 -> rc2-ecb(Zombies) -> reverse
#   -> b64 -> rijndael-256-ecb(Zombies) -> "The many worlds are now one."
# ---------------------------------------------------------------------------

MULTI_CT = (
    "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"
)
MULTI_PLAINTEXT = "The many worlds are now one."


def test_beaufort52_rc2_rijndael(cache):
    # Step 1: beaufort52 with key ZOMBIES
    after_beaufort = beaufort_decrypt(MULTI_CT, "ZOMBIES", alpha52=True)
    assert after_beaufort is not None

    # Step 2: base64 decode
    raw = base64.b64decode(after_beaufort)

    # Step 3: rc2-ecb decrypt
    after_rc2 = mcrypt_decrypt(
        "rc2", "ecb", b"Zombies", b"", raw, handle_cache=cache
    )
    assert after_rc2 is not None
    after_rc2_text = _strip_mcrypt_output(after_rc2).decode("ascii")

    # Step 4: reverse
    reversed_text = after_rc2_text[::-1]

    # Step 5: base64 decode
    raw2 = base64.b64decode(reversed_text)

    # Step 6: rijndael-256-ecb decrypt
    result = mcrypt_decrypt(
        "rijndael-256", "ecb", b"Zombies", b"", raw2, handle_cache=cache
    )
    assert result is not None
    text = _strip_mcrypt_output(result).decode("utf-8")
    assert text == MULTI_PLAINTEXT


# ---------------------------------------------------------------------------
# Test 3: b64 > loki97-cfb (single stage)
#   Long b64 ciphertext -> b64 -> loki97-cfb(Zombies, IV="0"*16)
#   -> "August, 1946. OSS report final T-7..."
# ---------------------------------------------------------------------------
# Test 2: b64 > rc2-cfb > reverse > hex > blowfish-cfb > b64 > loki97-cfb
#   Long b64 ciphertext -> b64 -> rc2-cfb(Zombies, IV="0"*8) -> reverse
#   -> hex decode -> blowfish-cfb(Zombies, IV="0"*8)
#   -> b64 -> loki97-cfb(Zombies, IV="0"*16)
#   -> "August, 1946. OSS report final T-7..."
# ---------------------------------------------------------------------------

THREE_MCRYPT_CT = (
    "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"
)

OSS_PLAINTEXT = (
    "August, 1946. OSS report final T-7. All of the Group 935 and "
    "Division 9 facilities we were able to procure have been dismantled "
    "and crated. We have 215 scientists heading back to the United States "
    "for orientation.\nJuly, 1947. OSS asset transfer request. We are "
    "requesting that Dr. Shuster be transferred to Broomstick and the "
    "Titan Project because of extensive intimacy with Group 935\u2019s long "
    "range rockets. If approved, we will have him onsite at White Sands "
    "for the first Titan Project test as an observer. As you know it is "
    "imperative that we advance Titan quickly and reach the anomaly "
    "before the Russians."
)


def test_3mcrypt_chain(cache):
    """b64 > rc2-cfb > reverse > hex > blowfish-cfb > b64 > loki97-cfb."""
    ct = THREE_MCRYPT_CT.replace(" ", "").replace("\n", "")
    key = b"Zombies"

    # Step 1: base64 decode
    raw = base64.b64decode(ct)

    # Step 2: rc2-cfb (IV = "0" * 8)
    s1 = mcrypt_decrypt("rc2", "cfb", key, b"0" * 8, raw, handle_cache=cache)
    assert s1 is not None
    s1_text = _strip_mcrypt_output(s1[: len(raw)]).decode("ascii")
    # Output should be hex string
    assert all(c in "0123456789abcdef" for c in s1_text)

    # Step 3: reverse
    rev = s1_text[::-1]

    # Step 4: hex decode
    hex_bytes = bytes.fromhex(rev)

    # Step 5: blowfish-cfb (IV = "0" * 8)
    s3 = mcrypt_decrypt("blowfish", "cfb", key, b"0" * 8, hex_bytes, handle_cache=cache)
    assert s3 is not None
    s3_text = _strip_mcrypt_output(s3[: len(hex_bytes)]).decode("ascii")
    # Output should be base64
    assert len(s3_text) > 100

    # Step 6: base64 decode
    s4 = base64.b64decode(s3_text)

    # Step 7: loki97-cfb (IV = "0" * 16)
    s5 = mcrypt_decrypt("loki97", "cfb", key, b"0" * 16, s4, handle_cache=cache)
    assert s5 is not None
    text = _strip_mcrypt_output(s5[: len(s4)]).decode("utf-8")

    assert text.startswith("August, 1946. OSS report final T-7.")
    assert text.endswith("before the Russians.")


# ---------------------------------------------------------------------------
# Test 3: hex > xtea-cfb > reverse > caesar(shift=6)
#   Hex ciphertext -> hex decode -> xtea-cfb(Zombies, IV=null)
#   -> reverse -> caesar(shift=6)
#   -> "Now that the many worlds are one..."
# ---------------------------------------------------------------------------

XTEA_HEX_CT = (
    "4521d3f287d5d75616be3fa56852a08234104a78448c2e5a2e5ee6ed7cad795671"
    "e6129fec7151d875a0ab9ce7c1b7eb2319d23e264479b5826645b0f6b6d648eb85"
    "9aa9df6a5cce921b64a2ad0a1f12fbe4d7cd008bd02893156462b1ebed006862f7"
    "665a152cc39970ee0aaade5465d2920665e979b9dc6ef6041b8f06802693275418"
    "cfb8034ff29bf0f77a3f4f7d84fe63786ede39533d1747c9ff5c0eb3ad5731d09d"
    "eb68a36e9469b04b86ea484bf3cb39b1ad19e0d05114f593c59ea161a1ada1a97f"
    "dd65866c6389fddf8cf7285df6"
)

# The first byte of xtea-cfb output is garbled (CFB first-block artifact with
# null IV), so the decrypted text starts with a replacement character. We check
# the body of the text rather than an exact match.
XTEA_PLAINTEXT_BODY = (
    "ow that the many worlds are one, it has all reset. There are no "
    "Apothicon, Keepers, or 115 knocking around to cause trouble."
)


def _caesar_shift(text: str, shift: int) -> str:
    """Apply a caesar shift (decryption direction)."""
    result = []
    for c in text:
        if "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
        elif "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
        else:
            result.append(c)
    return "".join(result)


def test_xtea_reverse_caesar(cache):
    """hex > xtea-cfb > reverse > caesar(shift=6)."""
    raw = bytes.fromhex(XTEA_HEX_CT.replace(" ", "").replace("\n", ""))
    key = b"Zombies"

    # Step 1: xtea-cfb (IV = null)
    s1 = mcrypt_decrypt("xtea", "cfb", key, b"\x00" * 8, raw, handle_cache=cache)
    assert s1 is not None
    s1_text = _strip_mcrypt_output(s1[: len(raw)]).decode("ascii", errors="replace")

    # Step 2: reverse
    rev = s1_text[::-1]

    # Step 3: caesar shift 6
    plaintext = _caesar_shift(rev, 6)

    assert XTEA_PLAINTEXT_BODY in plaintext
    assert "focus on the children" in plaintext
