#!/usr/bin/env python3
"""
Sweep symmetric ciphers that libmcrypt does not provide.

libmcrypt ships blowfish, cast-128, cast-256, des, gost, loki97, rc2,
rijndael-*, saferplus, serpent, tripledes, twofish and xtea, all of which the
pipeline already covers. This script fills the gaps: RC5, RC6, Camellia, IDEA,
SEED, Salsa20 and ChaCha20.

Key and IV handling mirrors the conventions that solved the Revelations
ciphers — raw/md5/sha1/sha256 key derivation, and an IV of ASCII "0" (0x30)
repeated to the block size, alongside null and prepended IVs.

Usage:
    python scripts/sweep_modern.py <ciphertext-file> [threshold]
"""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stages.common import combined_score  # noqa: E402

WORDS = [
    "TheGiant", "ElGigante", "ElGiganteX4", "TheGiantTheGiantTheGiantTheGiant",
    "Zombies", "Zombie", "Giant", "DerRiese", "Riese", "Group935", "Maxis",
    "Richtofen", "Samantha", "Primis", "115", "Element115", "Divinium",
    "TryThis",
]


def key_variants(word: str) -> list[str]:
    return list(dict.fromkeys([word, word.lower(), word.upper(), word.title()]))


def derive(word: str, size: int) -> list[tuple[str, bytes]]:
    """Key derivations matching stages/key_derivation.py, trimmed to `size`."""
    raw = word.encode()
    out = [
        ("raw-null", raw[:size].ljust(size, b"\x00")),
        ("raw-zero", raw[:size].ljust(size, b"0")),
        ("md5", hashlib.md5(raw).digest()[:size].ljust(size, b"\x00")),
        ("sha1", hashlib.sha1(raw).digest()[:size].ljust(size, b"\x00")),
        ("sha256", hashlib.sha256(raw).digest()[:size].ljust(size, b"\x00")),
    ]
    return out


# ---------------------------------------------------------------------------
# Pure-Python RC5 / RC6 (no maintained Python binding ships these)
# ---------------------------------------------------------------------------

def _rotl(x: int, n: int, w: int = 32) -> int:
    n %= w
    return ((x << n) | (x >> (w - n))) & 0xFFFFFFFF


def _rotr(x: int, n: int, w: int = 32) -> int:
    n %= w
    return ((x >> n) | (x << (w - n))) & 0xFFFFFFFF


def _rc5_schedule(key: bytes, rounds: int = 12) -> list[int]:
    P, Q = 0xB7E15163, 0x9E3779B9
    u, b = 4, len(key)
    c = max(1, (b + u - 1) // u)
    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) + key[i]) & 0xFFFFFFFF
    t = 2 * (rounds + 1)
    S = [(P + i * Q) & 0xFFFFFFFF for i in range(t)]
    a = bb = i = j = 0
    for _ in range(3 * max(t, c)):
        a = S[i] = _rotl((S[i] + a + bb) & 0xFFFFFFFF, 3)
        bb = L[j] = _rotl((L[j] + a + bb) & 0xFFFFFFFF, (a + bb) & 31)
        i, j = (i + 1) % t, (j + 1) % c
    return S


def rc5_decrypt_block(block: bytes, S: list[int], rounds: int = 12) -> bytes:
    a = int.from_bytes(block[:4], "little")
    b = int.from_bytes(block[4:8], "little")
    for i in range(rounds, 0, -1):
        b = _rotr((b - S[2 * i + 1]) & 0xFFFFFFFF, a & 31) ^ a
        a = _rotr((a - S[2 * i]) & 0xFFFFFFFF, b & 31) ^ b
    b = (b - S[1]) & 0xFFFFFFFF
    a = (a - S[0]) & 0xFFFFFFFF
    return a.to_bytes(4, "little") + b.to_bytes(4, "little")


def _rc6_schedule(key: bytes, rounds: int = 20) -> list[int]:
    P, Q = 0xB7E15163, 0x9E3779B9
    u, b = 4, len(key)
    c = max(1, (b + u - 1) // u)
    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) + key[i]) & 0xFFFFFFFF
    t = 2 * rounds + 4
    S = [(P + i * Q) & 0xFFFFFFFF for i in range(t)]
    a = bb = i = j = 0
    for _ in range(3 * max(t, c)):
        a = S[i] = _rotl((S[i] + a + bb) & 0xFFFFFFFF, 3)
        bb = L[j] = _rotl((L[j] + a + bb) & 0xFFFFFFFF, (a + bb) & 31)
        i, j = (i + 1) % t, (j + 1) % c
    return S


def rc6_decrypt_block(block: bytes, S: list[int], rounds: int = 20) -> bytes:
    a, b, c, d = (int.from_bytes(block[i : i + 4], "little") for i in range(0, 16, 4))
    c = (c - S[2 * rounds + 3]) & 0xFFFFFFFF
    a = (a - S[2 * rounds + 2]) & 0xFFFFFFFF
    for i in range(rounds, 0, -1):
        a, b, c, d = d, a, b, c
        u = _rotl((d * (2 * d + 1)) & 0xFFFFFFFF, 5)
        t = _rotl((b * (2 * b + 1)) & 0xFFFFFFFF, 5)
        c = (_rotr(c - S[2 * i + 1] & 0xFFFFFFFF, t & 31)) ^ u
        a = (_rotr(a - S[2 * i] & 0xFFFFFFFF, u & 31)) ^ t
    d = (d - S[1]) & 0xFFFFFFFF
    b = (b - S[0]) & 0xFFFFFFFF
    return b"".join(x.to_bytes(4, "little") for x in (a, b, c, d))


def _ecb_cbc(data: bytes, decrypt_block, block_size: int, iv: bytes | None):
    out, prev = bytearray(), iv
    for off in range(0, len(data) - block_size + 1, block_size):
        blk = data[off : off + block_size]
        dec = decrypt_block(blk)
        if prev is not None:
            dec = bytes(x ^ y for x, y in zip(dec, prev))
            prev = blk
        out += dec
    return bytes(out)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "../thegiant.txt"
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 1.45

    text = "".join(Path(path).read_text().split())
    ct = base64.b64decode(text + "=" * ((-len(text)) % 4))
    print(f"[sweep] {path}: {len(ct)} bytes, threshold {threshold}")

    keys = [v for w in WORDS for v in key_variants(w)]
    hits: list[tuple[float, str, bytes]] = []

    def check(label: str, pt: bytes | None) -> None:
        if pt and combined_score(pt) >= threshold:
            hits.append((combined_score(pt), label, pt[:120]))

    # --- RC5 (64-bit block) and RC6 (128-bit block), pure Python ---
    for word in keys:
        for dname, kb in derive(word, 16):
            try:
                S5 = _rc5_schedule(kb)
                for ivl, iv in (("ecb", None), ("cbc-zero", b"0" * 8), ("cbc-null", b"\x00" * 8)):
                    check(
                        f"RC5/{dname}/{ivl}/{word}",
                        _ecb_cbc(ct, lambda b: rc5_decrypt_block(b, S5), 8, iv),
                    )
                S6 = _rc6_schedule(kb)
                for ivl, iv in (("ecb", None), ("cbc-zero", b"0" * 16), ("cbc-null", b"\x00" * 16)):
                    check(
                        f"RC6/{dname}/{ivl}/{word}",
                        _ecb_cbc(ct, lambda b: rc6_decrypt_block(b, S6), 16, iv),
                    )
            except Exception:
                pass

    # --- Camellia, IDEA, SEED, CAST5 via cryptography ---
    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        specs = [
            ("Camellia", decrepit.Camellia, 16, (16, 24, 32)),
            ("IDEA", decrepit.IDEA, 8, (16,)),
            ("SEED", decrepit.SEED, 16, (16,)),
            ("CAST5", decrepit.CAST5, 8, (16,)),
        ]
        for name, algo, bs, sizes in specs:
            for word in keys:
                for size in sizes:
                    for dname, kb in derive(word, size):
                        for mname, mode in (
                            ("ecb", modes.ECB()),
                            ("cbc-zero", modes.CBC(b"0" * bs)),
                            ("cbc-null", modes.CBC(b"\x00" * bs)),
                            ("cfb8-zero", modes.CFB8(b"0" * bs)),
                            ("ofb-zero", modes.OFB(b"0" * bs)),
                        ):
                            try:
                                d = Cipher(algo(kb), mode).decryptor()
                                usable = len(ct) - (len(ct) % bs) if mname.startswith(("ecb", "cbc")) else len(ct)
                                check(f"{name}/{dname}/{mname}/{word}", d.update(ct[:usable]) + d.finalize())
                            except Exception:
                                pass
    except ImportError:
        print("[warn] cryptography not installed; skipping Camellia/IDEA/SEED/CAST5")

    # --- Salsa20 and ChaCha20 stream ciphers ---
    try:
        from Crypto.Cipher import ChaCha20, Salsa20

        for word in keys:
            for dname, kb in derive(word, 32):
                for nl in (8, 12):
                    for nname, nonce in (("zero", b"0" * nl), ("null", b"\x00" * nl), ("pre", ct[:nl])):
                        body = ct[nl:] if nname == "pre" else ct
                        try:
                            check(f"Salsa20/{dname}/{nname}{nl}/{word}",
                                  Salsa20.new(key=kb, nonce=nonce[:8]).decrypt(body))
                        except Exception:
                            pass
                        try:
                            check(f"ChaCha20/{dname}/{nname}{nl}/{word}",
                                  ChaCha20.new(key=kb, nonce=nonce).decrypt(body))
                        except Exception:
                            pass
    except ImportError:
        print("[warn] pycryptodome not installed; skipping Salsa20/ChaCha20")

    hits.sort(reverse=True, key=lambda h: h[0])
    print(f"\n[sweep] {len(hits)} candidates at or above {threshold}")
    for score, label, preview in hits[:25]:
        print(f"{score:.3f}  {label}\n        {preview!r}")
    if not hits:
        print("[sweep] no candidates")


if __name__ == "__main__":
    main()
