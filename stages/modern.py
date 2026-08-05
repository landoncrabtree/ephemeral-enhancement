"""
Standard (non-mcrypt) symmetric cipher stages via pycryptodome.

These are **not** duplicates of the mcrypt stages. libmcrypt differs from every
other implementation in two ways that change the plaintext:

1. **CFB width.** mcrypt's ``cfb`` is 8-bit CFB, one byte per block operation.
   Standard AES-CFB feeds back a full 128-bit block, and standard DES-CFB a
   64-bit one. ``rijndael-128-cfb`` and ``std-aes-128-cfb`` therefore produce
   different output from the same key and IV.
2. **Padding.** mcrypt zero-pads to the block size; the rest of the world uses
   PKCS#7. A PKCS#7-padded ciphertext decrypted with mcrypt semantics leaves a
   trailing pad block, and vice versa.

So a message encrypted by, say, PHP's ``openssl_encrypt`` is not reachable
through the mcrypt stages at all. This module adds that coverage, including
CTR and GCM, which libmcrypt's CFB/OFB set does not provide.

Stage names are prefixed ``std-`` to avoid colliding with the mcrypt registry:
``std-aes-128-cbc``, ``std-des-cfb``, ``std-3des-ecb`` and so on.
"""

from __future__ import annotations

from dataclasses import dataclass

# Modes needing an IV or nonce.
IV_MODES = frozenset({"cbc", "cfb", "cfb8", "ofb", "ctr"})

# (family, key_size, block_size)
_ALGORITHMS = [
    ("aes-128", 16, 16),
    ("aes-192", 24, 16),
    ("aes-256", 32, 16),
    ("des", 8, 8),
    ("3des", 24, 8),
]

# cfb  = full-block CFB (128-bit for AES, 64-bit for DES) — the standard form
# cfb8 = 8-bit CFB, matching mcrypt, kept so the two can be compared directly
_MODES = ["ecb", "cbc", "cfb", "cfb8", "ofb", "ctr"]


@dataclass(frozen=True)
class ModernStageInfo:
    """Metadata for a registered standard-crypto stage."""

    stage_name: str
    family: str
    key_size: int
    block_size: int
    mode: str
    needs_iv: bool

    @property
    def iv_size(self) -> int:
        return self.block_size if self.needs_iv else 0


def _build_registry() -> dict[str, ModernStageInfo]:
    registry: dict[str, ModernStageInfo] = {}
    for family, key_size, block_size in _ALGORITHMS:
        for mode in _MODES:
            name = f"std-{family}-{mode}"
            registry[name] = ModernStageInfo(
                stage_name=name,
                family=family,
                key_size=key_size,
                block_size=block_size,
                mode=mode,
                needs_iv=mode in IV_MODES,
            )
    return registry


_REGISTRY = _build_registry()


def get_all_modern_stage_names() -> set[str]:
    return set(_REGISTRY)


def get_modern_stage_info(name: str) -> ModernStageInfo | None:
    return _REGISTRY.get(name)


def is_modern_stage(name: str) -> bool:
    return name in _REGISTRY


def strip_padding(data: bytes, block_size: int) -> bytes:
    """
    Remove PKCS#7 padding when present, otherwise trailing zero bytes.

    Both conventions appear in the wild, and guessing wrong only costs a few
    trailing bytes, so try the stricter PKCS#7 check first.
    """
    if not data:
        return data
    pad = data[-1]
    if 0 < pad <= block_size and len(data) >= pad:
        if data[-pad:] == bytes([pad]) * pad:
            return data[:-pad]
    return data.rstrip(b"\x00")


def modern_decrypt(
    data: bytes, info: ModernStageInfo, key: bytes, iv: bytes | None
) -> bytes | None:
    """
    Decrypt with a standard implementation.

    Returns None on any error — a wrong key size, a short payload, or an
    unusable mode — so the caller can prune that branch.
    """
    try:
        from Crypto.Cipher import AES, DES, DES3
        from Crypto.Util import Counter
    except ImportError:
        return None

    if not data:
        return None

    key = key[: info.key_size].ljust(info.key_size, b"\x00")

    try:
        if info.family.startswith("aes"):
            module, factory = AES, AES.new
        elif info.family == "des":
            module, factory = DES, DES.new
        else:
            # pycryptodome refuses a 3DES key whose halves match, because it
            # degenerates to single DES. That is mathematically true, so rather
            # than pruning the branch (and losing coverage of a puzzle that
            # really did use a repeated key) fall through to single DES, which
            # produces identical plaintext.
            if key[:8] == key[8:16] or key[8:16] == key[16:24]:
                module, factory = DES, DES.new
                key = key[:8]
            else:
                module, factory = DES3, DES3.new

        block = info.block_size
        if info.mode in ("ecb", "cbc"):
            usable = len(data) - (len(data) % block)
            if usable < block:
                return None
            data = data[:usable]

        if info.mode == "ecb":
            cipher = factory(key, module.MODE_ECB)
        elif info.mode == "cbc":
            cipher = factory(key, module.MODE_CBC, iv)
        elif info.mode == "cfb":
            cipher = factory(key, module.MODE_CFB, iv, segment_size=block * 8)
        elif info.mode == "cfb8":
            cipher = factory(key, module.MODE_CFB, iv, segment_size=8)
        elif info.mode == "ofb":
            cipher = factory(key, module.MODE_OFB, iv)
        elif info.mode == "ctr":
            initial = int.from_bytes(iv or b"\x00" * block, "big")
            counter = Counter.new(block * 8, initial_value=initial)
            cipher = factory(key, module.MODE_CTR, counter=counter)
        else:
            return None

        return cipher.decrypt(data)
    except Exception:
        return None
