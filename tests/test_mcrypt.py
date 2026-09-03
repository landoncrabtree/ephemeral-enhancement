from __future__ import annotations

import hashlib

import pytest

from core.executor import StageExecutor
from core.pipeline import axes_for_pipeline
from stages.key_derivation import N_KEY_DERIVATION_MODES
from stages.mcrypt_registry import N_KEY_PAD_STRATEGIES, N_NON_IV_BLOCK_STRATEGIES
from stages.mcrypt_wrapper import McryptHandle, McryptHandleCache, mcrypt_decrypt


class TestMcryptWrapper:
    """Tests for the mcrypt ctypes wrapper."""

    def test_rijndael128_ecb_decrypt(self):
        """AES-128 ECB decrypt works."""
        key = b"0123456789abcdef"
        result = mcrypt_decrypt("rijndael-128", "ecb", key, None, b"\x00" * 16)
        assert result is not None
        assert len(result) == 16

    def test_rijndael128_cbc_decrypt(self):
        """AES-128 CBC decrypt with zero IV."""
        key = b"0123456789abcdef"
        iv = b"\x00" * 16
        result = mcrypt_decrypt("rijndael-128", "cbc", key, iv, b"\x00" * 32)
        assert result is not None
        assert len(result) == 32

    def test_des_ecb_decrypt(self):
        """DES ECB decrypt works."""
        key = b"abcdefgh"
        result = mcrypt_decrypt("des", "ecb", key, None, b"\x00" * 8)
        assert result is not None
        assert len(result) == 8

    def test_tripledes_ecb_decrypt(self):
        """3DES ECB decrypt works."""
        key = b"0123456789abcdef01234567"
        result = mcrypt_decrypt("tripledes", "ecb", key, None, b"\x00" * 8)
        assert result is not None
        assert len(result) == 8

    def test_arcfour_stream_decrypt(self):
        """RC4 stream cipher decrypt works."""
        key = b"testkey"
        result = mcrypt_decrypt("arcfour", "stream", key, None, b"hello")
        assert result is not None
        assert len(result) == 5

    def test_blowfish_ecb_decrypt(self):
        """Blowfish ECB decrypt works."""
        key = b"0123456789abcdef"
        result = mcrypt_decrypt("blowfish", "ecb", key, None, b"\x00" * 8)
        assert result is not None
        assert len(result) == 8

    def test_handle_cache_reuse(self):
        """Handle cache returns same handle for same algo/mode."""
        cache = McryptHandleCache()
        h1 = cache.get("rijndael-128", "ecb")
        h2 = cache.get("rijndael-128", "ecb")
        assert h1 is h2
        h3 = cache.get("des", "ecb")
        assert h3 is not h1
        cache.close_all()

    def test_block_padding_to_block_size(self):
        """Data not aligned to block size is zero-padded (PHP compat)."""
        key = b"0123456789abcdef"
        result = mcrypt_decrypt("rijndael-128", "ecb", key, None, b"\x00" * 7)
        assert result is not None
        assert len(result) == 16

    def test_stream_cipher_preserves_length(self):
        """Stream ciphers return same length as input."""
        key = b"mykey"
        result = mcrypt_decrypt("arcfour", "stream", key, None, b"abc")
        assert result is not None
        assert len(result) == 3


class TestMcryptRegistry:
    """Tests for mcrypt algorithm registry."""

    def test_registry_has_block_ciphers(self):
        """Registry contains all expected block ciphers."""
        from stages.mcrypt_registry import get_registry
        reg = get_registry()
        for algo in ["rijndael-128-ecb", "des-cbc", "blowfish-ecb", "twofish-ctr"]:
            assert algo in reg, f"{algo} not in registry"

    def test_registry_has_stream_ciphers(self):
        """Registry contains stream ciphers."""
        from stages.mcrypt_registry import get_registry
        reg = get_registry()
        assert "arcfour" in reg
        assert "wake" in reg

    def test_is_mcrypt_stage(self):
        """is_mcrypt_stage correctly identifies mcrypt vs classical."""
        from stages.mcrypt_registry import is_mcrypt_stage
        assert is_mcrypt_stage("rijndael-128-cbc")
        assert not is_mcrypt_stage("caesar")
        assert not is_mcrypt_stage("bifid")

    def test_key_pad_strategies_constant(self):
        """N_KEY_PAD_STRATEGIES is 2 (as-is and zero-pad)."""
        from stages.mcrypt_registry import N_KEY_PAD_STRATEGIES
        assert N_KEY_PAD_STRATEGIES == 2

    def test_ecb_axis_includes_iv_block_discards(self):
        axis = axes_for_pipeline(["des-ecb"], 4)[0]
        assert axis.size == (
            4
            * N_KEY_DERIVATION_MODES
            * N_KEY_PAD_STRATEGIES
            * N_NON_IV_BLOCK_STRATEGIES
        )

    def test_stream_axis_does_not_include_iv_block_discards(self):
        axis = axes_for_pipeline(["arcfour"], 4)[0]
        assert axis.size == 4 * N_KEY_DERIVATION_MODES * N_KEY_PAD_STRATEGIES


class TestNonIVBlockDiscard:
    """ECB ignores an IV, but some tools still attach one to the ciphertext."""

    @pytest.mark.parametrize(
        ("param_idx", "ciphertext", "iv_label"),
        [
            (1, b"unusediv" + bytes.fromhex("19dedaddbb054294"), "discarded-prepended"),
            (2, bytes.fromhex("19dedaddbb054294") + b"unusediv", "discarded-appended"),
        ],
    )
    def test_des_ecb_discards_unused_iv_block(
        self, param_idx, ciphertext, iv_label
    ):
        executor = StageExecutor("", ["abcdefgh"], ["des-ecb"], "standard")
        meta = {}

        result = executor._execute_mcrypt(
            "des-ecb", ciphertext, "bytes", [param_idx], 0, meta
        )

        assert result == ("TestData", "text", 1)
        assert meta["des-ecb_iv"] == iv_label


# Known encrypt→decrypt test vectors (generated from libmcrypt/PHP mcrypt)
_MCRYPT_VECTORS = [
    ("aes128-ecb-exact-block", "rijndael-128", "ecb", "30313233343536373839616263646566", "", "48656c6c6f20576f726c642121212121", "82e8dac9947183413caf76d4345d6928"),
    ("aes128-cbc-zero-iv", "rijndael-128", "cbc", "30313233343536373839616263646566", "00000000000000000000000000000000", "48656c6c6f20576f726c642121212121", "82e8dac9947183413caf76d4345d6928"),
    ("aes128-cbc-key-as-iv", "rijndael-128", "cbc", "30313233343536373839616263646566", "30313233343536373839616263646566", "48656c6c6f20576f726c642121212121", "0984058b4a8e728c2d27230bc88d82dd"),
    ("aes128-ecb-short-pt", "rijndael-128", "ecb", "30313233343536373839616263646566", "", "48656c6c6f", "20cff95086c35d686e3f3d9914ac9271"),
    ("aes128-cfb-zero-iv", "rijndael-128", "cfb", "30313233343536373839616263646566", "00000000000000000000000000000000", "48656c6c6f20576f726c642121212121", "436e1bb4e75eb1fc6950d77f2c92fd42"),
    ("aes128-ofb-zero-iv", "rijndael-128", "ofb", "30313233343536373839616263646566", "00000000000000000000000000000000", "48656c6c6f20576f726c642121212121", "43f9fb4c4c73f061e6678efc7ae63599"),
    ("aes128-nofb-zero-iv", "rijndael-128", "nofb", "30313233343536373839616263646566", "00000000000000000000000000000000", "48656c6c6f20576f726c642121212121", "43fe79b62464f79a6771abe5e13e14f4"),
    ("des-ecb-exact-block", "des", "ecb", "6162636465666768", "", "5465737444617461", "19dedaddbb054294"),
    ("des-cbc-zero-iv", "des", "cbc", "6162636465666768", "0000000000000000", "5465737444617461", "19dedaddbb054294"),
    ("3des-ecb", "tripledes", "ecb", "303132333435363738396162636465663031323334353637", "", "5465737444617461", "7daf86ded555b747"),
    ("3des-cbc-zero-iv", "tripledes", "cbc", "303132333435363738396162636465663031323334353637", "0000000000000000", "5465737444617461", "7daf86ded555b747"),
    ("blowfish-ecb", "blowfish", "ecb", "30313233343536373839616263646566", "", "5465737444617461", "2dd8badc6dbee4fa"),
    ("blowfish-cbc-zero-iv", "blowfish", "cbc", "30313233343536373839616263646566", "0000000000000000", "5465737444617461", "2dd8badc6dbee4fa"),
    ("twofish-ecb", "twofish", "ecb", "30313233343536373839616263646566", "", "48656c6c6f20576f726c642121212121", "a59038ee8472183a75424c000f169bce"),
    ("cast128-ecb", "cast-128", "ecb", "30313233343536373839616263646566", "", "5465737444617461", "1eea59483c496729"),
    ("serpent-ecb", "serpent", "ecb", "30313233343536373839616263646566", "", "48656c6c6f20576f726c642121212121", "e3d2a8ddc05548e88eac8c431c5be460"),
    ("xtea-ecb", "xtea", "ecb", "30313233343536373839616263646566", "", "5465737444617461", "6bb55fcfbc1f822f"),
    ("arcfour-stream", "arcfour", "stream", "30313233343536373839616263646566", "", "48656c6c6f20576f726c642121212121", "cc0d2c35926ef7f77b9a3ebfe1b27264"),
    ("arcfour-stream-short-key", "arcfour", "stream", "6b6579", "", "48656c6c6f20576f726c64", "430958814baf2c253a276c"),
    ("rijndael256-ecb", "rijndael-256", "ecb", "3031323334353637383961626364656630313233343536373839616263646566", "", "48656c6c6f20576f726c64203132333448656c6c6f20576f726c642031323334", "a658e31af88673d0bf01771d5b37afbc8070570819b09c5e6500decadef22d2c"),
    ("rijndael256-cbc-zero-iv", "rijndael-256", "cbc", "3031323334353637383961626364656630313233343536373839616263646566", "0000000000000000000000000000000000000000000000000000000000000000", "48656c6c6f20576f726c64203132333448656c6c6f20576f726c642031323334", "a658e31af88673d0bf01771d5b37afbc8070570819b09c5e6500decadef22d2c"),
    ("gost-ecb", "gost", "ecb", "3031323334353637383961626364656630313233343536373839616263646566", "", "5465737444617461", "2904ef58aacf5186"),
]


class TestMcryptParity:
    """Verify our mcrypt wrapper produces correct decrypt output against known vectors."""

    @pytest.fixture(scope="class")
    def handle_cache(self) -> McryptHandleCache:
        cache = McryptHandleCache()
        yield cache
        cache.close_all()

    @pytest.mark.parametrize(
        "label,algo,mode,key_hex,iv_hex,plaintext_hex,ciphertext_hex",
        _MCRYPT_VECTORS,
        ids=[v[0] for v in _MCRYPT_VECTORS],
    )
    def test_decrypt_matches_plaintext(
        self, label, algo, mode, key_hex, iv_hex, plaintext_hex, ciphertext_hex, handle_cache
    ):
        """Decrypt ciphertext and verify it matches the expected plaintext."""
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex) if iv_hex else None
        ciphertext = bytes.fromhex(ciphertext_hex)
        expected = bytes.fromhex(plaintext_hex)

        result = mcrypt_decrypt(algo, mode, key, iv, ciphertext, handle_cache=handle_cache)
        assert result is not None, f"mcrypt_decrypt returned None for {label}"

        assert result[: len(expected)] == expected, (
            f"Mismatch for {label}: expected {expected.hex()}, got {result[: len(expected)].hex()}"
        )
        trailing = result[len(expected):]
        if trailing:
            assert trailing == b"\x00" * len(trailing), (
                f"Non-null trailing bytes for {label}: {trailing.hex()}"
            )


PLAINTEXT = b"The quick brown fox jumps over the lazy dog"


def _strip_padding(pt: bytes) -> bytes:
    """Strip trailing null bytes from decrypted plaintext."""
    return pt.rstrip(b"\x00")


# ---------------------------------------------------------------------------
# Key derivation, key padding, and IV strategy tests
# Ciphertext generated via mcrypt_generic (encrypt) with known parameters.
# ---------------------------------------------------------------------------


class TestRijndael128KeyIV:
    """Rijndael-128: block=16, key_sizes=[16,24,32], iv_size=16."""

    def test_cfb_raw_key_asis_iv_ascii0(self):
        """raw key 'Zombies' (7 bytes), as-is pad (\\x00 by libmcrypt to 16), IV=ASCII '0'*16."""
        ct = bytes.fromhex(
            "3c70b73173e35977d0d46c10236f98484222386ff1229ce1"
            "fbfc930601cef8e818148feb28be06bba57fe1e54d19c0f4"
        )
        h = McryptHandle("rijndael-128", "cfb")
        pt = h.decrypt(b"Zombies", b"0" * 16, ct)
        h.close()
        assert pt is not None
        assert pt[: len(PLAINTEXT)] == PLAINTEXT

    def test_cfb_raw_key_ascii0_pad_iv_null(self):
        """raw key 'Zombies' padded with '0' to 16, IV=\\x00*16."""
        ct = bytes.fromhex(
            "e152caf2a5bc8e4e285564fb689ab6f3f76572377ebbe6ec"
            "c098e8cf81cab613fecf530aff980a2d45f1578663813415"
        )
        key = b"Zombies" + b"0" * 9
        h = McryptHandle("rijndael-128", "cfb")
        pt = h.decrypt(key, b"\x00" * 16, ct)
        h.close()
        assert pt is not None
        assert pt[: len(PLAINTEXT)] == PLAINTEXT

    def test_ecb_sha256_key_no_iv(self):
        """SHA-256 key (32 bytes = AES-256), ECB mode, no IV."""
        ct = bytes.fromhex(
            "60249aa739a8e068a549528be51137ebffbae03d694b21ab"
            "c1603f93fe4761a9db7b4a415977b2a8daed62f7ee8aa4d6"
        )
        key = hashlib.sha256(b"Zombies").digest()
        h = McryptHandle("rijndael-128", "ecb")
        pt = h.decrypt(key, None, ct)
        h.close()
        assert pt is not None
        assert _strip_padding(pt) == PLAINTEXT

    def test_cbc_md5_key_iv_from_key(self):
        """MD5 key (16 bytes), CBC mode, IV=key bytes (already 16, no padding needed)."""
        ct = bytes.fromhex(
            "1c003b491ebe80c4ff23bfc396453d5921e76bc138c49231"
            "b1736db603b9b4828d3020b472ac71a16f7d15f42f6de3ca"
        )
        key = hashlib.md5(b"Zombies").digest()
        iv = key[:16]
        h = McryptHandle("rijndael-128", "cbc")
        pt = h.decrypt(key, iv, ct)
        h.close()
        assert pt is not None
        assert _strip_padding(pt) == PLAINTEXT


class TestDESKeyIV:
    """DES: block=8, key_sizes=[8], iv_size=8."""

    def test_cfb_raw_key_asis_iv_ascii0(self):
        """raw key 'Zombies' (7 bytes), as-is (\\x00 pad to 8 by libmcrypt), IV=ASCII '0'*8."""
        ct = bytes.fromhex(
            "f951e0ddeec03dd632631d06a8d7a151c118ee433692b417"
            "aa90471e25e9d0bf36442323dcc493f593714fef550e6660"
        )
        h = McryptHandle("des", "cfb")
        pt = h.decrypt(b"Zombies", b"0" * 8, ct)
        h.close()
        assert pt is not None
        assert pt[: len(PLAINTEXT)] == PLAINTEXT

    def test_ecb_raw_key_ascii0_pad(self):
        """raw key 'Zombies' padded with '0' to 8, ECB, no IV."""
        ct = bytes.fromhex(
            "e4b0778d0461238fcd626e1b57484abcef1a2318c08bd866"
            "3b8768bbec67f6128e46c306a2361101084fa61918345571"
        )
        key = b"Zombies0"
        h = McryptHandle("des", "ecb")
        pt = h.decrypt(key, None, ct)
        h.close()
        assert pt is not None
        assert _strip_padding(pt) == PLAINTEXT

    def test_cbc_md5_key_truncated_iv_null(self):
        """MD5 key truncated to 8 bytes, CBC, IV=\\x00*8."""
        ct = bytes.fromhex(
            "d22ecaaee0dd6f099a7c294d2798bb6f07a2da4cafdd2612"
            "9f0a5c747cff9fdca61c89c766969a239709ac3dcb4e786e"
        )
        key = hashlib.md5(b"Zombies").digest()[:8]
        h = McryptHandle("des", "cbc")
        pt = h.decrypt(key, b"\x00" * 8, ct)
        h.close()
        assert pt is not None
        assert _strip_padding(pt) == PLAINTEXT


class TestLoki97KeyIV:
    """Loki97: block=16, key_sizes=[16,24,32], iv_size=16."""

    def test_cfb_sha1_key_iv_from_key(self):
        """SHA-1 key (20 bytes, libmcrypt rounds to 24), IV=key[:16]."""
        ct = bytes.fromhex(
            "79c0d95a1b19c3f82c8d8c96a6e9c77b65d323caa1b3ce17"
            "a5ab97d5d2fa45cee1a93f76d1395e84881e4e0410cad312"
        )
        key = hashlib.sha1(b"Zombies").digest()
        iv = key[:16]
        h = McryptHandle("loki97", "cfb")
        pt = h.decrypt(key, iv, ct)
        h.close()
        assert pt is not None
        assert pt[: len(PLAINTEXT)] == PLAINTEXT

    def test_ecb_raw_key_ascii0_pad(self):
        """raw key 'Zombies' padded with '0' to 16, ECB, no IV."""
        ct = bytes.fromhex(
            "0bc91964c1630f76e0bf6c147aea322cf3fc377ee7827284"
            "8632087c2f537e54734485ecafe4042042cc8b73dd871bec"
        )
        key = b"Zombies" + b"0" * 9
        h = McryptHandle("loki97", "ecb")
        pt = h.decrypt(key, None, ct)
        h.close()
        assert pt is not None
        assert _strip_padding(pt) == PLAINTEXT

    def test_ofb_sha256_key_iv_ascii0(self):
        """SHA-256 key (32 bytes), OFB mode, IV=ASCII '0'*16."""
        ct = bytes.fromhex(
            "f79a73bc39a1307b51af67e2292f5cc4f35c72ebde189672"
            "4482b75eedd87d6f55a5323514611bd6c17e2bc70a36325a"
        )
        key = hashlib.sha256(b"Zombies").digest()
        h = McryptHandle("loki97", "ofb")
        pt = h.decrypt(key, b"0" * 16, ct)
        h.close()
        assert pt is not None
        assert pt[: len(PLAINTEXT)] == PLAINTEXT
