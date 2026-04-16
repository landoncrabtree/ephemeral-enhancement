from __future__ import annotations

import pytest

from stages.mcrypt_wrapper import McryptHandleCache, mcrypt_decrypt


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
