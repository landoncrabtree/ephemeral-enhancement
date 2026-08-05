"""Tests for the standard (non-mcrypt) AES/DES/3DES stages."""

from __future__ import annotations

import pytest

from core.pipeline import axes_for_pipeline
from stages.key_derivation import N_KEY_DERIVATION_MODES
from stages.mcrypt_registry import N_IV_STRATEGIES, N_KEY_PAD_STRATEGIES
from stages.modern import (
    get_all_modern_stage_names,
    get_modern_stage_info,
    is_modern_stage,
    modern_decrypt,
    strip_padding,
)

pytest.importorskip("Crypto", reason="pycryptodome not installed")

N_KEYS = 4
KEY = b"TheGiantTheGiantTheGiantTheGiant"
# A non-degenerate 24-byte key, so the 3DES tests exercise real 3DES.
KEY3 = b"TheGiant-ElGigante-Zombie"


def _encrypt(info, key, iv, data):
    """Reference encryption with the same standard semantics."""
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util import Counter

    key = key[: info.key_size].ljust(info.key_size, b"\x00")
    if info.family.startswith("aes"):
        module, factory = AES, AES.new
    elif info.family == "des":
        module, factory = DES, DES.new
    elif key[:8] == key[8:16] or key[8:16] == key[16:24]:
        module, factory = DES, DES.new  # degenerate 3DES == single DES
        key = key[:8]
    else:
        module, factory = DES3, DES3.new

    block = info.block_size
    if info.mode == "ecb":
        return factory(key, module.MODE_ECB).encrypt(data)
    if info.mode == "cbc":
        return factory(key, module.MODE_CBC, iv).encrypt(data)
    if info.mode == "cfb":
        return factory(key, module.MODE_CFB, iv, segment_size=block * 8).encrypt(data)
    if info.mode == "cfb8":
        return factory(key, module.MODE_CFB, iv, segment_size=8).encrypt(data)
    if info.mode == "ofb":
        return factory(key, module.MODE_OFB, iv).encrypt(data)
    counter = Counter.new(block * 8, initial_value=int.from_bytes(iv, "big"))
    return factory(key, module.MODE_CTR, counter=counter).encrypt(data)


class TestRegistry:
    def test_expected_stage_count(self):
        # 5 algorithms x 6 modes
        assert len(get_all_modern_stage_names()) == 30

    @pytest.mark.parametrize(
        "name", ["std-aes-128-cbc", "std-aes-256-ctr", "std-des-ecb", "std-3des-cfb"]
    )
    def test_known_stages_registered(self, name):
        assert is_modern_stage(name)

    def test_names_do_not_collide_with_mcrypt(self):
        from stages.mcrypt_registry import get_all_valid_stage_names

        assert not (get_all_modern_stage_names() & get_all_valid_stage_names())

    def test_key_sizes(self):
        assert get_modern_stage_info("std-aes-128-cbc").key_size == 16
        assert get_modern_stage_info("std-aes-192-cbc").key_size == 24
        assert get_modern_stage_info("std-aes-256-cbc").key_size == 32
        assert get_modern_stage_info("std-des-cbc").key_size == 8
        assert get_modern_stage_info("std-3des-cbc").key_size == 24

    def test_ecb_needs_no_iv(self):
        assert get_modern_stage_info("std-aes-128-ecb").needs_iv is False
        assert get_modern_stage_info("std-aes-128-cbc").needs_iv is True


class TestRoundTrip:
    @pytest.mark.parametrize("name", sorted(get_all_modern_stage_names()))
    def test_roundtrip(self, name):
        info = get_modern_stage_info(name)
        iv = b"0" * info.iv_size if info.needs_iv else None
        plain = b"The many worlds are now one....."  # multiple of 8 and 16
        key = KEY3 if info.family == "3des" else KEY
        cipher = _encrypt(info, key, iv, plain)
        assert modern_decrypt(cipher, info, key, iv) == plain

    def test_wrong_key_does_not_recover(self):
        info = get_modern_stage_info("std-aes-128-cbc")
        iv = b"0" * 16
        plain = b"The many worlds are now one....."
        cipher = _encrypt(info, KEY, iv, plain)
        assert modern_decrypt(cipher, info, b"Zombies!", iv) != plain

    def test_empty_returns_none(self):
        info = get_modern_stage_info("std-aes-128-ecb")
        assert modern_decrypt(b"", info, KEY, None) is None

    def test_short_block_mode_input_returns_none(self):
        info = get_modern_stage_info("std-aes-128-ecb")
        assert modern_decrypt(b"short", info, KEY, None) is None


class TestDistinctFromMcrypt:
    """
    The point of these stages: mcrypt is not interchangeable with standard
    implementations, so the extra coverage is real rather than duplicated.
    """

    def test_standard_cfb_differs_from_mcrypt_8bit_cfb(self):
        """mcrypt's `cfb` is 8-bit; standard AES-CFB feeds back 128 bits."""
        full = get_modern_stage_info("std-aes-128-cfb")
        eight = get_modern_stage_info("std-aes-128-cfb8")
        iv = b"0" * 16
        data = bytes(range(64))
        assert modern_decrypt(data, full, KEY, iv) != modern_decrypt(data, eight, KEY, iv)

    def test_cfb8_matches_mcrypt_semantics(self):
        """The cfb8 variant exists so the two families can be compared."""
        pytest.importorskip("stages.mcrypt_wrapper")
        from stages.mcrypt_wrapper import mcrypt_decrypt

        info = get_modern_stage_info("std-aes-128-cfb8")
        iv, data = b"0" * 16, bytes(range(64))
        key = KEY[:16]
        try:
            expected = mcrypt_decrypt("rijndael-128", "cfb", key, iv, data)[: len(data)]
        except Exception:
            pytest.skip("libmcrypt unavailable")
        assert modern_decrypt(data, info, key, iv) == expected


class TestDegenerate3DES:
    """A repeated-half 3DES key is single DES, so it must still decrypt."""

    def test_degenerate_key_falls_back_to_single_des(self):
        info3 = get_modern_stage_info("std-3des-ecb")
        info1 = get_modern_stage_info("std-des-ecb")
        degenerate = b"TheGiant" * 3
        data = bytes(range(32))
        assert modern_decrypt(data, info3, degenerate, None) == modern_decrypt(
            data, info1, b"TheGiant", None
        )

    def test_degenerate_key_is_not_pruned(self):
        info = get_modern_stage_info("std-3des-cbc")
        assert modern_decrypt(bytes(range(32)), info, b"TheGiant" * 3, b"0" * 8) is not None


class TestPadding:
    def test_pkcs7_removed(self):
        assert strip_padding(b"HELLO" + bytes([3]) * 3, 8) == b"HELLO"

    def test_zero_padding_removed(self):
        assert strip_padding(b"HELLO\x00\x00\x00", 8) == b"HELLO"

    def test_unpadded_untouched(self):
        assert strip_padding(b"HELLOWOR", 8) == b"HELLOWOR"

    def test_invalid_pkcs7_falls_back_to_zero_strip(self):
        assert strip_padding(b"HELLO\x03\x03\x04", 8) == b"HELLO\x03\x03\x04"


class TestAxisSizes:
    def test_iv_mode_axis(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["std-aes-128-cbc"], N_KEYS)}
        assert sizes["std-aes-128-cbc"] == (
            N_KEYS * N_KEY_DERIVATION_MODES * N_KEY_PAD_STRATEGIES * N_IV_STRATEGIES
        )

    def test_ecb_axis_has_no_iv_factor(self):
        sizes = {a.name: a.size for a in axes_for_pipeline(["std-aes-128-ecb"], N_KEYS)}
        assert sizes["std-aes-128-ecb"] == (
            N_KEYS * N_KEY_DERIVATION_MODES * N_KEY_PAD_STRATEGIES
        )
