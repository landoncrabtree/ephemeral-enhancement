"""
Tests for mcrypt decryption with various key derivation, key padding, and IV strategies.

Test vectors are hardcoded ciphertext encrypted with mcrypt_generic (encrypt)
against the plaintext: "The quick brown fox jumps over the lazy dog"
"""

import hashlib

import pytest

from stages.mcrypt_wrapper import McryptHandle

PLAINTEXT = b"The quick brown fox jumps over the lazy dog"


def _strip_padding(pt: bytes) -> bytes:
    """Strip trailing null bytes from decrypted plaintext."""
    return pt.rstrip(b"\x00")


# ---------------------------------------------------------------------------
# Rijndael-128 (AES) tests
# ---------------------------------------------------------------------------


class TestRijndael128:
    """Rijndael-128: block=16, key_sizes=[16,24,32], iv_size=16."""

    def test_cfb_raw_key_asis_iv_ascii0(self):
        """raw key 'Zombies' (7 bytes), as-is pad (\x00 by libmcrypt to 16), IV=ASCII '0'*16."""
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
        """raw key 'Zombies' padded with '0' to 16, IV=\x00*16."""
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


# ---------------------------------------------------------------------------
# DES tests
# ---------------------------------------------------------------------------


class TestDES:
    """DES: block=8, key_sizes=[8], iv_size=8."""

    def test_cfb_raw_key_asis_iv_ascii0(self):
        """raw key 'Zombies' (7 bytes), as-is (\x00 pad to 8 by libmcrypt), IV=ASCII '0'*8."""
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
        """MD5 key truncated to 8 bytes, CBC, IV=\x00*8."""
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


# ---------------------------------------------------------------------------
# Loki97 tests
# ---------------------------------------------------------------------------


class TestLoki97:
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
