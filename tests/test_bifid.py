from __future__ import annotations

from stages.bifid import (
    BASE64_ALPHABET,
    STANDARD_ALPHABET,
    bifid_decrypt,
    bifid_encrypt,
    build_keyed_square,
)


class TestBifidCipher:
    """Tests for Bifid cipher operations."""

    def test_decrypt_valid_standard_alphabet(self):
        """Decrypt valid ciphertext with standard alphabet."""
        key = "ZOMBIE"
        period = len("THE HYDRA HAS 99 HEADS!")
        ciphertext = "RCV QHRAD VOX 99 HAQOS!"
        plaintext = bifid_decrypt(ciphertext, key, period, STANDARD_ALPHABET)
        assert plaintext == "THE HYDRA HAS 99 HEADS!"

    def test_encrypt_decrypt_round_trip_standard(self):
        """Encrypt and decrypt round trip (standard alphabet)."""
        plaintext = "ATTACK AT DAWN"
        key = "ZOMBIE"
        period = len(plaintext)
        encrypted = bifid_encrypt(plaintext, key, period, STANDARD_ALPHABET)
        decrypted = bifid_decrypt(encrypted, key, period, STANDARD_ALPHABET)
        assert decrypted == plaintext

    def test_encrypt_decrypt_round_trip_base64(self):
        """Encrypt and decrypt round trip (base64 alphabet)."""
        plaintext = "HELLOWORLD1234"
        key = "TESTKEY"
        period = len(plaintext)
        encrypted = bifid_encrypt(plaintext, key, period, BASE64_ALPHABET)
        decrypted = bifid_decrypt(encrypted, key, period, BASE64_ALPHABET)
        assert decrypted == plaintext

    def test_wrong_key_produces_gibberish(self):
        """Wrong key produces incorrect output."""
        ciphertext = "RCV QHRAD VOX 99 HAQOS!"
        wrong_key = "WRONG"
        period = len(ciphertext)
        result = bifid_decrypt(ciphertext, wrong_key, period, STANDARD_ALPHABET)
        assert result != "THE HYDRA HAS 99 HEADS!"

    def test_build_keyed_square_standard(self):
        """Build keyed square with standard alphabet."""
        square = build_keyed_square(STANDARD_ALPHABET, "ZOMBIE")
        assert len(square) == 25
        assert square.startswith("ZOMBIE")
        assert square == "ZOMBIEACDFGHKLNPQRSTUVWXY"
        assert square.count("Z") == 1

    def test_build_keyed_square_base64(self):
        """Build keyed square with base64 alphabet."""
        square = build_keyed_square(BASE64_ALPHABET, "SECRET")
        assert len(square) == 64
        assert square.startswith("SECRT")
        assert square.count("S") == 1

    def test_i_j_substitution(self):
        """Standard alphabet handles I/J correctly."""
        assert "J" not in STANDARD_ALPHABET
        assert "I" in STANDARD_ALPHABET
        assert len(STANDARD_ALPHABET) == 25
