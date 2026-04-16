from __future__ import annotations

from .columnar import CHARSET_ALL, columnar_decrypt


def double_columnar_decrypt(
    cipher: str, key1: str, key2: str, charset_mode: int = CHARSET_ALL
) -> str:
    """
    Decrypt double columnar transposition cipher.

    If encryption was: C = col(col(P, key1), key2)
    then decryption is: P = col_dec(col_dec(C, key2), key1)

    Args:
        cipher: The ciphertext to decrypt
        key1: The first key (applied last during encryption)
        key2: The second key (applied first during encryption)
        charset_mode: Which characters to transpose (0=alpha, 1=alnum, 2=all)

    Returns:
        The decrypted plaintext
    """
    return columnar_decrypt(
        columnar_decrypt(cipher, key2, charset_mode), key1, charset_mode
    )
