from __future__ import annotations


def repeating_xor(data: bytes, key: bytes) -> bytes:
    """
    Apply repeating-key XOR to data.

    Args:
        data: The data to XOR
        key: The key to repeat across the data

    Returns:
        The XORed result
    """
    if not key:
        return b""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
