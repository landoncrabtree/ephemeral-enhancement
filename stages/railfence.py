from __future__ import annotations


def railfence_decrypt(cipher: str, num_rails: int) -> str:
    """
    Decrypt a railfence cipher with the given number of rails.

    The railfence cipher writes text in a zigzag pattern across multiple rails,
    then reads off each rail sequentially. To decrypt, we need to determine
    which positions in the cipher correspond to which positions in the plaintext.
    """
    if num_rails <= 1:
        return cipher

    n = len(cipher)
    if n == 0:
        return cipher

    # Create the rail pattern to determine indices
    rail_indices = [[] for _ in range(num_rails)]
    rail = 0
    direction = 1  # 1 for down, -1 for up

    # Build the pattern to see which rail each position belongs to
    for i in range(n):
        rail_indices[rail].append(i)
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    # Now fill the rails from the cipher text
    result = [""] * n
    cipher_idx = 0
    for rail in range(num_rails):
        for pos in rail_indices[rail]:
            if cipher_idx < len(cipher):
                result[pos] = cipher[cipher_idx]
                cipher_idx += 1

    return "".join(result)
