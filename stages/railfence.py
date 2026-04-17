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


def redefense_decrypt(cipher: str, keyword: str) -> str:
    """
    Decrypt a Redefence (keyed rail fence) cipher.

    Like rail fence, but the order rails are read off is determined by the
    keyword. The keyword defines which rail is filled first from the ciphertext.
    """
    if not keyword or not cipher:
        return cipher

    num_rails = len(keyword)
    n = len(cipher)

    if num_rails <= 1:
        return cipher

    # Determine rail for each position (zigzag pattern)
    rail_for_pos = []
    rail = 0
    direction = 1
    for _ in range(n):
        rail_for_pos.append(rail)
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    # Count chars per rail
    rail_lengths = [0] * num_rails
    for r in rail_for_pos:
        rail_lengths[r] += 1

    # Keyword determines the order rails are read from ciphertext
    rail_order = [i for i, _ in sorted(enumerate(keyword), key=lambda x: (x[1], x[0]))]

    # Fill rails from ciphertext in keyword order
    rails = [""] * num_rails
    idx = 0
    for rail_idx in rail_order:
        length = rail_lengths[rail_idx]
        rails[rail_idx] = cipher[idx : idx + length]
        idx += length

    # Read off by zigzag pattern
    rail_positions = [0] * num_rails
    out = []
    for r in rail_for_pos:
        out.append(rails[r][rail_positions[r]])
        rail_positions[r] += 1

    return "".join(out)
