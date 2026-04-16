from __future__ import annotations


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
    # Sort by keyword chars to get rail read order
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
