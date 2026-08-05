"""
Hypercube (multi-axis reshape) transposition.

Generalises the scytale from two dimensions to N. The text is written into a
grid of shape ``(d0, d1, ... dk-1)`` in row-major order, the axes are permuted,
and the result is read back out in row-major order.

Two axes reproduce a classical scytale/columnar read. Three and four axes are
the interesting cases here: a 192-character payload factors as 8 x 6 x 4 —
the cells, faces and corners of an unfolded tesseract — and 192 is also the
order of the tesseract's rotation group. That makes an N-dimensional reshape a
natural construction to test for a hypercube-themed puzzle.

Being a transposition it only permutes characters, so a base64 payload stays
decodable.
"""

from __future__ import annotations

from itertools import permutations

from stages.charsets import (  # noqa: F401  (re-exported for callers)
    CHARSET_ALL,
    CHARSET_ALPHA,
    CHARSET_ALPHANUMERIC,
    N_CHARSET_MODES,
    merge_selected,
    split_selected,
)

# Axis counts to enumerate, and the ceiling on shapes per length. 192 yields
# 13 + 57 + 125 = 195 shapes across 2-4 axes, so this covers it with headroom.
AXIS_COUNTS = (2, 3, 4)
MAX_SHAPES = 256
MAX_PERMS = 24  # 4! — the largest permutation count across AXIS_COUNTS


def _factorizations(n: int, parts: int) -> list[tuple[int, ...]]:
    """Ordered factorisations of `n` into `parts` factors, each at least 2."""
    if parts == 1:
        return [(n,)] if n >= 2 else []
    out: list[tuple[int, ...]] = []
    for d in range(2, n + 1):
        if n % d == 0:
            for rest in _factorizations(n // d, parts - 1):
                out.append((d,) + rest)
    return out


def shapes_for_length(n: int) -> list[tuple[int, ...]]:
    """
    Every grid shape a text of length `n` can be reshaped into.

    Deterministically ordered so a given index always means the same shape.
    """
    shapes: list[tuple[int, ...]] = []
    for k in AXIS_COUNTS:
        shapes.extend(sorted(_factorizations(n, k)))
    return shapes[:MAX_SHAPES]


def _read_order(shape: tuple[int, ...], perm: tuple[int, ...]) -> list[int]:
    """
    Flat source indices in the order the permuted grid reads them out.

    Position `t` of the output takes its character from index `order[t]` of the
    input, so the result is always a permutation of `range(product(shape))`.
    """
    k = len(shape)
    strides = [1] * k
    for a in range(k - 2, -1, -1):
        strides[a] = strides[a + 1] * shape[a + 1]

    transposed = [shape[p] for p in perm]
    order: list[int] = []
    idx = [0] * k
    total = 1
    for d in shape:
        total *= d

    for _ in range(total):
        flat = 0
        for m, p in enumerate(perm):
            flat += idx[m] * strides[p]
        order.append(flat)
        # Increment the odometer over the transposed shape.
        for m in range(k - 1, -1, -1):
            idx[m] += 1
            if idx[m] < transposed[m]:
                break
            idx[m] = 0
    return order


def _hypercube_decrypt_raw(
    cipher: str, shape: tuple[int, ...], perm: tuple[int, ...]
) -> str:
    order = _read_order(shape, perm)
    out = [""] * len(order)
    for position, source in enumerate(order):
        out[source] = cipher[position]
    return "".join(out)


def hypercube_decrypt(
    cipher: str,
    shape_idx: int,
    perm_idx: int,
    charset_mode: int = CHARSET_ALL,
) -> str | None:
    """
    Decrypt a multi-axis reshape transposition.

    Args:
        cipher: The ciphertext to decrypt.
        shape_idx: Index into `shapes_for_length` for the selected text.
        perm_idx: Index into the axis permutations for that shape.
        charset_mode: 0=alpha, 1=alphanumeric, 2=all.

    Returns:
        The decrypted text, or None when the index pair does not describe a
        valid shape for this length — the text may not factor that way at all.
    """
    if not cipher:
        return None

    if charset_mode == CHARSET_ALL:
        chars, positions = list(cipher), None
    else:
        chars, positions = split_selected(cipher, charset_mode)
        if not chars:
            return None

    shapes = shapes_for_length(len(chars))
    if shape_idx >= len(shapes):
        return None

    shape = shapes[shape_idx]
    perms = list(permutations(range(len(shape))))
    if perm_idx >= len(perms):
        return None

    decrypted = _hypercube_decrypt_raw("".join(chars), shape, perms[perm_idx])
    if positions is None:
        return decrypted
    return merge_selected(cipher, positions, decrypted)
