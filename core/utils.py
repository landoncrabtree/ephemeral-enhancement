"""
Utility functions for the cipher pipeline.

This module contains general-purpose utility functions used throughout
the pipeline, including dictionary loading, key limiting, and mixed-radix
enumeration for parameter space exploration.
"""

from __future__ import annotations


def load_dictionary(path: str) -> list[str]:
    """
    Load a dictionary file containing one word per line.

    Args:
        path: Path to dictionary file

    Returns:
        List of words (stripped of whitespace)
    """
    with open(path, "r") as f:
        return [w.strip() for w in f if w.strip()]


def limit_keys(dictionary: list[str], limit: int) -> list[str]:
    """
    Limit the dictionary to the first N keys.

    Args:
        dictionary: Full dictionary list
        limit: Maximum number of keys (0 = no limit)

    Returns:
        Limited dictionary (or full dictionary if limit <= 0)
    """
    return dictionary[:limit] if limit > 0 else dictionary


def load_common_words(
    path: str = "common.txt", fallback_keys: list[str] | None = None
) -> set[str]:
    """
    Load common English words for scoring.

    Args:
        path: Path to common words file
        fallback_keys: Fallback to use first 1000 keys if file not found

    Returns:
        Set of uppercase common words
    """
    try:
        words = load_dictionary(path)
        return set(word.upper() for word in words)
    except FileNotFoundError:
        if fallback_keys:
            return set(word.upper() for word in fallback_keys[:1000])
        return set()


def mixed_radix_unrank(x: int, bases: list[int]) -> list[int]:
    """
    Convert a linear index to mixed-radix coordinates.

    This is used to enumerate all parameter combinations in the pipeline.
    For example, with bases [26, 100, 100] (caesar, bifid, xor):
    - x=0 → [0, 0, 0]
    - x=1 → [0, 0, 1]
    - x=100 → [0, 1, 0]

    Args:
        x: Linear index into parameter space
        bases: Size of each parameter dimension

    Returns:
        List of indices, one per dimension
    """
    idxs: list[int] = []
    for b in reversed(bases):
        idxs.append(x % b)
        x //= b
    return list(reversed(idxs))
