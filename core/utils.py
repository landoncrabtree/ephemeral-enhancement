"""
Utility functions for the cipher pipeline.

This module contains general-purpose utility functions used throughout
the pipeline, including dictionary loading, key limiting, and mixed-radix
enumeration for parameter space exploration.
"""

from __future__ import annotations

import os

# When --vary-case is used: try lowercase, uppercase, title case per word
N_CASE_VARIANTS = 3  # 0=lower, 1=upper, 2=title

# Project root (parent of the `core` package), used to resolve bundled data
# files such as the dictionaries in `dicts/` regardless of the current
# working directory.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_data_path(path: str) -> str:
    """
    Resolve a data file path, falling back to the project root.

    A relative path is first tried as-is (relative to the current working
    directory); if it does not exist, it is resolved against the project
    root so bundled files like ``dicts/full_dictionary.txt`` work from
    anywhere.

    Args:
        path: Absolute or relative path to a data file

    Returns:
        The path to use when opening the file
    """
    if os.path.isabs(path) or os.path.exists(path):
        return path
    candidate = os.path.join(PROJECT_ROOT, path)
    return candidate if os.path.exists(candidate) else path


def apply_case_variant(word: str, variant: int) -> str:
    """
    Return a case variant of the word (for --vary-case bruteforce).

    Args:
        word: Dictionary word
        variant: 0=lowercase, 1=uppercase, 2=title case

    Returns:
        Word with the chosen casing
    """
    if variant == 0:
        return word.lower()
    if variant == 1:
        return word.upper()
    if variant == 2:
        return word.title()
    return word


def load_dictionary(path: str) -> list[str]:
    """
    Load a dictionary file containing one key per line.

    Lines beginning with '#' are comments and are skipped, so curated
    dictionaries can document where their keys came from without those
    comments being brute-forced as keys. A key that genuinely starts with '#'
    can be escaped as '\\#'.

    Args:
        path: Path to dictionary file

    Returns:
        List of keys (stripped of whitespace, comments and blanks removed)
    """
    keys: list[str] = []
    with open(resolve_data_path(path), "r") as f:
        for line in f:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            keys.append(word[1:] if word.startswith("\\#") else word)
    return keys


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
