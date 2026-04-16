"""
Mcrypt algorithm/mode registry.

Maps pipeline stage names to libmcrypt algorithm+mode combinations.
Provides metadata (key sizes, block size, IV requirements) for parameter
space computation and key derivation.

Stage naming convention: "{algo}-{mode}" e.g. "rijndael-128-cbc", "des-ecb"
Stream ciphers use "{algo}" e.g. "arcfour", "wake"
"""

from __future__ import annotations

from dataclasses import dataclass

# Block cipher algorithms available in libmcrypt 2.5.8
BLOCK_ALGORITHMS = [
    "blowfish",
    "blowfish-compat",
    "cast-128",
    "cast-256",
    "des",
    "gost",
    "loki97",
    "rc2",
    "rijndael-128",
    "rijndael-192",
    "rijndael-256",
    "saferplus",
    "serpent",
    "tripledes",
    "twofish",
    "xtea",
]

# Stream cipher algorithms
STREAM_ALGORITHMS = [
    "arcfour",
    "wake",
    "enigma",
]

# Block cipher modes
BLOCK_MODES = ["ecb", "cbc", "cfb", "ofb", "nofb", "ctr"]

# Modes that require an IV
IV_MODES = {"cbc", "cfb", "ofb", "nofb", "ctr"}

# Number of key padding strategies
# 0 = as-is: pass key to libmcrypt (it auto-pads short keys with \x00)
# 1 = ascii-0-pad: pad key with ASCII "0" (0x30) to max_key_size
# Both truncate first if key > max_key_size
N_KEY_PAD_STRATEGIES = 2
KEY_PAD_ASIS = 0
KEY_PAD_ASCII_ZERO = 1

# Number of IV strategies (only applies to modes that need an IV)
# 0 = IV derived from key (key bytes zero-padded/truncated to iv_size)
# 1 = IV is ASCII "0" (0x30) repeated to iv_size
# 2 = IV is null byte (0x00) repeated to iv_size
N_IV_STRATEGIES = 3
IV_FROM_KEY = 0
IV_ASCII_ZERO = 1
IV_NULL_BYTES = 2


@dataclass(frozen=True)
class McryptStageInfo:
    """Metadata for a registered mcrypt pipeline stage."""

    stage_name: str
    algo: str
    mode: str
    max_key_size: int
    block_size: int
    iv_size: int
    needs_iv: bool
    is_block: bool
    # Fixed key sizes (e.g. [16,24,32]) or None for variable-length
    key_sizes: list[int] | None


def _build_registry() -> dict[str, McryptStageInfo]:
    """Build the full registry by querying libmcrypt for algo properties."""
    from stages.mcrypt_wrapper import get_algo_info

    registry: dict[str, McryptStageInfo] = {}

    # Block ciphers: one stage per algo+mode combo
    for algo in BLOCK_ALGORITHMS:
        try:
            info = get_algo_info(algo)
        except (ValueError, OSError):
            continue

        for mode in BLOCK_MODES:
            needs_iv = mode in IV_MODES
            stage_name = f"{algo}-{mode}"
            registry[stage_name] = McryptStageInfo(
                stage_name=stage_name,
                algo=algo,
                mode=mode,
                max_key_size=info["max_key_size"],
                block_size=info["block_size"],
                iv_size=info["block_size"] if needs_iv else 0,
                needs_iv=needs_iv,
                is_block=True,
                key_sizes=info["key_sizes"],
            )

    # Stream ciphers: only "stream" mode
    for algo in STREAM_ALGORITHMS:
        try:
            info = get_algo_info(algo, mode="stream")
        except (ValueError, OSError):
            continue

        stage_name = algo
        registry[stage_name] = McryptStageInfo(
            stage_name=stage_name,
            algo=algo,
            mode="stream",
            max_key_size=info["max_key_size"],
            block_size=info["block_size"],
            iv_size=0,
            needs_iv=False,
            is_block=False,
            key_sizes=info["key_sizes"],
        )

    return registry


# Lazily initialized registry
_registry: dict[str, McryptStageInfo] | None = None


def get_registry() -> dict[str, McryptStageInfo]:
    """Get the full mcrypt stage registry (lazily initialized)."""
    global _registry
    if _registry is None:
        _registry = _build_registry()
    return _registry


def get_stage_info(name: str) -> McryptStageInfo | None:
    """Look up stage info by name."""
    return get_registry().get(name)


def is_mcrypt_stage(name: str) -> bool:
    """Check if a stage name is a registered mcrypt stage."""
    return name in get_registry()


def list_mcrypt_stages() -> list[str]:
    """Return all registered mcrypt stage names (sorted)."""
    return sorted(get_registry().keys())


def get_all_valid_stage_names() -> set[str]:
    """Return all valid mcrypt stage names."""
    return set(get_registry().keys())
