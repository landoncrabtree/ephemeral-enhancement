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

# Number of IV derivation strategies for modes that need an IV
# 0 = zero IV, 1 = IV derived from key (zero-padded/truncated to iv_size)
N_IV_STRATEGIES = 2


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


# Backward-compatible aliases: old stage name -> new stage name
ALIASES: dict[str, str] = {
    "aes_ecb": "rijndael-128-ecb",
    "aes_cbc": "rijndael-128-cbc",
    "des_ecb": "des-ecb",
    "des_cbc": "des-cbc",
    "des3": "tripledes-ecb",
    "rc4": "arcfour",
    "xtea": "xtea-ecb",
}


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


def resolve_stage_name(name: str) -> str:
    """Resolve a stage name, following aliases."""
    return ALIASES.get(name, name)


def get_stage_info(name: str) -> McryptStageInfo | None:
    """Look up stage info by name (follows aliases)."""
    resolved = resolve_stage_name(name)
    return get_registry().get(resolved)


def is_mcrypt_stage(name: str) -> bool:
    """Check if a stage name (or alias) is a registered mcrypt stage."""
    resolved = resolve_stage_name(name)
    return resolved in get_registry()


def list_mcrypt_stages() -> list[str]:
    """Return all registered mcrypt stage names (sorted)."""
    return sorted(get_registry().keys())


def get_all_valid_stage_names() -> set[str]:
    """Return all valid mcrypt stage names including aliases."""
    reg = get_registry()
    names = set(reg.keys())
    names.update(ALIASES.keys())
    return names
