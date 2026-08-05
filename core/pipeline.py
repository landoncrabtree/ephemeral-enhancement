"""
Pipeline configuration and validation.

This module handles parsing pipeline strings, validating stages,
and computing the parameter axes for the search space.
"""

from __future__ import annotations

from dataclasses import dataclass

from stages.key_derivation import N_KEY_DERIVATION_MODES
from stages.amsco import N_AMSCO_PATTERNS
from stages.charsets import N_CHARSET_MODES
from stages.playfair import N_PLAYFAIR_GRIDS
from stages.skip import MAX_BYPASS, N_SKIP_VALUES
from stages.trifid import N_TRIFID_CUBES, N_TRIFID_PERIODS
from stages.columnar import N_COLUMNAR_CHARSET_MODES
from stages.railfence import N_RAILFENCE_CHARSET_MODES
from stages.polyalpha import N_POLYALPHA_ALPHABETS, N_POLYALPHA_MODES
from stages.mcrypt_registry import (
    N_IV_STRATEGIES,
    N_KEY_PAD_STRATEGIES,
    get_all_valid_stage_names,
    get_stage_info,
    is_mcrypt_stage,
)

from .utils import N_CASE_VARIANTS

# Classical cipher stages (non-mcrypt)
_CLASSICAL_STAGES = {
    "affine",
    "amsco",
    "atbash",
    "atbash26",
    "atbash52",
    "atbash62",
    "atbash64",
    "beaufort",
    "beaufort26",
    "beaufort62",
    "beaufort64",
    "beaufort52",
    "caesar",
    "keyword",
    "keyword26",
    "keyword52",
    "keyword62",
    "keyword64",
    "bifid",
    "columnar",
    "decimal",
    "double_columnar",
    "b64",
    "hex",
    "myszkowski",
    "playfair",
    "porta",
    "porta26",
    "porta62",
    "porta64",
    "porta52",
    "redefense",
    "trifid",
    "trithemius",
    "trithemius26",
    "trithemius62",
    "trithemius64",
    "trithemius52",
    "vigenere",
    "vigenere26",
    "vigenere62",
    "vigenere64",
    "vigenere52",
    "xor",
    "railfence",
    "reverse",
    "scytale",
    "skip",
}

# Valid stages = classical + all mcrypt stages (including aliases)
VALID_STAGES = _CLASSICAL_STAGES | get_all_valid_stage_names()


@dataclass(slots=True)
class StageAxis:
    """
    Represents one dimension of the parameter space.

    Attributes:
        name: Stage name (e.g., "caesar", "xor")
        size: Number of possible values for this parameter
    """

    name: str
    size: int


def parse_pipeline(pipeline: str) -> list[str]:
    """
    Parse a pipeline string into a list of stage names.

    Args:
        pipeline: Pipeline string (e.g., "caesar>bifid>xor")

    Returns:
        List of stage names

    Raises:
        SystemExit: If pipeline contains unknown stages
    """
    stages = [s.strip() for s in pipeline.split(">") if s.strip()]
    bad = [s for s in stages if s not in VALID_STAGES]
    if bad:
        raise SystemExit(
            f"Unknown stages in pipeline: {bad}. Valid: {sorted(VALID_STAGES)}"
        )
    return stages


def axes_for_pipeline(
    stages: list[str], n_keys: int, vary_case: bool = False
) -> list[StageAxis]:
    """
    Compute parameter axes for a pipeline.

    Each stage that requires parameters (keys, shifts, rails) contributes
    one axis to the search space. Stages like b64 and reverse have no
    parameters and don't contribute axes.

    When vary_case is True, each key dimension is multiplied by
    N_CASE_VARIANTS (lower, upper, title) and the effective key is
    computed at runtime.

    Args:
        stages: List of stage names
        n_keys: Number of keys in dictionary
        vary_case: If True, try 3 case variants per word (lower/upper/title)

    Returns:
        List of StageAxis objects defining the parameter space
    """
    k = n_keys * (N_CASE_VARIANTS if vary_case else 1)
    axes: list[StageAxis] = []
    for st in stages:
        if st == "affine":
            from stages.affine import N_AFFINE_TOTAL
            axes.append(StageAxis("affine", N_AFFINE_TOTAL))
        elif st == "caesar":
            from stages.caesar import N_CAESAR_TOTAL
            axes.append(StageAxis("caesar", N_CAESAR_TOTAL))
        elif st == "railfence":
            axes.append(StageAxis("railfence", 29 * N_RAILFENCE_CHARSET_MODES))  # 2-30 rails × charset modes
        elif st == "scytale":
            # 2-100 columns × charset modes
            axes.append(StageAxis("scytale", 99 * N_CHARSET_MODES))
        elif st == "skip":
            # skip values x bypass offsets x charset modes
            axes.append(
                StageAxis("skip", N_SKIP_VALUES * MAX_BYPASS * N_CHARSET_MODES)
            )
        elif st == "amsco":
            # keys x chunk patterns (1-2 / 2-1) x charset modes
            axes.append(
                StageAxis("amsco", k * N_AMSCO_PATTERNS * N_CHARSET_MODES)
            )
        elif st == "playfair":
            # keys x grid sizes (5x5 / 6x6 / 8x8-base64)
            axes.append(StageAxis("playfair", k * N_PLAYFAIR_GRIDS))
        elif st == "trifid":
            # keys x periods x cube sizes (3x3x3 / 4x4x4-base64)
            axes.append(
                StageAxis("trifid", k * N_TRIFID_PERIODS * N_TRIFID_CUBES)
            )
        elif st == "myszkowski":
            axes.append(StageAxis("myszkowski", k * N_CHARSET_MODES))
        elif st in ("bifid", "xor"):
            axes.append(StageAxis(st, k))
        elif st in ("vigenere", "beaufort", "porta"):
            # Base name sweeps both alphabets; the 26/52 variants pin one.
            axes.append(
                StageAxis(st, k * N_POLYALPHA_MODES * N_POLYALPHA_ALPHABETS)
            )
        elif st in ("vigenere26", "beaufort26", "porta26",
                    "vigenere52", "beaufort52", "porta52",
                    "vigenere62", "beaufort62", "porta62",
                    "vigenere64", "beaufort64", "porta64"):
            axes.append(StageAxis(st, k * N_POLYALPHA_MODES))
        elif st in ("trithemius", "atbash"):
            # Keyless, but still sweeps every alphabet.
            axes.append(StageAxis(st, N_POLYALPHA_ALPHABETS))
        elif st == "keyword":
            axes.append(StageAxis(st, k * N_POLYALPHA_ALPHABETS))
        elif st in ("keyword26", "keyword52", "keyword62", "keyword64"):
            axes.append(StageAxis(st, k))
        elif st == "redefense":
            axes.append(StageAxis("redefense", k * N_RAILFENCE_CHARSET_MODES))
        elif st == "columnar":
            axes.append(StageAxis("columnar", k * N_COLUMNAR_CHARSET_MODES))
        elif st == "double_columnar":
            axes.append(StageAxis("double_columnar", k * k * N_COLUMNAR_CHARSET_MODES))
        elif is_mcrypt_stage(st):
            info = get_stage_info(st)
            assert info is not None
            # key × derivation modes × key_pad_strategies × iv_strategies
            iv_mult = N_IV_STRATEGIES if info.needs_iv else 1
            size = k * N_KEY_DERIVATION_MODES * N_KEY_PAD_STRATEGIES * iv_mult
            axes.append(StageAxis(st, size))
        elif st in ("b64", "hex", "decimal", "reverse",
                    "trithemius26", "trithemius52",
                    "trithemius62", "trithemius64",
                    "atbash26", "atbash52", "atbash62", "atbash64"):
            continue
    return axes


def validate_pipeline(stages: list[str]) -> None:
    """
    Validate a pipeline configuration.

    Args:
        stages: List of stage names

    Raises:
        ValueError: If pipeline is invalid
    """
    if not stages:
        raise ValueError("Pipeline cannot be empty")

    # Check for unknown stages
    unknown = [s for s in stages if s not in VALID_STAGES]
    if unknown:
        raise ValueError(f"Unknown stages: {unknown}")

    # Could add more validation here:
    # - Warn about inefficient orderings
    # - Check for incompatible stage combinations
    # - etc.
