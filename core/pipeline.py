"""
Pipeline configuration and validation.

This module handles parsing pipeline strings, validating stages,
and computing the parameter axes for the search space.
"""

from __future__ import annotations

from dataclasses import dataclass

from stages.aes_cbc import N_IV_MODES
from stages.des_cbc import N_IV_MODES as DES_CBC_IV_MODES
from stages.key_derivation import N_KEY_DERIVATION_MODES

from .utils import N_CASE_VARIANTS

# Valid cipher stages
VALID_STAGES = {
    "caesar",
    "bifid",
    "columnar",
    "double_columnar",
    "b64",
    "xor",
    "railfence",
    "reverse",
    "rc4",
    "aes_ecb",
    "aes_cbc",
    "des_ecb",
    "des_cbc",
    "des3",
    "xtea",
}


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
        if st == "caesar":
            axes.append(StageAxis("caesar", 26))
        elif st == "railfence":
            axes.append(StageAxis("railfence", 29))  # 2-30 rails
        elif st in ("bifid", "columnar", "xor"):
            axes.append(StageAxis(st, k))
        elif st == "double_columnar":
            axes.append(StageAxis("double_columnar", k * k))
        elif st == "rc4":
            axes.append(StageAxis("rc4", k * N_KEY_DERIVATION_MODES))
        elif st == "aes_ecb":
            axes.append(
                StageAxis("aes_ecb", k * N_KEY_DERIVATION_MODES * 2)
            )
        elif st == "aes_cbc":
            axes.append(
                StageAxis(
                    "aes_cbc",
                    k * N_KEY_DERIVATION_MODES * N_IV_MODES * 2,
                )
            )
        elif st == "des_ecb":
            axes.append(
                StageAxis("des_ecb", k * N_KEY_DERIVATION_MODES * 2)
            )
        elif st == "des_cbc":
            axes.append(
                StageAxis(
                    "des_cbc",
                    k * N_KEY_DERIVATION_MODES * DES_CBC_IV_MODES * 2,
                )
            )
        elif st == "des3":
            axes.append(StageAxis("des3", k * N_KEY_DERIVATION_MODES))
        elif st == "xtea":
            axes.append(StageAxis("xtea", k * N_KEY_DERIVATION_MODES))
        elif st in ("b64", "reverse"):
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
