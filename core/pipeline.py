"""
Pipeline configuration and validation.

This module handles parsing pipeline strings, validating stages,
and computing the parameter axes for the search space.
"""

from __future__ import annotations

from dataclasses import dataclass

from stages.key_derivation import N_KEY_DERIVATION_MODES
from stages.mcrypt_registry import (
    N_IV_STRATEGIES,
    get_all_valid_stage_names,
    get_stage_info,
    is_mcrypt_stage,
    resolve_stage_name,
)

from .utils import N_CASE_VARIANTS

# Classical cipher stages (non-mcrypt)
_CLASSICAL_STAGES = {
    "caesar",
    "bifid",
    "columnar",
    "double_columnar",
    "b64",
    "xor",
    "railfence",
    "reverse",
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
    # Resolve aliases to canonical names
    stages = [resolve_stage_name(s) for s in stages]
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
        elif is_mcrypt_stage(st):
            info = get_stage_info(st)
            assert info is not None
            # key × derivation modes × (IV strategies if mode needs IV)
            size = k * N_KEY_DERIVATION_MODES
            if info.needs_iv:
                size *= N_IV_STRATEGIES
            axes.append(StageAxis(st, size))
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
