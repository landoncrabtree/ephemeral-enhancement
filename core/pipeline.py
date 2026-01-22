"""
Pipeline configuration and validation.

This module handles parsing pipeline strings, validating stages,
and computing the parameter axes for the search space.
"""

from __future__ import annotations

from dataclasses import dataclass

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


def axes_for_pipeline(stages: list[str], n_keys: int) -> list[StageAxis]:
    """
    Compute parameter axes for a pipeline.

    Each stage that requires parameters (keys, shifts, rails) contributes
    one axis to the search space. Stages like b64 and reverse have no
    parameters and don't contribute axes.

    Args:
        stages: List of stage names
        n_keys: Number of keys in dictionary

    Returns:
        List of StageAxis objects defining the parameter space
    """
    axes: list[StageAxis] = []
    for st in stages:
        if st == "caesar":
            axes.append(StageAxis("caesar", 26))
        elif st == "railfence":
            axes.append(StageAxis("railfence", 29))  # 2-30 rails
        elif st in ("bifid", "columnar", "xor"):
            axes.append(StageAxis(st, n_keys))
        elif st == "double_columnar":
            # Ordered pairs of keys: (key1, key2)
            axes.append(StageAxis("double_columnar", n_keys * n_keys))
        elif st in ("b64", "reverse"):
            # No parameters
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
