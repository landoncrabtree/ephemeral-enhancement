"""
Worker state and chunk processing.

This module handles the multiprocessing worker state and chunk processing logic.
Workers process batches of parameter combinations in parallel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .executor import StageExecutor
from .pipeline import StageAxis, axes_for_pipeline
from .utils import mixed_radix_unrank


@dataclass
class WorkerState:
    """
    State maintained by each worker process.

    Attributes:
        ciphertext: Input ciphertext
        keys: Dictionary of keys
        stages: List of stage names
        axes: Parameter axes
        bases: Size of each axis
        threshold: Minimum score to report
        bifid_alphabet: Alphabet for bifid cipher
        common_words: Common words for English scoring
    """

    ciphertext: str
    keys: list[str]
    stages: list[str]
    axes: list[StageAxis]
    bases: list[int]
    threshold: float
    bifid_alphabet: str
    common_words: set[str] | None


# Global worker state (set by init_worker)
_WORKER_STATE: WorkerState | None = None


def init_worker(
    ciphertext: str,
    keys: list[str],
    stages: list[str],
    threshold: float,
    bifid_alphabet: str,
    common_words: set[str] | None = None,
) -> None:
    """
    Initialize worker process state.

    This is called once per worker process when the multiprocessing
    pool is created.

    Args:
        ciphertext: Input ciphertext
        keys: Dictionary of keys
        stages: List of stage names
        threshold: Minimum score to report
        bifid_alphabet: Alphabet for bifid cipher
        common_words: Common words for English scoring
    """
    global _WORKER_STATE

    axes = axes_for_pipeline(stages, len(keys))
    bases = [a.size for a in axes]

    _WORKER_STATE = WorkerState(
        ciphertext=ciphertext,
        keys=keys,
        stages=stages,
        axes=axes,
        bases=bases,
        threshold=threshold,
        bifid_alphabet=bifid_alphabet,
        common_words=common_words,
    )


def process_chunk(
    task: tuple[int, int],
) -> tuple[int, list[tuple[float, Dict[str, Any]]]]:
    """
    Process a chunk of parameter combinations.

    This is the main worker function that processes a range of parameter
    combinations and returns all hits above the threshold.

    Args:
        task: (start, end) indices into linearized parameter space

    Returns:
        (attempts, hits) where hits is list of (score, metadata) tuples
    """
    assert _WORKER_STATE is not None, "Worker not initialized"

    state = _WORKER_STATE
    executor = StageExecutor(
        ciphertext=state.ciphertext,
        keys=state.keys,
        stages=state.stages,
        bifid_alphabet=state.bifid_alphabet,
        common_words=state.common_words,
    )

    attempts = 0
    hits: list[tuple[float, Dict[str, Any]]] = []

    start, end = task
    for x in range(start, end):
        attempts += 1
        param_idxs = mixed_radix_unrank(x, state.bases)
        score, meta = executor.execute_pipeline(param_idxs, state.threshold)

        if score is not None and meta is not None:
            hits.append((score, meta))

    return attempts, hits
