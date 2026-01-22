"""
Parallel execution orchestration.

This module handles both single-process and multi-process execution
of the pipeline, including task creation, progress tracking, and
result collection.
"""

from __future__ import annotations

import multiprocessing as mp
import time
from dataclasses import dataclass
from typing import Any, Dict

from .worker import init_worker, process_chunk


@dataclass
class ExecutionResults:
    """
    Results from pipeline execution.

    Attributes:
        attempts: Total parameter combinations tried
        hits: List of (score, metadata) tuples for all results above threshold
        elapsed_time: Total execution time in seconds
    """

    attempts: int
    hits: list[tuple[float, Dict[str, Any]]]
    elapsed_time: float


class ParallelExecutor:
    """
    Orchestrates parallel execution of the pipeline.

    Handles both single-process and multi-process execution modes,
    with progress tracking and result collection.
    """

    def __init__(
        self,
        ciphertext: str,
        keys: list[str],
        stages: list[str],
        threshold: float,
        bifid_alphabet: str,
        common_words: set[str] | None,
        workers: int,
        chunk_size: int,
        progress_every: int,
    ):
        """
        Initialize the parallel executor.

        Args:
            ciphertext: Input ciphertext
            keys: Dictionary of keys
            stages: List of stage names
            threshold: Minimum score to report
            bifid_alphabet: Alphabet for bifid cipher
            common_words: Common words for English scoring
            workers: Number of worker processes
            chunk_size: Parameter combinations per chunk
            progress_every: Show progress every N chunks
        """
        self.ciphertext = ciphertext
        self.keys = keys
        self.stages = stages
        self.threshold = threshold
        self.bifid_alphabet = bifid_alphabet
        self.common_words = common_words
        self.workers = workers
        self.chunk_size = chunk_size
        self.progress_every = progress_every

    def create_tasks(self, total_combinations: int) -> list[tuple[int, int]]:
        """
        Create task chunks for workers.

        Args:
            total_combinations: Total number of parameter combinations

        Returns:
            List of (start, end) tuples defining each chunk
        """
        chunk = max(1, self.chunk_size)
        tasks: list[tuple[int, int]] = []
        for start in range(0, total_combinations, chunk):
            tasks.append((start, min(total_combinations, start + chunk)))
        return tasks

    def run_single_process(self, tasks: list[tuple[int, int]]) -> ExecutionResults:
        """
        Run pipeline in single-process mode.

        Args:
            tasks: List of task chunks

        Returns:
            ExecutionResults with all hits and timing
        """
        # Initialize worker state in main process
        init_worker(
            self.ciphertext,
            self.keys,
            self.stages,
            self.threshold,
            self.bifid_alphabet,
            self.common_words,
        )

        t0 = time.time()
        attempts = 0
        all_hits: list[tuple[float, Dict[str, Any]]] = []

        for i, task in enumerate(tasks, start=1):
            a, hits = process_chunk(task)
            attempts += a
            all_hits.extend(hits)

            if self.progress_every and i % self.progress_every == 0:
                dt = max(1e-9, time.time() - t0)
                print(
                    f"[progress] tasks={i:,}/{len(tasks):,} "
                    f"attempts={attempts:,} hits={len(all_hits)} "
                    f"rate={attempts / dt:,.1f}/s"
                )

        elapsed = time.time() - t0
        return ExecutionResults(attempts, all_hits, elapsed)

    def run_multiprocess(self, tasks: list[tuple[int, int]]) -> ExecutionResults:
        """
        Run pipeline in multi-process mode.

        Args:
            tasks: List of task chunks

        Returns:
            ExecutionResults with all hits and timing
        """
        t0 = time.time()
        attempts = 0
        all_hits: list[tuple[float, Dict[str, Any]]] = []

        with mp.Pool(
            processes=self.workers,
            initializer=init_worker,
            initargs=(
                self.ciphertext,
                self.keys,
                self.stages,
                self.threshold,
                self.bifid_alphabet,
                self.common_words,
            ),
        ) as pool:
            for i, (a, hits) in enumerate(
                pool.imap_unordered(process_chunk, tasks, chunksize=1), start=1
            ):
                attempts += a
                all_hits.extend(hits)

                if self.progress_every and i % self.progress_every == 0:
                    dt = max(1e-9, time.time() - t0)
                    print(
                        f"[progress] tasks={i:,}/{len(tasks):,} "
                        f"attempts={attempts:,} hits={len(all_hits)} "
                        f"rate={attempts / dt:,.1f}/s"
                    )

        elapsed = time.time() - t0
        return ExecutionResults(attempts, all_hits, elapsed)

    def execute(self, total_combinations: int) -> ExecutionResults:
        """
        Execute the pipeline (single or multi-process).

        Args:
            total_combinations: Total number of parameter combinations

        Returns:
            ExecutionResults with all hits and timing
        """
        tasks = self.create_tasks(total_combinations)

        if self.workers <= 1:
            return self.run_single_process(tasks)
        else:
            return self.run_multiprocess(tasks)


def display_results(
    results: ExecutionResults,
    max_hits: int,
) -> None:
    """
    Display execution results.

    Sorts hits by score (descending) and displays top N results.

    Args:
        results: ExecutionResults from execution
        max_hits: Maximum number of results to display (0 = all)
    """
    # Sort by score (descending)
    results.hits.sort(key=lambda x: x[0], reverse=True)

    # Limit results
    hits_to_show = results.hits[:max_hits] if max_hits else results.hits

    # Display results
    for score, meta in hits_to_show:
        print(f"{score:.3f} meta={meta}")

    # Display summary
    print(
        f"[done] attempts={results.attempts:,} "
        f"hits={len(results.hits)} "
        f"time={results.elapsed_time:.2f}s"
    )
