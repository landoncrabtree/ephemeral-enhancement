"""
Argument parsing and configuration.

This module handles command-line argument parsing and creates
a configuration object for the pipeline execution.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass


@dataclass
class PipelineConfig:
    """
    Configuration for pipeline execution.

    Attributes:
        ciphertext: Input ciphertext to decrypt
        dictionary: Path to dictionary file
        pipeline: Pipeline string (e.g., "caesar>xor")
        threshold: Minimum score to report results
        max_hits: Maximum number of results to display
        workers: Number of worker processes
        chunk_size: Parameter combinations per worker task
        progress_every: Show progress every N tasks
        key_limit: Limit dictionary to first N keys (0 = no limit)
        bifid_alphabet: Alphabet for bifid cipher ("standard" or "base64")
        dry_run: Only show parameter space size, don't run
    """

    ciphertext: str
    dictionary: str
    pipeline: str
    threshold: float
    max_hits: int
    workers: int
    chunk_size: int
    progress_every: int
    key_limit: int
    bifid_alphabet: str
    dry_run: bool


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.

    Returns:
        Configured ArgumentParser
    """
    ap = argparse.ArgumentParser(
        description="Multi-stage cipher brute-forcing pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple Caesar cipher
  python run_pipeline.py --pipeline caesar --ciphertext "KHOOR ZRUOG"
  
  # Multi-stage pipeline with limited dictionary
  python run_pipeline.py --pipeline "caesar>bifid>xor" --key_limit 100
  
  # Parallel execution with 8 workers
  python run_pipeline.py --pipeline "b64>xor" --workers 8 --threshold 1.7
  
  # Dry run to estimate search space
  python run_pipeline.py --pipeline "caesar>bifid>xor" --dry_run
        """,
    )

    ap.add_argument(
        "--ciphertext",
        type=str,
        default="kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1",
        help="Ciphertext to decrypt",
    )

    ap.add_argument(
        "--dictionary",
        type=str,
        default="dictionary.txt",
        help="Path to dictionary file (one word per line)",
    )

    ap.add_argument(
        "--pipeline",
        type=str,
        required=True,
        help="Pipeline stages separated by '>' (e.g., caesar>bifid>b64>xor)",
    )

    ap.add_argument(
        "--threshold",
        type=float,
        default=0.80,
        help="Minimum score to report results (0.0-2.0, recommend 1.7 for English)",
    )

    ap.add_argument(
        "--max_hits",
        type=int,
        default=50,
        help="Maximum number of results to display (0 = unlimited)",
    )

    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes for parallel execution",
    )

    ap.add_argument(
        "--chunk_size",
        type=int,
        default=10_000,
        help="Parameter combinations per worker task",
    )

    ap.add_argument(
        "--progress_every",
        type=int,
        default=50,
        help="Show progress update every N completed tasks",
    )

    ap.add_argument(
        "--key_limit",
        type=int,
        default=0,
        help="Limit dictionary to first N keys (0 = use all keys, WARNING: huge search space)",
    )

    ap.add_argument(
        "--bifid_alphabet",
        type=str,
        default="standard",
        choices=["standard", "base64"],
        help="Alphabet for bifid cipher: 'standard' (5x5, I/J combined) or 'base64' (8x8)",
    )

    ap.add_argument(
        "--dry_run",
        action="store_true",
        help="Show parameter space size without running the pipeline",
    )

    return ap


def parse_args() -> PipelineConfig:
    """
    Parse command-line arguments and create configuration.

    Returns:
        PipelineConfig object
    """
    parser = create_argument_parser()
    args = parser.parse_args()

    return PipelineConfig(
        ciphertext=args.ciphertext,
        dictionary=args.dictionary,
        pipeline=args.pipeline,
        threshold=args.threshold,
        max_hits=args.max_hits,
        workers=args.workers,
        chunk_size=args.chunk_size,
        progress_every=args.progress_every,
        key_limit=args.key_limit,
        bifid_alphabet=args.bifid_alphabet,
        dry_run=args.dry_run,
    )
