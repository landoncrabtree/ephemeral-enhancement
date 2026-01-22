"""
Multi-stage cipher brute-forcing pipeline.

Main entry point for the cipher brute-forcing tool. This script orchestrates
the pipeline execution using the modular components in the core/ package.

Usage:
    python run_pipeline.py --pipeline "caesar>xor" --ciphertext "..." [options]

For more information:
    python run_pipeline.py --help
"""

from __future__ import annotations

from core import (
    ParallelExecutor,
    axes_for_pipeline,
    display_results,
    limit_keys,
    load_common_words,
    load_dictionary,
    parse_args,
    parse_pipeline,
)
from stages.bifid import BASE64_ALPHABET, STANDARD_ALPHABET
from stages.common import normalize_base64_alphabet


def main() -> None:
    """Main entry point for the pipeline."""
    # Parse command-line arguments
    config = parse_args()

    # Parse and validate pipeline
    stages = parse_pipeline(config.pipeline)

    # Load dictionary and keys
    dictionary = load_dictionary(config.dictionary)
    keys = limit_keys(dictionary, config.key_limit)

    # Load common words for English scoring
    common_words = load_common_words("common.txt", keys)

    # Configure bifid alphabet
    bifid_alphabet = (
        STANDARD_ALPHABET if config.bifid_alphabet == "standard" else BASE64_ALPHABET
    )

    # Normalize ciphertext if bifid is in pipeline
    if "bifid" in stages:
        ciphertext = normalize_base64_alphabet(config.ciphertext, bifid_alphabet)
    else:
        ciphertext = config.ciphertext

    # Calculate parameter space
    axes = axes_for_pipeline(stages, len(keys))
    total_combinations = 1
    for axis in axes:
        total_combinations *= axis.size

    # Display pipeline information
    print(f"[pipeline] {config.pipeline}")
    print(f"[keys] {len(keys):,}")
    if axes:
        print("[axes] " + " ".join(f"{a.name}={a.size:,}" for a in axes))
    print(f"[estimate] param_tuples={total_combinations:,}")

    # Dry run: just show estimates
    if config.dry_run:
        return

    # Create parallel executor
    executor = ParallelExecutor(
        ciphertext=ciphertext,
        keys=keys,
        stages=stages,
        threshold=config.threshold,
        bifid_alphabet=bifid_alphabet,
        common_words=common_words,
        workers=config.workers,
        chunk_size=config.chunk_size,
        progress_every=config.progress_every,
    )

    # Execute pipeline
    results = executor.execute(total_combinations)

    # Display results
    display_results(results, config.max_hits)


if __name__ == "__main__":
    main()
