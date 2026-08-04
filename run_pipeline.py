"""
Multi-stage cipher brute-forcing pipeline.

Main entry point for the cipher brute-forcing tool. This script orchestrates
the pipeline execution using the modular components in the core/ package.

Usage:
    python run_pipeline.py --pipeline "caesar>xor" --ciphertext "..." [options]

Optional shared run tracking (see backend/README.md):
    python run_pipeline.py --join-network <token>     # once; saves ~/.ee/config

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
from core.tracker import (
    SEMANTICS_VERSION,
    Tracker,
    compute_fingerprint,
    file_sha256,
    git_commit,
    save_config,
    sha256_text,
)
from core.utils import resolve_data_path
from stages.bifid import BASE64_ALPHABET, STANDARD_ALPHABET
from stages.common import normalize_base64_alphabet


def _join_network(config) -> None:
    """Persist a join token, then confirm the server is reachable."""
    path = save_config(config.join_network, config.server)
    tracker = Tracker()
    print(f"[network] token saved to {path}")
    print(f"[network] server {tracker.config.server}")
    print(f"[network] runner {tracker.config.runner}  (hashed machine id)")

    version = tracker.upstream_version()
    if version and "sha" in version:
        print(f"[network] connected - upstream at {version['short_sha']}")
    else:
        print("[network] warning: server unreachable; runs will not be shared")


def main() -> None:
    """Main entry point for the pipeline."""
    config = parse_args()

    # --join-network is a one-shot setup command.
    if config.join_network:
        _join_network(config)
        return

    stages = parse_pipeline(config.pipeline)

    dictionary = load_dictionary(config.dictionary)
    keys = limit_keys(dictionary, config.key_limit)
    common_words = load_common_words("common.txt", keys)

    bifid_alphabet = (
        STANDARD_ALPHABET if config.bifid_alphabet == "standard" else BASE64_ALPHABET
    )

    if "bifid" in stages:
        ciphertext = normalize_base64_alphabet(config.ciphertext, bifid_alphabet)
    else:
        ciphertext = config.ciphertext

    axes = axes_for_pipeline(stages, len(keys), vary_case=config.vary_case)
    total_combinations = 1
    for axis in axes:
        total_combinations *= axis.size

    print(f"[pipeline] {config.pipeline}")
    print(f"[keys] {len(keys):,}" + (" (vary-case: 3 per word)" if config.vary_case else ""))
    if axes:
        print("[axes] " + " ".join(f"{a.name}={a.size:,}" for a in axes))
    print(f"[estimate] param_tuples={total_combinations:,}")

    if config.dry_run:
        return

    # --- tracker: was this exact search space already covered? ---
    tracker = None if config.no_track else Tracker()
    fingerprint = None
    dictionary_sha = None

    if tracker is not None and tracker.enabled:
        dictionary_sha = file_sha256(str(resolve_data_path(config.dictionary)))
        fingerprint = compute_fingerprint(
            stages=stages,
            axes=[(a.name, a.size) for a in axes],
            ciphertext=ciphertext,
            dictionary_sha=dictionary_sha,
            n_keys=len(keys),
            vary_case=config.vary_case,
        )

        update = tracker.check_for_updates()
        if update:
            print(update)

        previous = tracker.lookup(fingerprint)
        if previous and not config.force:
            print(
                f"[network] already searched by "
                f"{previous.get('runner') or 'someone'} on {previous.get('created_at')} "
                f"- {previous.get('combos') or 0:,} combos, "
                f"{previous.get('hits') or 0} hits"
            )
            if previous.get("best_score"):
                preview = (previous.get("best_plaintext") or "")[:100]
                print(f"[network] best {previous['best_score']:.3f}: {preview}")
            print("[network] skipping (use --force to run anyway)")
            return

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
        vary_case=config.vary_case,
    )

    results = executor.execute(total_combinations)

    # Capture the best hit before display_results(), which both sorts hits in
    # place and pops "preview" out of each metadata dict to print it. Reading
    # afterwards loses the plaintext; reading hits[0] beforehand would pick an
    # arbitrary hit, since the list is unsorted until display_results runs.
    best_score, best_meta, best_plaintext = None, None, None
    if results.hits:
        best_score, meta = max(results.hits, key=lambda h: h[0])
        best_meta = dict(meta)
        best_plaintext = best_meta.pop("preview", None)

    display_results(results, config.max_hits)

    # --- tracker: record what was covered ---
    if tracker is not None and tracker.enabled and fingerprint:
        ok = tracker.submit({
            "fingerprint": fingerprint,
            "pipeline": config.pipeline,
            "ciphertext": ciphertext,
            "ciphertext_sha": sha256_text(ciphertext),
            "dictionary": config.dictionary,
            "dictionary_sha": dictionary_sha,
            "n_keys": len(keys),
            "axes": [(a.name, a.size) for a in axes],
            "combos": results.attempts,
            "hits": len(results.hits),
            "best_score": best_score,
            "best_plaintext": best_plaintext,
            "best_meta": best_meta,
            "threshold": config.threshold,
            "vary_case": config.vary_case,
            "status": "complete",
            "semantics_version": SEMANTICS_VERSION,
            "git_commit": git_commit(),
            "runner": tracker.config.runner,
            "duration_s": results.elapsed_time,
        })
        print("[network] run recorded" if ok else "[network] server unreachable")


if __name__ == "__main__":
    main()
