from __future__ import annotations

import argparse
import base64
import multiprocessing as mp
import time
from dataclasses import dataclass
from typing import Any, Dict, Literal

from stages.bifid import BASE64_ALPHABET as B64_ALPHA
from stages.bifid import bifid_decrypt, build_keyed_square
from stages.columnar import columnar_decrypt
from stages.common import normalize_base64_alphabet, printable_ratio
from stages.double_columnar import double_columnar_decrypt
from stages.xor import repeating_xor

Kind = Literal["text", "bytes"]


@dataclass(slots=True)
class StageAxis:
    name: str
    size: int


def load_dictionary(path: str) -> list[str]:
    with open(path, "r") as f:
        return [w.strip() for w in f if w.strip()]


def limit_keys(dictionary: list[str], limit: int) -> list[str]:
    return dictionary[:limit] if limit > 0 else dictionary


def caesar_shift_text(text: str, shift: int) -> str:
    shift %= 26
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(65 + ((o - 65 + shift) % 26)))
        elif 97 <= o <= 122:
            out.append(chr(97 + ((o - 97 + shift) % 26)))
        else:
            out.append(ch)
    return "".join(out)


def parse_pipeline(pipeline: str) -> list[str]:
    stages = [s.strip() for s in pipeline.split(">") if s.strip()]
    valid = {"caesar", "bifid", "columnar", "double_columnar", "b64", "xor"}
    bad = [s for s in stages if s not in valid]
    if bad:
        raise SystemExit(f"Unknown stages in pipeline: {bad}. Valid: {sorted(valid)}")
    return stages


def axes_for_pipeline(stages: list[str], n_keys: int) -> list[StageAxis]:
    axes: list[StageAxis] = []
    for st in stages:
        if st == "caesar":
            axes.append(StageAxis("caesar", 26))
        elif st in ("bifid", "columnar", "xor"):
            axes.append(StageAxis(st, n_keys))
        elif st == "double_columnar":
            axes.append(StageAxis("double_columnar", n_keys * n_keys))  # ordered pairs
        elif st == "b64":
            continue
    return axes


def mixed_radix_unrank(x: int, bases: list[int]) -> list[int]:
    idxs: list[int] = []
    for b in reversed(bases):
        idxs.append(x % b)
        x //= b
    return list(reversed(idxs))


# --- multiprocessing worker state ---
_W_CT: str | None = None
_W_KEYS: list[str] | None = None
_W_STAGES: list[str] | None = None
_W_AXES: list[StageAxis] | None = None
_W_BASES: list[int] | None = None
_W_THRESHOLD: float = 0.0
_W_MAX_HITS: int = 0


def init_worker(
    ct: str, keys: list[str], stages: list[str], threshold: float, max_hits: int
) -> None:
    global _W_CT, _W_KEYS, _W_STAGES, _W_AXES, _W_BASES, _W_THRESHOLD, _W_MAX_HITS
    _W_CT = ct
    _W_KEYS = keys
    _W_STAGES = stages
    _W_AXES = axes_for_pipeline(stages, len(keys))
    _W_BASES = [a.size for a in _W_AXES]
    _W_THRESHOLD = threshold
    _W_MAX_HITS = max_hits


def run_one_combo(param_idxs: list[int]) -> tuple[float | None, Dict[str, Any] | None]:
    """
    Evaluate the pipeline for one parameter tuple.
    Returns (printable_ratio, meta) on hit else (None, None).
    """
    assert _W_CT is not None
    assert _W_KEYS is not None
    assert _W_STAGES is not None
    assert _W_AXES is not None

    # Build meta from axis selections
    meta: Dict[str, Any] = {}
    axis_pos = 0

    kind: Kind = "text"
    payload: str | bytes = _W_CT

    for st in _W_STAGES:
        if st == "b64":
            if kind != "text":
                return (None, None)
            try:
                payload = base64.b64decode(payload, validate=True)
            except Exception:
                return (None, None)
            kind = "bytes"
            continue

        if st == "caesar":
            shift = param_idxs[axis_pos]
            axis_pos += 1
            meta["caesar_shift"] = shift
            if kind != "text":
                return (None, None)
            payload = caesar_shift_text(payload, shift)  # type: ignore[arg-type]
            continue

        if st == "bifid":
            ki = param_idxs[axis_pos]
            axis_pos += 1
            key = _W_KEYS[ki]
            meta["bifid_key"] = key
            if kind != "text":
                return (None, None)
            sq = build_keyed_square(B64_ALPHA, key, size=8)
            payload = bifid_decrypt(payload, sq, period=len(payload), size=8)  # type: ignore[arg-type]
            continue

        if st == "columnar":
            ki = param_idxs[axis_pos]
            axis_pos += 1
            key = _W_KEYS[ki]
            meta["columnar_key"] = key
            if kind != "text":
                return (None, None)
            payload = columnar_decrypt(payload, key)  # type: ignore[arg-type]
            continue

        if st == "double_columnar":
            pi = param_idxs[axis_pos]
            axis_pos += 1
            n = len(_W_KEYS)
            k1 = _W_KEYS[pi // n]
            k2 = _W_KEYS[pi % n]
            meta["double_columnar_key1"] = k1
            meta["double_columnar_key2"] = k2
            if kind != "text":
                return (None, None)
            payload = double_columnar_decrypt(payload, k1, k2)  # type: ignore[arg-type]
            continue

        if st == "xor":
            ki = param_idxs[axis_pos]
            axis_pos += 1
            key = _W_KEYS[ki]
            meta["xor_key"] = key
            if kind != "bytes":
                return (None, None)
            payload = repeating_xor(payload, key.encode("utf-8", "ignore"))  # type: ignore[arg-type]
            continue

        raise ValueError(f"Unhandled stage: {st}")

    if kind != "bytes":
        return (None, None)
    pr = printable_ratio(payload)  # type: ignore[arg-type]
    if pr >= _W_THRESHOLD:
        return (pr, meta)
    return (None, None)


def worker_run_chunk(
    task: tuple[int, int],
) -> tuple[int, list[tuple[float, Dict[str, Any]]]]:
    """
    task = (start, end) over linearized parameter tuples.
    Returns (attempts, hits)
    """
    assert _W_BASES is not None
    attempts = 0
    hits: list[tuple[float, Dict[str, Any]]] = []

    start, end = task
    for x in range(start, end):
        attempts += 1
        idxs = mixed_radix_unrank(x, _W_BASES)
        pr, meta = run_one_combo(idxs)
        if pr is not None and meta is not None:
            hits.append((pr, meta))
            if _W_MAX_HITS and len(hits) >= _W_MAX_HITS:
                break
    return attempts, hits


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ciphertext", type=str, default="")
    ap.add_argument("--dictionary", type=str, default="dictionary.txt")
    ap.add_argument(
        "--pipeline", type=str, required=True, help="e.g. caesar>bifid>b64>xor"
    )
    ap.add_argument("--threshold", type=float, default=0.80)
    ap.add_argument("--max_hits", type=int, default=50)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument(
        "--chunk_size",
        type=int,
        default=10_000,
        help="parameter tuples per worker task",
    )
    ap.add_argument(
        "--progress_every",
        type=int,
        default=50,
        help="progress update per N completed tasks",
    )
    ap.add_argument(
        "--key_limit",
        type=int,
        default=0,
        help="0 = use entire dictionary (WARNING: huge)",
    )
    ap.add_argument("--dry_run", action="store_true")
    args = ap.parse_args()

    if not args.ciphertext:
        args.ciphertext = "kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1"

    stages = parse_pipeline(args.pipeline)
    dictionary = load_dictionary(args.dictionary)
    keys = limit_keys(dictionary, args.key_limit)
    ct = normalize_base64_alphabet(args.ciphertext, B64_ALPHA)

    axes = axes_for_pipeline(stages, len(keys))
    total = 1
    for a in axes:
        total *= a.size

    print(f"[pipeline] {args.pipeline}")
    print(f"[keys] {len(keys):,}")
    if axes:
        print("[axes] " + " ".join(f"{a.name}={a.size:,}" for a in axes))
    print(f"[estimate] param_tuples={total:,}")
    if args.dry_run:
        return

    # Build chunk tasks
    chunk = max(1, args.chunk_size)
    tasks: list[tuple[int, int]] = []
    for start in range(0, total, chunk):
        tasks.append((start, min(total, start + chunk)))

    # Single-process path (still uses the same worker code for consistency)
    if args.workers <= 1:
        init_worker(ct, keys, stages, args.threshold, args.max_hits)
        t0 = time.time()
        attempts = 0
        hits_total = 0
        for i, task in enumerate(tasks, start=1):
            a, hits = worker_run_chunk(task)
            attempts += a
            for pr, meta in hits:
                print(f"{pr:.3f} meta={meta}")
                hits_total += 1
                if args.max_hits and hits_total >= args.max_hits:
                    dt = max(1e-9, time.time() - t0)
                    print(
                        f"[done] attempts={attempts:,} hits={hits_total} time={dt:.2f}s"
                    )
                    return
            if args.progress_every and i % args.progress_every == 0:
                dt = max(1e-9, time.time() - t0)
                print(
                    f"[progress] tasks={i:,}/{len(tasks):,} attempts={attempts:,} hits={hits_total} rate={attempts / dt:,.1f}/s"
                )
        dt = max(1e-9, time.time() - t0)
        print(f"[done] attempts={attempts:,} hits={hits_total} time={dt:.2f}s")
        return

    # Multiprocessing path
    t0 = time.time()
    attempts = 0
    hits_total = 0
    with mp.Pool(
        processes=args.workers,
        initializer=init_worker,
        initargs=(ct, keys, stages, args.threshold, args.max_hits),
    ) as pool:
        for i, (a, hits) in enumerate(
            pool.imap_unordered(worker_run_chunk, tasks, chunksize=1), start=1
        ):
            attempts += a
            for pr, meta in hits:
                print(f"{pr:.3f} meta={meta}")
                hits_total += 1
                if args.max_hits and hits_total >= args.max_hits:
                    pool.terminate()
                    pool.join()
                    dt = max(1e-9, time.time() - t0)
                    print(
                        f"[done] attempts={attempts:,} hits={hits_total} time={dt:.2f}s"
                    )
                    return
            if args.progress_every and i % args.progress_every == 0:
                dt = max(1e-9, time.time() - t0)
                print(
                    f"[progress] tasks={i:,}/{len(tasks):,} attempts={attempts:,} hits={hits_total} rate={attempts / dt:,.1f}/s"
                )
    dt = max(1e-9, time.time() - t0)
    print(f"[done] attempts={attempts:,} hits={hits_total} time={dt:.2f}s")


if __name__ == "__main__":
    main()
