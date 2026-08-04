"""Write upscaled previews of each text line, for producing an initial transcription.

The identifier re-decides every ``0``, ``O``, ``I`` and ``l`` from the pixels, so those
characters may be guessed arbitrarily when reading these images. Everything else must be
transcribed correctly, since it anchors the layout fit.

Usage:
    python -m glyphid.preview IMAGE.tif --out-dir previews
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from PIL import Image

from .extract import ink_coverage, segment_lines


def write_previews(
    image_path: str,
    out_dir: Path,
    zoom: int = 3,
    chunk_px: int = 520,
    overlap_px: int = 24,
) -> list[Path]:
    """Render each segmented line to disk, split into readable horizontal chunks."""
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage = ink_coverage(image_path)
    written: list[Path] = []

    for line in segment_lines(coverage):
        art = ((1.0 - line.coverage) * 255).astype(np.uint8)
        image = Image.fromarray(art)
        height, width = art.shape
        starts = list(range(0, width, chunk_px - overlap_px)) or [0]
        for part, start in enumerate(starts):
            stop = min(width, start + chunk_px)
            if stop - start < overlap_px and part:
                break
            crop = image.crop((start, 0, stop, height))
            path = out_dir / f"line{line.index}_{part}.png"
            crop.resize(
                ((stop - start) * zoom, height * zoom), Image.LANCZOS
            ).save(path)
            written.append(path)
        print(
            f"line {line.index}: y={line.y0}-{line.y1} x={line.x0}-{line.x1} "
            f"({len(starts)} chunk(s))"
        )
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--out-dir", default="previews")
    parser.add_argument("--zoom", type=int, default=3)
    parser.add_argument("--chunk-px", type=int, default=520,
                        help="Width of each preview chunk, in source pixels.")
    args = parser.parse_args()

    written = write_previews(
        args.image, Path(args.out_dir), zoom=args.zoom, chunk_px=args.chunk_px
    )
    print(f"\nwrote {len(written)} preview(s) to {args.out_dir}/")
    print("Transcribe them into a text file, one line per text line.")
    print("Any 0/O/I/l may be guessed - they are re-decided from the pixels.")


if __name__ == "__main__":
    main()
