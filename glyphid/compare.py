"""Compare the original texture against the fitted reconstruction.

Produces an overlay image and reports the typography the fit recovered — font size,
character spacing, baselines and line spacing — which are useful both as a sanity check
and as a description of how the original artwork was set.

Usage:
    python -m glyphid.compare IMAGE.tif --font FONT.ttf --text-file lines.txt \
        --out overlay.png
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import numpy as np
from PIL import Image

from .extract import ink_coverage, segment_lines
from .fit import correlation
from .identify import _fit_layout, analyse_line
from .render import FontRenderer


@dataclass
class LineTypography:
    """Typography recovered for one line, in source pixels."""

    index: int
    text: str
    size_px: float
    tracking_px: float
    tracking_std: float
    left_margin: float
    baseline_y: float
    correlation: float
    rms_error: float

    @property
    def tracking_em(self) -> float:
        """Letter spacing as a fraction of an em, the unit design tools use."""
        return self.tracking_px / self.size_px if self.size_px else float("nan")


def measure_tracking(
    renderer: FontRenderer, text: str, pens: list[float], size_px: float
) -> tuple[float, float]:
    """Mean and spread of the gap between consecutive glyph advances."""
    gaps = [
        pens[i + 1] - pens[i] - renderer.advance_px(text[i], size_px)
        for i in range(len(text) - 1)
        if renderer.has_glyph(text[i]) and renderer.has_glyph(text[i + 1])
    ]
    if not gaps:
        return (float("nan"), float("nan"))
    return (float(np.mean(gaps)), float(np.std(gaps)))


def reconstruct(
    renderer: FontRenderer,
    image_path: str,
    texts: list[str],
    sizes: np.ndarray,
    trackings: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, list[LineTypography]]:
    """Return (observed, rendered) full-page coverage maps plus per-line typography."""
    coverage = ink_coverage(image_path)
    raw = ink_coverage(image_path, raw=True)
    lines = segment_lines(coverage)
    if len(lines) != len(texts):
        raise SystemExit(
            f"image has {len(lines)} text lines but {len(texts)} were supplied"
        )

    rendered = np.zeros_like(coverage)
    report: list[LineTypography] = []

    for line, text in zip(lines, texts):
        resolved = analyse_line(
            renderer,
            line.coverage,
            raw[line.y0 : line.y1, line.x0 : line.x1],
            text,
            line.index,
            sizes,
            trackings,
        ).resolved
        pens, size_px, baseline_y, _ = _fit_layout(
            renderer, line.coverage, resolved, sizes, trackings
        )
        height, width = line.coverage.shape
        patch = renderer.render_placed(
            list(resolved), pens, size_px, baseline_y, width, height
        )
        rendered[line.y0 : line.y1, line.x0 : line.x1] = patch

        tracking, spread = measure_tracking(renderer, resolved, pens, size_px)
        report.append(
            LineTypography(
                index=line.index,
                text=resolved,
                size_px=size_px,
                tracking_px=tracking,
                tracking_std=spread,
                left_margin=float(pens[0]) + line.x0,
                baseline_y=baseline_y + line.y0,
                correlation=correlation(line.coverage, patch),
                rms_error=float(np.sqrt(((line.coverage - patch) ** 2).mean())),
            )
        )
    return coverage, rendered, report


def overlay_image(observed: np.ndarray, rendered: np.ndarray) -> Image.Image:
    """Two-colour overlay: agreement reads black, disagreement reads coloured.

    Observed-only ink appears magenta, reconstruction-only ink appears green, and ink
    present in both cancels to neutral dark. Any systematic mis-registration therefore
    shows up immediately as a coloured fringe.
    """
    observed = np.clip(observed, 0.0, 1.0)
    rendered = np.clip(rendered, 0.0, 1.0)
    red = 1.0 - rendered
    green = 1.0 - observed
    blue = 1.0 - np.maximum(observed, rendered)
    stack = np.dstack([red, green, blue])
    return Image.fromarray((stack * 255).astype(np.uint8))


def difference_image(
    observed: np.ndarray, rendered: np.ndarray, amplify: float = 3.0
) -> Image.Image:
    """Amplified absolute difference, as a heat map.

    The overlay reads almost pure black on a good fit, which is reassuring but tells you
    nothing about *where* the remaining error sits. Scaling the residual makes the
    structure visible: a good fit shows only thin symmetric outlines (sub-pixel edge
    placement), whereas a mis-registration shows solid one-sided blocks.
    """
    residual = np.clip(np.abs(observed - rendered) * amplify, 0.0, 1.0)
    red = np.ones_like(residual)
    green = 1.0 - residual
    blue = 1.0 - residual
    return Image.fromarray(
        (np.dstack([red, green, blue]) * 255).astype(np.uint8)
    )


def stacked_image(
    observed: np.ndarray,
    rendered: np.ndarray,
    gap: int = 10,
    amplify: float = 3.0,
) -> Image.Image:
    """Original, reconstruction, overlay and amplified residual, stacked vertically."""
    grays = [
        np.dstack([1.0 - np.clip(p, 0, 1)] * 3)
        for p in (observed, rendered)
    ]
    blocks = grays + [
        np.asarray(overlay_image(observed, rendered), dtype=np.float32) / 255.0,
        np.asarray(
            difference_image(observed, rendered, amplify), dtype=np.float32
        ) / 255.0,
    ]

    height, width, _ = blocks[0].shape
    canvas = np.ones(
        (height * len(blocks) + gap * (len(blocks) - 1), width, 3), dtype=np.float32
    )
    for i, block in enumerate(blocks):
        top = i * (height + gap)
        canvas[top : top + height] = block
    return Image.fromarray((canvas * 255).astype(np.uint8))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--font", required=True)
    parser.add_argument("--text-file", required=True)
    parser.add_argument("--out", default="overlay.png")
    parser.add_argument("--stacked", help="Also write an original/render/overlay stack.")
    parser.add_argument("--crop", help="Zoomed crop as x0,y0,x1,y1 for a detail view.")
    parser.add_argument("--zoom", type=int, default=3)
    parser.add_argument("--amplify", type=float, default=3.0,
                        help="Residual gain in the difference panel.")
    parser.add_argument("--min-size", type=float, default=44.0)
    parser.add_argument("--max-size", type=float, default=49.0)
    args = parser.parse_args()

    with open(args.text_file, encoding="utf-8") as handle:
        texts = [line.rstrip("\n") for line in handle if line.strip()]

    renderer = FontRenderer(args.font)
    observed, rendered, report = reconstruct(
        renderer,
        args.image,
        texts,
        np.arange(args.min_size, args.max_size + 0.01, 0.25),
        np.arange(0.0, 3.01, 0.25),
    )

    print(f"{'line':>4}  {'size':>6}  {'tracking':>16}  {'left':>6}  "
          f"{'baseline':>8}  {'corr':>6}  {'rms':>6}")
    for row in report:
        print(
            f"{row.index:>4}  {row.size_px:6.2f}  "
            f"{row.tracking_px:6.2f} +-{row.tracking_std:4.2f} px  "
            f"{row.left_margin:6.1f}  {row.baseline_y:8.1f}  "
            f"{row.correlation:6.4f}  {row.rms_error:6.4f}"
        )

    body = [r for r in report if len(r.text) > 12]
    if body:
        sizes = np.array([r.size_px for r in body])
        tracks = np.array([r.tracking_px for r in body])
        print(
            f"\nbody text: size {sizes.mean():.2f} +-{sizes.std():.2f} px, "
            f"tracking {tracks.mean():.2f} +-{tracks.std():.2f} px "
            f"({tracks.mean() / sizes.mean() * 1000:.0f}/1000 em)"
        )
    baselines = [r.baseline_y for r in report]
    if len(baselines) > 1:
        steps = np.diff(baselines)
        print(
            f"line spacing: {steps.mean():.1f} +-{steps.std():.1f} px "
            f"({steps.mean() / np.mean([r.size_px for r in report]):.3f} x size)"
        )

    image = overlay_image(observed, rendered)
    if args.crop:
        x0, y0, x1, y1 = (int(v) for v in args.crop.split(","))
        image = image.crop((x0, y0, x1, y1))
        image = image.resize(
            ((x1 - x0) * args.zoom, (y1 - y0) * args.zoom), Image.LANCZOS
        )
    image.save(args.out)
    print(f"\nwrote {args.out}")

    if args.stacked:
        stacked_image(observed, rendered, amplify=args.amplify).save(args.stacked)
        print(f"wrote {args.stacked}")


if __name__ == "__main__":
    main()
