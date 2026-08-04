"""End-to-end glyph disambiguation for a BO3 cipher texture.

Usage:
    python -m glyphid.identify IMAGE.tif --font FONT.ttf --text-file lines.txt
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize, minimize_scalar

from .extract import ink_coverage, segment_lines
from .fit import coarse_search, correlation, fit_line
from .render import FontRenderer
from .solver import GlyphVerdict, score_glyph, track_pens

AMBIGUOUS = "0OIl"


@dataclass
class LineReport:
    index: int
    text: str
    size_px: float
    baseline_y: float
    tracking_px: float
    correlation: float
    verdicts: list[GlyphVerdict]

    @property
    def resolved(self) -> str:
        """The line re-spelled using the winning candidate at each position."""
        chars = list(self.text)
        for verdict in self.verdicts:
            chars[verdict.index] = verdict.best_char
        return "".join(chars)


def _refit_scale(
    renderer: FontRenderer,
    observed: np.ndarray,
    text: str,
    pens: list[float],
    size_px: float,
    baseline_y: float,
) -> tuple[float, float]:
    """Re-estimate (size, baseline) with the pen positions held fixed."""
    height, width = observed.shape
    mass = max(float(observed.sum()), 1e-6)

    def cost(params: np.ndarray) -> float:
        size, baseline = float(params[0]), float(params[1])
        if not 4.0 < size < 400.0:
            return 1e9
        rendered = renderer.render_placed(
            list(text), pens, size, baseline, width, height
        )
        return float(((observed - rendered) ** 2).sum() / mass)

    result = minimize(
        cost,
        np.array([size_px, baseline_y]),
        method="Nelder-Mead",
        options={"xatol": 1e-3, "fatol": 1e-10, "maxiter": 300},
    )
    return float(result.x[0]), float(result.x[1])


def _fit_layout(
    renderer: FontRenderer,
    observed: np.ndarray,
    text: str,
    sizes: np.ndarray,
    trackings: np.ndarray,
    rounds: int = 2,
    fixed_size: float | None = None,
) -> tuple[list[float], float, float, float]:
    """Fit pen positions, size and baseline for one line of known text.

    With ``fixed_size`` the size is held and only position is fitted, which is what the
    global-size path uses.
    """
    seed = coarse_search(renderer, observed, text, sizes, trackings, 4.0, 40.0)
    fit = fit_line(renderer, observed, text, *seed)

    size_px, baseline_y = fit.size_px, fit.baseline_y
    if fixed_size is not None:
        size_px = fixed_size
    pens = renderer.pen_positions(text, size_px, fit.tracking_px, fit.x0)
    for _ in range(rounds):
        pens = track_pens(
            renderer, observed, text, size_px, fit.tracking_px, fit.x0, baseline_y
        )
        if fixed_size is None:
            size_px, baseline_y = _refit_scale(
                renderer, observed, text, pens, size_px, baseline_y
            )
        else:
            baseline_y = _refit_baseline(
                renderer, observed, text, pens, size_px, baseline_y
            )
    return pens, size_px, baseline_y, fit.tracking_px


def _refit_baseline(
    renderer: FontRenderer,
    observed: np.ndarray,
    text: str,
    pens: list[float],
    size_px: float,
    baseline_y: float,
) -> float:
    """Re-estimate the baseline with size and pen positions held fixed."""
    height, width = observed.shape
    mass = max(float(observed.sum()), 1e-6)

    def cost(baseline: float) -> float:
        rendered = renderer.render_placed(
            list(text), pens, size_px, float(baseline), width, height
        )
        return float(((observed - rendered) ** 2).sum() / mass)

    result = minimize_scalar(
        cost, bounds=(baseline_y - 3.0, baseline_y + 3.0), method="bounded",
        options={"xatol": 5e-3},
    )
    return float(result.x)


def fit_global_size(
    renderer: FontRenderer,
    observed_lines: list[np.ndarray],
    texts: list[str],
    sizes: np.ndarray,
    trackings: np.ndarray,
) -> float:
    """Fit one font size shared by every line.

    Size and tracking are partially degenerate — larger glyphs with tighter tracking
    occupy nearly the same width — so a per-line fit can settle anywhere along a shallow
    valley, and the scatter that produces is the dominant error term. Body text on a
    single texture is set at one size, so fitting it once against all lines at once
    resolves the degeneracy with far more evidence and puts every line on the same
    reference scale, which matters because the discriminator references are evaluated at
    the fitted size.
    """
    seeds = [
        fit_line(
            renderer, obs, text, *coarse_search(renderer, obs, text, sizes, trackings, 4.0, 40.0)
        )
        for obs, text in zip(observed_lines, texts)
    ]

    def total_cost(size_px: float) -> float:
        total = 0.0
        for obs, text, seed in zip(observed_lines, texts, seeds):
            height, width = obs.shape

            def cost(baseline: float) -> float:
                pens = track_pens(
                    renderer, obs, text, size_px, seed.tracking_px, seed.x0, baseline
                )
                rendered = renderer.render_placed(
                    list(text), pens, size_px, float(baseline), width, height
                )
                return float(((obs - rendered) ** 2).sum())

            total += minimize_scalar(
                cost,
                bounds=(seed.baseline_y - 2.5, seed.baseline_y + 2.5),
                method="bounded",
                options={"xatol": 2e-2},
            ).fun
        return total

    grid = np.arange(float(sizes[0]), float(sizes[-1]) + 0.01, 0.4)
    scores = [total_cost(s) for s in grid]
    best = float(grid[int(np.argmin(scores))])
    refined = minimize_scalar(
        total_cost, bounds=(best - 0.4, best + 0.4), method="bounded",
        options={"xatol": 1e-2},
    )
    return float(refined.x)


def analyse_line(
    renderer: FontRenderer,
    observed: np.ndarray,
    raw_coverage: np.ndarray,
    text: str,
    index: int,
    sizes: np.ndarray,
    trackings: np.ndarray,
    rounds: int = 2,
    passes: int = 3,
    fixed_size: float | None = None,
) -> LineReport:
    """Fit the layout of one line, then measure every confusable glyph in it.

    The whole fit is repeated after each round of decisions. ``0`` and ``O`` have
    different advance widths (426 vs 477 units), so a wrong letter in the supplied
    transcription displaces every glyph after it; re-fitting with the corrected text
    realigns the line so the next pass measures through correctly placed windows.
    Iterating to a fixed point is what makes the result independent of how good the
    initial guess was.
    """
    current = text
    seen: set[str] = set()
    pens, size_px, baseline_y, tracking_px = _fit_layout(
        renderer, observed, current, sizes, trackings, rounds, fixed_size
    )
    verdicts: list[GlyphVerdict] = []

    for _ in range(passes):
        verdicts = [
            score_glyph(renderer, raw_coverage, current, pens, size_px, baseline_y, i)
            for i, char in enumerate(current)
            if char in AMBIGUOUS
        ]
        chars = list(current)
        for verdict in verdicts:
            chars[verdict.index] = verdict.best_char
        resolved = "".join(chars)
        if resolved == current or resolved in seen:
            break
        seen.add(current)
        current = resolved
        pens, size_px, baseline_y, tracking_px = _fit_layout(
            renderer, observed, current, sizes, trackings, rounds, fixed_size
        )

    height, width = observed.shape
    rendered = renderer.render_placed(
        list(current), pens, size_px, baseline_y, width, height
    )
    return LineReport(
        index=index,
        text=text,
        size_px=size_px,
        baseline_y=baseline_y,
        tracking_px=tracking_px,
        correlation=correlation(observed, rendered),
        verdicts=verdicts,
    )


def _diff_marks(before: str, after: str) -> str:
    return "".join("^" if a != b else " " for a, b in zip(before, after))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--font", required=True)
    parser.add_argument("--text-file", required=True,
                        help="One transcription line per text line in the image. "
                             "Any 0/O/I/l may be guessed; they get re-decided.")
    parser.add_argument("--min-size", type=float, default=44.0)
    parser.add_argument("--max-size", type=float, default=49.0)
    parser.add_argument("--per-line-size", action="store_true",
                        help="Fit font size independently per line instead of once "
                             "globally. Noisier; kept for diagnostics.")
    parser.add_argument("--json", help="Write the full per-glyph report here.")
    args = parser.parse_args()

    coverage = ink_coverage(args.image)
    raw_coverage = ink_coverage(args.image, raw=True)
    lines = segment_lines(coverage)
    with open(args.text_file, encoding="utf-8") as handle:
        texts = [line.rstrip("\n") for line in handle if line.strip()]
    if len(texts) != len(lines):
        raise SystemExit(
            f"image has {len(lines)} text lines but {len(texts)} were supplied"
        )

    renderer = FontRenderer(args.font)
    sizes = np.arange(args.min_size, args.max_size + 0.01, 0.25)
    trackings = np.arange(0.0, 3.01, 0.25)

    global_size: float | None = None
    if not args.per_line_size and len(lines) > 1:
        global_size = fit_global_size(
            renderer, [line.coverage for line in lines], texts, sizes, trackings
        )
        print(f"global font size: {global_size:.2f} px (shared by all lines)\n")

    reports: list[LineReport] = []
    for line, text in zip(lines, texts):
        report = analyse_line(
            renderer,
            line.coverage,
            raw_coverage[line.y0 : line.y1, line.x0 : line.x1],
            text,
            line.index,
            sizes,
            trackings,
            fixed_size=global_size,
        )
        reports.append(report)
        print(
            f"\nline {report.index}   size={report.size_px:.2f}px  "
            f"corr={report.correlation:.4f}"
        )
        print(f"  in   {report.text}")
        print(f"  out  {report.resolved}")
        marks = _diff_marks(report.text, report.resolved)
        if "^" in marks:
            print(f"       {marks}")
        for verdict in report.verdicts:
            if verdict.discriminator is None:
                continue
            first, second = verdict.discriminator.pair
            flag = "OK" if verdict.confident else "??"
            print(
                f"   {flag} [{verdict.index:3d}] {verdict.observed_char} -> "
                f"{verdict.best_char}   {verdict.discriminator.name} = "
                f"{verdict.value:.5f}   "
                f"({first}={verdict.references[first]:.5f}, "
                f"{second}={verdict.references[second]:.5f})   "
                f"margin={verdict.margin * 200:5.1f}%"
            )

    print("\n=== resolved text ===")
    for report in reports:
        print(report.resolved)

    if args.json:
        payload = [
            {
                "line": report.index,
                "input": report.text,
                "resolved": report.resolved,
                "size_px": report.size_px,
                "correlation": report.correlation,
                "glyphs": [
                    {
                        "index": v.index,
                        "read": v.observed_char,
                        "best": v.best_char,
                        "metric": v.discriminator.name if v.discriminator else None,
                        "value": v.value,
                        "references": v.references,
                        "position": v.position,
                        "margin": v.margin,
                        "confident": v.confident,
                    }
                    for v in report.verdicts
                ],
            }
            for report in reports
        ]
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
