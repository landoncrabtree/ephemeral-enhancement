"""Decide between visually confusable glyphs (0/O, I/l) in a rendered texture.

The method never tries to reproduce the original antialiasing. Each ambiguous pair is
separated by a purpose-built descriptor that is a ratio of coverage *integrals*, so it
is invariant under any area-preserving antialiaser and independent of the fitted font
size:

``I`` / ``l``
    Both are plain rectangles of identical height in Franklin Gothic, differing only in
    width (76 vs 69 units). ``stem width / height`` therefore separates them by 10.6%
    and is completely unaffected by blur.

``0`` / ``O``
    Differ in aspect. The ratio of the ink distribution's horizontal to vertical
    standard deviation separates them by ~6%, with size jitter under 0.5%.

Every measurement is taken *in context*: the neighbouring glyphs are rendered from the
fitted layout and subtracted first, so a tight inter-glyph gap contaminates nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import numpy as np
from scipy import ndimage
from scipy.optimize import minimize_scalar

from .metrics import GlyphMetrics, measure, stem_width
from .render import FontRenderer

WINDOW_PAD_PX = 4.0


def _stem_width_units(patch: np.ndarray, metrics: GlyphMetrics, size_px: float) -> float:
    """Stem width in font units per em.

    ``I`` and ``l`` are plain rectangles of identical height that differ only in stem
    width (76 vs 69 units), so this single number decides between them. The width comes
    from a coverage integral across the stem, which is exact under any area-preserving
    antialiasing; normalising by the fitted size rather than by the glyph's own height
    keeps the estimate away from the noisier vertical extent, which is sensitive to how
    the window clips the stem's ends.
    """
    if size_px <= 0:
        return float("nan")
    return stem_width(patch) / size_px * 1000.0


def _moment_aspect(patch: np.ndarray, metrics: GlyphMetrics, size_px: float) -> float:
    """Horizontal spread of the ink relative to its vertical spread."""
    return metrics.moment_aspect


@dataclass(frozen=True)
class Discriminator:
    """A confusable pair and the single measurement that separates it."""

    pair: tuple[str, str]
    name: str
    measure_fn: Callable[[np.ndarray, GlyphMetrics, float], float]

    def __contains__(self, char: str) -> bool:
        return char in self.pair

    def evaluate(self, patch: np.ndarray, size_px: float) -> float:
        return self.measure_fn(patch, measure(patch), size_px)


DISCRIMINATORS: tuple[Discriminator, ...] = (
    Discriminator(("I", "l"), "stem width (font units)", _stem_width_units),
    Discriminator(("0", "O"), "x-spread / y-spread", _moment_aspect),
)


def discriminator_for(char: str) -> Discriminator | None:
    for discriminator in DISCRIMINATORS:
        if char in discriminator:
            return discriminator
    return None


@dataclass
class GlyphVerdict:
    index: int
    observed_char: str
    pen: float
    discriminator: Discriminator | None = None
    value: float = float("nan")
    references: dict[str, float] = field(default_factory=dict)

    @property
    def position(self) -> float:
        """Where the measurement falls between the two references.

        0.0 sits exactly on the first candidate, 1.0 exactly on the second. Values
        outside [0, 1] mean the measurement is beyond a reference rather than between.
        """
        if self.discriminator is None:
            return float("nan")
        first, second = self.discriminator.pair
        low, high = self.references.get(first), self.references.get(second)
        if low is None or high is None or not np.isfinite(self.value) or high == low:
            return float("nan")
        return (self.value - low) / (high - low)

    @property
    def best_char(self) -> str:
        position = self.position
        if self.discriminator is None or not np.isfinite(position):
            return self.observed_char
        first, second = self.discriminator.pair
        return first if position < 0.5 else second

    @property
    def margin(self) -> float:
        """Distance from the decision boundary, as a fraction of the reference gap.

        0.0 means the measurement landed exactly halfway between the two candidates;
        0.5 means it landed exactly on one of them.
        """
        position = self.position
        if not np.isfinite(position):
            return 0.0
        return abs(position - 0.5)

    @property
    def confident(self) -> bool:
        return self.margin >= 0.25


def glyph_window(
    renderer: FontRenderer,
    shape: tuple[int, int],
    char: str,
    pen: float,
    size_px: float,
    baseline_y: float,
    pad: float = WINDOW_PAD_PX,
) -> tuple[slice, slice]:
    """Bounding window around one placed glyph, padded by ``pad`` pixels."""
    height, width = shape
    bounds = renderer.ink_bounds_units(char)
    if bounds is None:
        return (slice(0, height), slice(0, width))
    scale = size_px / renderer.units_per_em
    return (
        slice(
            max(0, int(np.floor(baseline_y - bounds[3] * scale - pad))),
            min(height, int(np.ceil(baseline_y - bounds[1] * scale + pad))),
        ),
        slice(
            max(0, int(np.floor(pen + bounds[0] * scale - pad))),
            min(width, int(np.ceil(pen + bounds[2] * scale + pad))),
        ),
    )


def render_into(
    renderer: FontRenderer,
    chars: list[str],
    pens: list[float],
    size_px: float,
    baseline_y: float,
    window: tuple[slice, slice],
) -> np.ndarray:
    """Rasterise glyphs directly in window coordinates."""
    rows, cols = window
    return renderer.render_placed(
        chars,
        [pen - cols.start for pen in pens],
        size_px,
        baseline_y - rows.start,
        cols.stop - cols.start,
        rows.stop - rows.start,
    )


def context_render(
    renderer: FontRenderer,
    text: str,
    pens: list[float],
    size_px: float,
    baseline_y: float,
    window: tuple[slice, slice],
    skip: int,
) -> np.ndarray:
    """Render every glyph except ``skip`` into the window, ready for subtraction."""
    rows, cols = window
    span = 3.0 * size_px
    chars: list[str] = []
    placed: list[float] = []
    for i, (char, pen) in enumerate(zip(text, pens)):
        if i == skip or char == " " or not renderer.has_glyph(char):
            continue
        if pen < cols.start - span or pen > cols.stop + span:
            continue
        chars.append(char)
        placed.append(pen)
    if not chars:
        return np.zeros((rows.stop - rows.start, cols.stop - cols.start), np.float32)
    return render_into(renderer, chars, placed, size_px, baseline_y, window)


def _align(
    renderer: FontRenderer,
    target: np.ndarray,
    window: tuple[slice, slice],
    char: str,
    pen: float,
    size_px: float,
    baseline_y: float,
    search_px: float,
    step: float = 0.25,
) -> tuple[float, float]:
    """Slide one glyph to minimise its windowed residual. Returns (pen, residual)."""
    mass = max(float(np.abs(target).sum()), 1e-6)

    def cost(offset: float) -> float:
        rendered = render_into(
            renderer, [char], [pen + offset], size_px, baseline_y, window
        )
        return float(((target - rendered) ** 2).sum() / mass)

    grid = np.arange(-search_px, search_px + step, step)
    seed = float(grid[int(np.argmin([cost(g) for g in grid]))])
    result = minimize_scalar(
        cost, bounds=(seed - step, seed + step), method="bounded",
        options={"xatol": 2e-3},
    )
    return pen + float(result.x), float(result.fun)


def track_pens(
    renderer: FontRenderer,
    observed: np.ndarray,
    text: str,
    size_px: float,
    tracking_px: float,
    x0: float,
    baseline_y: float,
    first_search_px: float = 8.0,
    search_px: float = 2.5,
) -> list[float]:
    """Locate every glyph left to right, seeding each from its predecessor.

    Anchoring each glyph on the *measured* position of the previous one keeps the local
    search window small even when the line's true tracking differs from the fitted
    average, which is what makes a uniform-tracking layout lose lock partway along a
    long line.
    """
    pens: list[float] = []
    pen = x0
    for i, char in enumerate(text):
        if char == " " or not renderer.has_glyph(char):
            pens.append(pen)
            pen += renderer.advance_px(char, size_px) + tracking_px
            continue
        reach = first_search_px if i == 0 else search_px
        window = glyph_window(
            renderer, observed.shape, char, pen, size_px, baseline_y, pad=reach + 3
        )
        found, _ = _align(
            renderer, observed[window], window, char, pen, size_px, baseline_y, reach
        )
        pens.append(found)
        pen = found + renderer.advance_px(char, size_px) + tracking_px
    return pens


def isolate(
    renderer: FontRenderer,
    raw_coverage: np.ndarray,
    text: str,
    pens: list[float],
    size_px: float,
    baseline_y: float,
    index: int,
    window: tuple[slice, slice],
) -> np.ndarray:
    """Observed coverage in ``window`` with all neighbouring glyphs modelled out."""
    others = context_render(
        renderer, text, pens, size_px, baseline_y, window, skip=index
    )
    return raw_coverage[window] - others


def support_mask(
    renderer: FontRenderer,
    discriminator: Discriminator,
    pen: float,
    size_px: float,
    baseline_y: float,
    window: tuple[slice, slice],
    reach: int = 2,
) -> np.ndarray:
    """Pixels where either candidate could plausibly place ink.

    Restricting the measurement to this mask means residue left over from an imperfect
    neighbour subtraction cannot contaminate the descriptor, while the dilation by
    ``reach`` keeps every antialiased edge pixel that genuinely belongs to the glyph.
    """
    stack = [
        render_into(renderer, [candidate], [pen], size_px, baseline_y, window)
        for candidate in discriminator.pair
        if renderer.has_glyph(candidate)
    ]
    combined = np.maximum.reduce(stack) if stack else np.zeros(1)
    return ndimage.binary_dilation(
        combined > 0.001, ndimage.generate_binary_structure(2, 2), iterations=reach
    )


def reference_value(
    renderer: FontRenderer,
    discriminator: Discriminator,
    char: str,
    size_px: float,
) -> float:
    """Evaluate the discriminator on a clean render of ``char``."""
    return discriminator.evaluate(renderer.render_glyph(char, size_px), size_px)


def score_glyph(
    renderer: FontRenderer,
    raw_coverage: np.ndarray,
    text: str,
    pens: list[float],
    size_px: float,
    baseline_y: float,
    index: int,
) -> GlyphVerdict:
    """Measure the glyph at ``index`` and place it between its two candidates."""
    char, pen = text[index], pens[index]
    verdict = GlyphVerdict(index=index, observed_char=char, pen=pen)
    discriminator = discriminator_for(char)
    if discriminator is None:
        return verdict

    verdict.discriminator = discriminator
    window = glyph_window(renderer, raw_coverage.shape, char, pen, size_px, baseline_y)
    patch = isolate(
        renderer, raw_coverage, text, pens, size_px, baseline_y, index, window
    )
    patch = patch * support_mask(
        renderer, discriminator, pen, size_px, baseline_y, window
    )
    verdict.value = discriminator.evaluate(patch, size_px)
    verdict.references = {
        candidate: reference_value(renderer, discriminator, candidate, size_px)
        for candidate in discriminator.pair
    }
    return verdict
