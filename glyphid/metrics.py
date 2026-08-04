"""Scale-invariant shape descriptors for identifying a rasterised glyph.

Comparing a glyph against reference renders by squared pixel difference is sensitive to
exactly the thing we cannot reproduce — the antialiasing kernel. These descriptors are
built from coverage *integrals* instead, which are invariant under any linear coverage
antialiaser, and are formed as ratios so that an error in the fitted font size cancels:

``I`` and ``l`` in Franklin Gothic are plain rectangles of identical height (667 units)
that differ only in width (76 vs 69 units), so ``stem width / height`` separates them by
10% with no dependence on size at all. ``0`` and ``O`` differ in aspect ratio by ~8%.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class GlyphMetrics:
    """Measurements of a single glyph's ink distribution."""

    area: float
    width: float
    height: float
    rms_x: float
    rms_y: float

    @property
    def aspect(self) -> float:
        """Ink width relative to ink height. Independent of font size."""
        return self.width / self.height if self.height > 0 else float("nan")

    @property
    def moment_aspect(self) -> float:
        """Spread in x relative to spread in y. Independent of font size."""
        return self.rms_x / self.rms_y if self.rms_y > 0 else float("nan")

    @property
    def fill(self) -> float:
        """Ink area relative to the area implied by its spread. Size independent."""
        denominator = self.rms_x * self.rms_y
        return self.area / denominator if denominator > 0 else float("nan")

    def descriptors(self) -> np.ndarray:
        return np.array([self.aspect, self.moment_aspect, self.fill], dtype=float)


def _extent(profile: np.ndarray, floor: float) -> float:
    """Sub-pixel support width of a 1-D profile.

    Uses the equivalent-rectangle width (total mass over peak height), which reads the
    extent from the coverage integral rather than from a threshold crossing, and so is
    accurate to a small fraction of a pixel.
    """
    peak = float(profile.max())
    if peak <= floor:
        return 0.0
    return float(profile.sum() / peak)


def measure(patch: np.ndarray, floor: float = 1e-6) -> GlyphMetrics:
    """Measure the ink in ``patch`` (a neighbour-subtracted coverage window)."""
    ink = np.clip(patch, 0.0, None)
    area = float(ink.sum())
    if area <= floor:
        return GlyphMetrics(0.0, 0.0, 0.0, 0.0, 0.0)

    rows = ink.sum(axis=1)
    cols = ink.sum(axis=0)

    y = np.arange(ink.shape[0], dtype=float)
    x = np.arange(ink.shape[1], dtype=float)
    mean_y = float((rows * y).sum() / area)
    mean_x = float((cols * x).sum() / area)
    var_y = float((rows * (y - mean_y) ** 2).sum() / area)
    var_x = float((cols * (x - mean_x) ** 2).sum() / area)

    return GlyphMetrics(
        area=area,
        width=_extent(cols, floor),
        height=_extent(rows, floor),
        rms_x=float(np.sqrt(max(var_x, 0.0))),
        rms_y=float(np.sqrt(max(var_y, 0.0))),
    )


def stem_width(patch: np.ndarray, central_fraction: float = 0.5) -> float:
    """Mean horizontal ink width across the central rows of a patch.

    For a glyph with vertical sides — ``I``, ``l`` — the coverage sum along any row that
    crosses only the stem *is* the stem width, exactly, under any area-preserving
    antialiasing. Averaging over the central rows avoids the ends, and confining the sum
    to the stem's own column support keeps a neighbouring glyph from inflating it.
    """
    ink = np.clip(patch, 0.0, None)
    rows = ink.sum(axis=1)
    if rows.max() <= 0:
        return float("nan")
    inked = np.nonzero(rows > 0.25 * rows.max())[0]
    if len(inked) < 4:
        return float("nan")
    top, bottom = int(inked[0]), int(inked[-1])
    trim = int((bottom - top + 1) * (1.0 - central_fraction) / 2.0)
    band = ink[top + trim : bottom + 1 - trim]
    if band.size == 0:
        return float("nan")
    profile = band.mean(axis=0)
    left, right = _peak_support(profile)
    return float(profile[left:right].sum())


def _peak_support(profile: np.ndarray, floor_ratio: float = 0.01) -> tuple[int, int]:
    """Span of the single peak in ``profile``, cut at the surrounding local minima."""
    if profile.size == 0 or profile.max() <= 0:
        return (0, profile.size)
    peak = int(np.argmax(profile))
    floor = floor_ratio * float(profile[peak])

    left = peak
    while left > 0 and profile[left - 1] <= profile[left] and profile[left - 1] > floor:
        left -= 1
    right = peak
    limit = profile.size - 1
    while right < limit and profile[right + 1] <= profile[right] and profile[right + 1] > floor:
        right += 1
    return (left, right + 1)
