"""Extract per-pixel ink coverage and line/glyph segmentation from a BO3 cipher texture.

The textures are dark text composited onto a noisy paper background. Antialiasing is
plain grayscale coverage against pure-black ink, so coverage can be recovered as
``1 - pixel / background`` once the (textured) background is estimated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from PIL import Image
from scipy import ndimage


@dataclass
class Line:
    """One text line: its coverage bitmap plus where it sat in the source image."""

    index: int
    y0: int
    y1: int
    x0: int
    x1: int
    coverage: np.ndarray
    glyph_spans: list[tuple[int, int]] = field(default_factory=list)

    @property
    def height(self) -> int:
        return self.y1 - self.y0

    @property
    def width(self) -> int:
        return self.x1 - self.x0


def load_luminance(path: str) -> tuple[np.ndarray, np.ndarray]:
    """Return (luminance, alpha) as float arrays in 0..255."""
    image = Image.open(path)
    array = np.array(image.convert("RGBA")).astype(np.float32)
    luminance = array[:, :, :3].mean(axis=2)
    alpha = array[:, :, 3]
    return luminance, alpha


def estimate_background(
    luminance: np.ndarray,
    stroke_radius: int = 9,
    ink_mask: np.ndarray | None = None,
) -> np.ndarray:
    """Estimate the paper background beneath the text.

    When an ``ink_mask`` is supplied the background is a normalised convolution: a
    Gaussian-weighted mean of paper pixels only, with the ink excluded and its hole
    filled by interpolation from the surrounding paper. This is unbiased, which matters
    because ink area is measured by integrating ``1 - luminance / background``.

    Without a mask it falls back to a grey closing, which is robust enough to *find*
    the text but reads high (a closing takes a local maximum), so it is only used for
    the initial bootstrap pass.
    """
    if ink_mask is None:
        closed = ndimage.grey_closing(luminance, size=(stroke_radius * 2 + 1,) * 2)
        return ndimage.gaussian_filter(closed, sigma=stroke_radius)

    paper = (~ink_mask).astype(np.float32)
    sigma = float(stroke_radius)
    weighted = ndimage.gaussian_filter(luminance * paper, sigma=sigma)
    weights = ndimage.gaussian_filter(paper, sigma=sigma)
    background = np.divide(
        weighted, weights, out=np.zeros_like(weighted), where=weights > 1e-3
    )
    if np.any(weights <= 1e-3):
        fallback = ndimage.gaussian_filter(luminance, sigma=sigma * 3)
        background = np.where(weights > 1e-3, background, fallback)
    return background


def ink_coverage(
    path: str,
    stroke_radius: int = 9,
    alpha_threshold: float = 250.0,
    border_erosion: int = 14,
    seed_level: float = 0.75,
    keep_level: float = 0.12,
    edge_reach: int = 3,
    raw: bool = False,
) -> np.ndarray:
    """Return an ink-coverage map in 0..1 (1 == fully inked).

    The paper texture carries scratches and a ragged burnt border that survive the
    background model. Plain connected-component hysteresis is not enough because faint
    texture bridges can chain a scratch into a real glyph, so the keep mask is also
    constrained to lie within ``edge_reach`` pixels of a solidly inked seed. Every
    antialiased glyph edge is by construction adjacent to its own solid core, while
    isolated texture is discarded.

    With ``raw=True`` no gating or clipping is applied at all, so coverage may go
    slightly negative where the paper is brighter than the background estimate. That
    is deliberate: clipping at zero would rectify the background noise and bias every
    area integral upward, whereas the signed residual averages to zero off-glyph and
    keeps the integral unbiased. Gated coverage is right for segmentation; signed raw
    coverage is right for area integrals.
    """
    luminance, alpha = load_luminance(path)
    paper = alpha >= alpha_threshold
    if border_erosion > 0:
        paper = ndimage.binary_erosion(
            paper, ndimage.generate_binary_structure(2, 2), iterations=border_erosion
        )

    structure = ndimage.generate_binary_structure(2, 2)
    bootstrap = 1.0 - luminance / np.maximum(estimate_background(luminance, stroke_radius), 1.0)
    ink_mask = ndimage.binary_dilation(
        (bootstrap > seed_level) & paper, structure, iterations=stroke_radius
    )
    background = estimate_background(luminance, stroke_radius, ink_mask=ink_mask)

    coverage = 1.0 - luminance / np.maximum(background, 1.0)
    coverage[~paper] = 0.0
    if raw:
        return np.minimum(coverage, 1.0)

    coverage = np.clip(coverage, 0.0, 1.0)
    seeds = coverage > seed_level
    reachable = ndimage.binary_dilation(seeds, structure, iterations=edge_reach)
    return np.where(reachable & (coverage > keep_level), coverage, 0.0)


def _runs(profile: np.ndarray, threshold: float, min_length: int = 1) -> list[tuple[int, int]]:
    """Return [start, end) spans where ``profile`` stays above ``threshold``."""
    active = profile > threshold
    spans: list[tuple[int, int]] = []
    start: int | None = None
    for index, value in enumerate(active):
        if value and start is None:
            start = index
        elif not value and start is not None:
            spans.append((start, index))
            start = None
    if start is not None:
        spans.append((start, len(active)))
    return [span for span in spans if span[1] - span[0] >= min_length]


def segment_lines(
    coverage: np.ndarray,
    row_threshold: float = 0.5,
    min_line_height: int = 8,
    pad: int = 6,
) -> list[Line]:
    """Split a coverage map into text lines using a horizontal ink projection."""
    profile = coverage.sum(axis=1)
    lines: list[Line] = []
    for index, (top, bottom) in enumerate(_runs(profile, row_threshold, min_line_height)):
        top = max(0, top - pad)
        bottom = min(coverage.shape[0], bottom + pad)
        band = coverage[top:bottom]
        columns = np.nonzero(band.sum(axis=0) > 0.05)[0]
        if columns.size == 0:
            continue
        left = max(0, int(columns[0]) - pad)
        right = min(band.shape[1], int(columns[-1]) + 1 + pad)
        line = Line(
            index=index,
            y0=top,
            y1=bottom,
            x0=left,
            x1=right,
            coverage=band[:, left:right].copy(),
        )
        line.glyph_spans = segment_glyphs(line.coverage)
        lines.append(line)
    return lines


def segment_glyphs(
    line_coverage: np.ndarray,
    column_threshold: float = 0.06,
    min_width: int = 1,
) -> list[tuple[int, int]]:
    """Split a line into ink columns. Adjacent glyphs may merge; that is fine."""
    return _runs(line_coverage.sum(axis=0), column_threshold, min_width)


def baseline_of(line_coverage: np.ndarray) -> float:
    """Estimate the baseline row as the sharpest drop in the ink row-profile.

    Most glyphs terminate on the baseline, so the row profile falls off steeply there
    even when a few descenders continue below.
    """
    profile = line_coverage.sum(axis=1)
    gradient = np.diff(profile)
    lower_half = len(gradient) // 2
    return float(lower_half + int(np.argmin(gradient[lower_half:])) + 1)
