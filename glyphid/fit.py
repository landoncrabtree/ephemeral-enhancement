"""Fit font metrics (size, tracking, origin) of a rendered line to an observed line.

Translation is handled separately from shape: for any candidate (size, tracking) the
best integer offset is recovered by FFT cross-correlation, so the coarse scan never has
to search translation and the local optimiser starts already aligned.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize
from scipy.signal import fftconvolve

from .render import FontRenderer


@dataclass
class LineFit:
    text: str
    size_px: float
    tracking_px: float
    x0: float
    baseline_y: float
    residual: float
    correlation: float

    @property
    def params(self) -> tuple[float, float, float, float]:
        return (self.size_px, self.tracking_px, self.x0, self.baseline_y)


def residual(observed: np.ndarray, rendered: np.ndarray) -> float:
    """Mean squared coverage error normalised by observed ink mass."""
    mass = float(observed.sum())
    if mass <= 0:
        return float("inf")
    return float(((observed - rendered) ** 2).sum() / mass)


def correlation(observed: np.ndarray, rendered: np.ndarray) -> float:
    """Zero-mean normalised cross-correlation, 1.0 == identical."""
    a = observed.ravel() - observed.mean()
    b = rendered.ravel() - rendered.mean()
    denominator = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denominator == 0:
        return 0.0
    return float(a @ b / denominator)


def best_shift(
    observed: np.ndarray, rendered: np.ndarray, limit: int = 24
) -> tuple[int, int]:
    """Integer (dy, dx) to add to the render origin so it best overlays ``observed``."""
    scores = fftconvolve(observed, rendered[::-1, ::-1], mode="same")
    centre_y, centre_x = (np.array(scores.shape) - 1) // 2
    top, left = max(0, centre_y - limit), max(0, centre_x - limit)
    window = scores[top : centre_y + limit + 1, left : centre_x + limit + 1]
    peak_y, peak_x = np.unravel_index(int(np.argmax(window)), window.shape)
    return int(peak_y + top - centre_y), int(peak_x + left - centre_x)


def _render(
    renderer: FontRenderer,
    text: str,
    size_px: float,
    tracking_px: float,
    x0: float,
    baseline_y: float,
    shape: tuple[int, int],
) -> np.ndarray:
    height, width = shape
    return renderer.render_line(text, size_px, tracking_px, x0, baseline_y, width, height)


def coarse_search(
    renderer: FontRenderer,
    observed: np.ndarray,
    text: str,
    sizes: np.ndarray,
    trackings: np.ndarray,
    x0: float,
    baseline_y: float,
) -> tuple[float, float, float, float]:
    """Scan (size, tracking), auto-aligning each candidate. Returns seed parameters."""
    best = (float("inf"), float(sizes[0]), float(trackings[0]), x0, baseline_y)
    for size_px in sizes:
        for tracking_px in trackings:
            rendered = _render(
                renderer, text, size_px, tracking_px, x0, baseline_y, observed.shape
            )
            dy, dx = best_shift(observed, rendered)
            aligned = _render(
                renderer,
                text,
                size_px,
                tracking_px,
                x0 + dx,
                baseline_y + dy,
                observed.shape,
            )
            score = residual(observed, aligned)
            if score < best[0]:
                best = (score, float(size_px), float(tracking_px), x0 + dx, baseline_y + dy)
    return best[1], best[2], best[3], best[4]


def fit_line(
    renderer: FontRenderer,
    observed: np.ndarray,
    text: str,
    size0: float,
    tracking0: float,
    x00: float,
    baseline0: float,
    refine: bool = True,
) -> LineFit:
    """Refine (size, tracking, x0, baseline) by Nelder-Mead on the ink residual."""

    def objective(params: np.ndarray) -> float:
        size_px, tracking_px, x0, baseline_y = params
        if not 4.0 < size_px < 400.0:
            return 1e9
        return residual(
            observed,
            _render(renderer, text, size_px, tracking_px, x0, baseline_y, observed.shape),
        )

    params = np.array([size0, tracking0, x00, baseline0], dtype=float)
    if refine:
        simplex = np.vstack(
            [
                params,
                params + [0.6, 0.0, 0.0, 0.0],
                params + [0.0, 0.4, 0.0, 0.0],
                params + [0.0, 0.0, 0.8, 0.0],
                params + [0.0, 0.0, 0.0, 0.8],
            ]
        )
        params = minimize(
            objective,
            params,
            method="Nelder-Mead",
            options={
                "xatol": 5e-4,
                "fatol": 1e-10,
                "maxiter": 3000,
                "maxfev": 3000,
                "initial_simplex": simplex,
            },
        ).x

    size_px, tracking_px, x0, baseline_y = (float(v) for v in params)
    rendered = _render(
        renderer, text, size_px, tracking_px, x0, baseline_y, observed.shape
    )
    return LineFit(
        text=text,
        size_px=size_px,
        tracking_px=tracking_px,
        x0=x0,
        baseline_y=baseline_y,
        residual=residual(observed, rendered),
        correlation=correlation(observed, rendered),
    )
