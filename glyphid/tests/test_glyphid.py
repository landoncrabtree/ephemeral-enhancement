"""Round-trip validation for the glyph identifier.

The point of these tests is to show the identifier does not depend on reproducing the
original antialiasing. The synthetic pages are rasterised by FreeType's own hinted
rasteriser and then blurred and resampled, which is a genuinely different filter from
the supersampled box filter the identifier renders its references with. If the letters
are still recovered, the discriminators are doing their job.
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pytest
from fontTools.pens.recordingPen import RecordingPen
from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFont
from scipy import ndimage

from glyphid.extract import ink_coverage, segment_lines
from glyphid.identify import analyse_line
from glyphid.metrics import measure, stem_width
from glyphid.render import FontRenderer

# Both may be overridden so the suite can run against a different asset or font.
FONT_PATH = os.environ.get(
    "GLYPHID_FONT", str(Path.home() / "Downloads" / "franklingothicurwcom-boo.ttf")
)
CIPHER_TIF = os.environ.get(
    "GLYPHID_TEXTURE",
    str(Path.home() / "Downloads" / "mtl_p7_zm_der_cipher_message_01_c.tif"),
)

SIZE_PX = 46
TRACKING_PX = 1.0
MARGIN = 24
RASTER_SCALE = 16


def _font_available() -> bool:
    try:
        ImageFont.truetype(FONT_PATH, 12)
    except OSError:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _font_available(), reason=f"font not available at {FONT_PATH}"
)


def _flatten(pen_value, steps: int = 12) -> list[list[tuple[float, float]]]:
    """Convert a recorded outline into closed polygons in font units."""

    def quad(p0, p1, p2):
        return [
            (
                (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
                (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1],
            )
            for t in (i / steps for i in range(1, steps + 1))
        ]

    def cubic(p0, p1, p2, p3):
        return [
            (
                (1 - t) ** 3 * p0[0] + 3 * (1 - t) ** 2 * t * p1[0]
                + 3 * (1 - t) * t * t * p2[0] + t**3 * p3[0],
                (1 - t) ** 3 * p0[1] + 3 * (1 - t) ** 2 * t * p1[1]
                + 3 * (1 - t) * t * t * p2[1] + t**3 * p3[1],
            )
            for t in (i / steps for i in range(1, steps + 1))
        ]

    contours: list[list[tuple[float, float]]] = []
    current: list[tuple[float, float]] = []
    for op, args in pen_value:
        if op == "moveTo":
            if len(current) > 2:
                contours.append(current)
            current = [tuple(args[0])]
        elif op == "lineTo":
            current.append(tuple(args[0]))
        elif op == "qCurveTo":
            points = [tuple(p) for p in args if p is not None]
            start = current[-1]
            implied = points[:-1]
            on_curve = points[-1]
            controls = list(implied)
            for i, control in enumerate(controls):
                end = (
                    on_curve
                    if i == len(controls) - 1
                    else (
                        (control[0] + controls[i + 1][0]) / 2,
                        (control[1] + controls[i + 1][1]) / 2,
                    )
                )
                current.extend(quad(start, control, end))
                start = end
        elif op == "curveTo":
            points = [tuple(p) for p in args]
            current.extend(cubic(current[-1], points[0], points[1], points[2]))
        elif op == "closePath" and len(current) > 2:
            contours.append(current)
            current = []
    if len(current) > 2:
        contours.append(current)
    return contours


class OutlineRasteriser:
    """Rasterise glyphs by scan-converting flattened outlines.

    This shares no code with :class:`glyphid.render.FontRenderer` and never goes through
    FreeType's hinting, which at any size would snap the ``I`` and ``l`` stems to the
    same whole-pixel width and erase the distinction under test. Coverage comes from
    filling the polygons at ``RASTER_SCALE`` times resolution and box-averaging down.
    """

    def __init__(self, path: str, scale: int = RASTER_SCALE):
        self.scale = scale
        self._tt = TTFont(path, lazy=True)
        self._glyphs = self._tt.getGlyphSet()
        self._cmap = self._tt.getBestCmap()
        self.units_per_em = self._tt["head"].unitsPerEm

    def contours(self, char: str) -> list[list[tuple[float, float]]]:
        name = self._cmap.get(ord(char))
        if name is None:
            return []
        pen = RecordingPen()
        self._glyphs[name].draw(pen)
        return _flatten(pen.value)


def render_page(
    lines: list[str],
    blur: float = 0.0,
    size_px: int = SIZE_PX,
    tracking_px: float = TRACKING_PX,
    noise: float = 3.0,
    seed: int = 0,
) -> Image.Image:
    """Build a paper-like RGBA page with an independent, unhinted rasteriser."""
    rng = np.random.default_rng(seed)
    metrics = FontRenderer(FONT_PATH)
    raster = OutlineRasteriser(FONT_PATH)
    scale = raster.scale

    line_height = int(size_px * 2.0)
    width = MARGIN * 2 + max(
        int(metrics.advance_total(text, size_px, tracking_px)) for text in lines
    )
    height = MARGIN * 2 + line_height * len(lines)

    mask = np.zeros((height * scale, width * scale), dtype=bool)
    for row, text in enumerate(lines):
        baseline = MARGIN + line_height * row + size_px
        for char, pen in zip(
            text, metrics.pen_positions(text, size_px, tracking_px, float(MARGIN))
        ):
            unit = size_px / raster.units_per_em * scale
            for contour in raster.contours(char):
                layer = Image.new("1", (width * scale, height * scale), 0)
                ImageDraw.Draw(layer).polygon(
                    [
                        (pen * scale + x * unit, baseline * scale - y * unit)
                        for x, y in contour
                    ],
                    fill=1,
                )
                # XOR per contour so counters (the hole in O, e, a) stay open.
                mask ^= np.asarray(layer, dtype=bool)

    ink = (
        mask.reshape(height, scale, width, scale).mean(axis=(1, 3)).astype(np.float32)
    )
    if blur > 0:
        ink = ndimage.gaussian_filter(ink, blur)

    paper = 140.0 + rng.normal(0.0, noise, ink.shape).astype(np.float32)
    paper += 12.0 * ndimage.gaussian_filter(
        rng.normal(0.0, 1.0, ink.shape).astype(np.float32), 20
    )
    page = np.clip(paper * (1.0 - np.clip(ink, 0.0, 1.0)), 0, 255).astype(np.uint8)

    rgba = np.dstack([page, page, page, np.full_like(page, 255)])
    return Image.fromarray(rgba, mode="RGBA")


def _identify(page: Image.Image, guesses: list[str], tmp_path) -> list[str]:
    path = tmp_path / "page.tif"
    page.save(path, compression="tiff_adobe_deflate")

    coverage = ink_coverage(str(path))
    raw = ink_coverage(str(path), raw=True)
    lines = segment_lines(coverage)
    assert len(lines) == len(guesses), f"segmented {len(lines)} lines, want {len(guesses)}"

    renderer = FontRenderer(FONT_PATH)
    sizes = np.arange(44.0, 49.01, 0.25)
    trackings = np.arange(0.0, 3.01, 0.25)
    results = []
    for line, guess in zip(lines, guesses):
        report = analyse_line(
            renderer,
            line.coverage,
            raw[line.y0 : line.y1, line.x0 : line.x1],
            guess,
            line.index,
            sizes,
            trackings,
        )
        results.append(report.resolved)
    return results


def _swap_ambiguous(text: str) -> str:
    """Flip every 0/O and I/l so the identifier must correct all of them."""
    table = str.maketrans({"0": "O", "O": "0", "I": "l", "l": "I"})
    return text.translate(table)


class TestReferenceMetrics:
    """The discriminators must be invariant to size and to antialiasing."""

    @staticmethod
    def _units(patch, size: float) -> float:
        """Stem width in font units per em — the quantity the solver decides on."""
        return stem_width(patch) / size * 1000.0

    def test_stem_width_separates_i_from_l(self):
        renderer = FontRenderer(FONT_PATH)
        upper = self._units(renderer.render_glyph("I", 46.0), 46.0)
        lower = self._units(renderer.render_glyph("l", 46.0), 46.0)
        assert upper == pytest.approx(76, rel=0.02)
        assert lower == pytest.approx(69, rel=0.02)
        assert (upper - lower) / lower > 0.08

    @pytest.mark.parametrize("size", [44.0, 45.5, 46.0, 48.0])
    def test_stem_width_is_size_invariant(self, size):
        renderer = FontRenderer(FONT_PATH)
        assert self._units(renderer.render_glyph("I", size), size) == pytest.approx(
            76, rel=0.03
        )
        assert self._units(renderer.render_glyph("l", size), size) == pytest.approx(
            69, rel=0.03
        )

    @pytest.mark.parametrize("blur", [0.0, 0.4, 0.8, 1.2])
    def test_stem_width_survives_blur(self, blur):
        """Blur is area preserving, so the coverage integral must not move."""
        renderer = FontRenderer(FONT_PATH)
        patch = renderer.render_glyph("I", 46.0)
        if blur:
            patch = ndimage.gaussian_filter(patch, blur)
        assert self._units(patch, 46.0) == pytest.approx(76, rel=0.03)

    @pytest.mark.parametrize("char,expected", [("0", 0.597), ("O", 0.627)])
    def test_moment_aspect_separates_zero_from_oh(self, char, expected):
        renderer = FontRenderer(FONT_PATH)
        value = measure(renderer.render_glyph(char, 46.0)).moment_aspect
        assert value == pytest.approx(expected, rel=0.02)


class TestRoundTrip:
    """A page rasterised by an independent engine must still be read correctly."""

    # The real texture measures an edge width of 1.82 px; the synthetic page measures
    # 1.83 px at blur 0.0-0.25, so this range brackets the asset's actual sharpness.
    @pytest.mark.parametrize("blur", [0.0, 0.15, 0.25])
    def test_recovers_swapped_letters(self, blur, tmp_path):
        truth = ["kCmlgFi6GUJNgkNI1Q4", "xOw3xle8FOhAG0Zl7O0"]
        page = render_page(truth, blur=blur)
        guesses = [_swap_ambiguous(line) for line in truth]
        assert _identify(page, guesses, tmp_path) == truth

    @pytest.mark.parametrize("seed", [1, 2, 3])
    def test_robust_to_paper_noise(self, seed, tmp_path):
        truth = ["I0lOxAyB", "l0IOzCwD"]
        page = render_page(truth, blur=0.15, seed=seed)
        guesses = [_swap_ambiguous(line) for line in truth]
        assert _identify(page, guesses, tmp_path) == truth

    def test_recovers_dense_ambiguous_run(self, tmp_path):
        truth = ["xOI0lOlIx", "xl0OIO0Ix"]
        page = render_page(truth, blur=0.1)
        guesses = [_swap_ambiguous(line) for line in truth]
        assert _identify(page, guesses, tmp_path) == truth


EXPECTED_CIPHER = [
    "TheGiant",
    "kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvlqkZil0KIAXAzP1U1uy1BE4U",
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wn",
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1",
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1",
]


@pytest.mark.skipif(
    not os.path.exists(CIPHER_TIF), reason=f"texture not available at {CIPHER_TIF}"
)
class TestCipherTexture:
    """Regression tests against the actual Der Riese cipher texture."""

    def _run(self, guesses: list[str]) -> list[str]:
        coverage = ink_coverage(CIPHER_TIF)
        raw = ink_coverage(CIPHER_TIF, raw=True)
        lines = segment_lines(coverage)
        renderer = FontRenderer(FONT_PATH)
        sizes = np.arange(44.0, 49.01, 0.25)
        trackings = np.arange(0.0, 3.01, 0.25)
        return [
            analyse_line(
                renderer,
                line.coverage,
                raw[line.y0 : line.y1, line.x0 : line.x1],
                guess,
                line.index,
                sizes,
                trackings,
            ).resolved
            for line, guess in zip(lines, guesses)
        ]

    def test_reads_expected_text(self):
        assert self._run(EXPECTED_CIPHER) == EXPECTED_CIPHER

    def test_result_is_independent_of_initial_guess(self):
        """Flipping every 0/O and I/l in the input must not change the output."""
        swapped = [_swap_ambiguous(line) for line in EXPECTED_CIPHER]
        assert self._run(swapped) == EXPECTED_CIPHER

    def test_converges_from_a_partially_wrong_transcription(self):
        """A hand transcription differing at one stem must still converge."""
        guess = list(EXPECTED_CIPHER)
        # Line 2 position 35 reads 69.7 units: close to l (69), far from I (76).
        guess[2] = guess[2][:35] + "I" + guess[2][36:]
        assert self._run(guess) == EXPECTED_CIPHER
